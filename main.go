// Go re-implementation of patterniha's SNI-Spoofing / DPI-bypass TCP forwarder.
//
// Linux: uses AF_PACKET raw sockets (requires CAP_NET_RAW / root).
// macOS: uses BPF (/dev/bpf*) — requires root, or r/w access to /dev/bpf*.
//
// Faithful port of the Python+WinDivert logic:
//   * Sniffer captures the outbound SYN (recording ISN) and the outbound
//     third-handshake ACK (used as the L2+L3+L4 template for injection).
//   * Immediately after the 3rd ACK is captured, it waits 1 ms and injects
//     the fake TLS ClientHello with seq = ISN+1 - len(fake). Out of window
//     for the server (dropped), parsed by DPI (whitelisted).
//   * After injecting, sniffer waits for an inbound ACK matching syn_seq+1
//     proving the server ignored the fake, then signals handle() to relay.
//   * handle() will NOT start the real-data relay until the confirmation
//     arrives (2s timeout => abort, matching the Python version exactly).

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// ---- TLS ClientHello template (517 bytes, extracted from the original exe) ----

const tplHexBody = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5"

var tpl []byte

func init() {
	body, err := hex.DecodeString(tplHexBody)
	if err != nil {
		panic(err)
	}
	tpl = append(body, make([]byte, 517-len(body))...)
}

func buildClientHello(sni string) []byte {
	if len(sni) > 219 {
		panic("sni too long")
	}
	random := make([]byte, 32)
	sessID := make([]byte, 32)
	keyShare := make([]byte, 32)
	rand.Read(random)
	rand.Read(sessID)
	rand.Read(keyShare)

	sniBytes := []byte(sni)
	padLen := 219 - len(sniBytes)
	out := make([]byte, 0, 517)
	out = append(out, tpl[:11]...)
	out = append(out, random...)
	out = append(out, 0x20)
	out = append(out, sessID...)
	out = append(out, tpl[76:120]...)
	out = be16(out, uint16(len(sniBytes)+5))
	out = be16(out, uint16(len(sniBytes)+3))
	out = append(out, 0x00)
	out = be16(out, uint16(len(sniBytes)))
	out = append(out, sniBytes...)
	out = append(out, tpl[127+6:262+6]...)
	out = append(out, keyShare...)
	out = append(out, 0x00, 0x15)
	out = be16(out, uint16(padLen))
	out = append(out, make([]byte, padLen)...)
	if len(out) != 517 {
		panic(fmt.Sprintf("bad size: %d", len(out)))
	}
	return out
}

func be16(b []byte, v uint16) []byte {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], v)
	return append(b, x[:]...)
}

// ---- Config ----

type Config struct {
	ListenHost  string `json:"LISTEN_HOST"`
	ListenPort  int    `json:"LISTEN_PORT"`
	ConnectIP   string `json:"CONNECT_IP"`
	ConnectPort int    `json:"CONNECT_PORT"`
	FakeSNI     string `json:"FAKE_SNI"`
}

var (
	cfg       Config
	localIP   net.IP
	connectIP net.IP
	ifaceName string
	ifaceIdx  int
	rawFd     int
)

// ---- Per-connection (by local ephemeral port) state ----

type portState struct {
	mu       sync.Mutex
	synSeq   uint32
	fake     []byte
	fakeSent bool
	done     chan struct{} // closed after sniffer confirms server ACK'd syn+1
}

var ports sync.Map // uint16 -> *portState

// ---- Checksums (RFC1071) ----

func ipHdrLen(b []byte) int { return int(b[0]&0x0f) * 4 }

func sum16(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)&1 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func ipChecksum(iph []byte) uint16 { return fold(sum16(iph)) }

func tcpChecksum(iph, tcpAndPayload []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], iph[12:16])
	copy(pseudo[4:8], iph[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpAndPayload)))
	return fold(sum16(pseudo) + sum16(tcpAndPayload))
}

// ---- Injection: build fake frame from captured 3rd ACK ----

func buildFakeFrame(tpl []byte, isn uint32, fake []byte) []byte {
	ipOff := 14
	ihl := ipHdrLen(tpl[ipOff:])
	tcpOff := ipOff + ihl
	tcpHL := int(tpl[tcpOff+12]>>4) * 4

	hdrs := tpl[:tcpOff+tcpHL]
	out := make([]byte, 0, len(hdrs)+len(fake))
	out = append(out, hdrs...)
	out = append(out, fake...)

	binary.BigEndian.PutUint16(out[ipOff+2:ipOff+4], uint16(len(out)-ipOff))
	id := binary.BigEndian.Uint16(out[ipOff+4 : ipOff+6])
	binary.BigEndian.PutUint16(out[ipOff+4:ipOff+6], id+1)
	out[ipOff+10], out[ipOff+11] = 0, 0
	binary.BigEndian.PutUint16(out[ipOff+10:ipOff+12], ipChecksum(out[ipOff:ipOff+ihl]))

	out[tcpOff+13] |= 0x08 // PSH
	seq := isn + 1 - uint32(len(fake))
	binary.BigEndian.PutUint32(out[tcpOff+4:tcpOff+8], seq)
	out[tcpOff+16], out[tcpOff+17] = 0, 0
	binary.BigEndian.PutUint16(out[tcpOff+16:tcpOff+18],
		tcpChecksum(out[ipOff:ipOff+ihl], out[tcpOff:]))
	return out
}

// ---- Sniffer: sees ALL TCP packets between localIP and connectIP,
// injects the fake as soon as the 3rd ACK is seen, and signals
// handle() when the server's response ACK confirms the fake was ignored. ----

func sniffLoop() {
	buf := make([]byte, 65536)
	for {
		n, err := recvFrame(buf)
		if err != nil {
			log.Println("recv:", err)
			continue
		}
		if n < 14+20+20 {
			continue
		}
		pkt := buf[:n]
		if binary.BigEndian.Uint16(pkt[12:14]) != 0x0800 {
			continue
		}
		ip := pkt[14:]
		if ip[0]>>4 != 4 || ip[9] != 6 {
			continue
		}
		ihl := ipHdrLen(ip)
		src := net.IP(ip[12:16])
		dst := net.IP(ip[16:20])
		tcp := ip[ihl:]
		flags := tcp[13]
		dataOff := int(tcp[12]>>4) * 4
		plen := len(tcp) - dataOff

		const (
			FIN = 1 << 0
			SYN = 1 << 1
			RST = 1 << 2
			PSH = 1 << 3
			ACK = 1 << 4
		)

		outbound := src.Equal(localIP) && dst.Equal(connectIP)
		inbound := src.Equal(connectIP) && dst.Equal(localIP)

		if outbound {
			srcPort := binary.BigEndian.Uint16(tcp[0:2])
			seq := binary.BigEndian.Uint32(tcp[4:8])

			// SYN only: start of a new outbound connection. Reset state.
			if flags&SYN != 0 && flags&ACK == 0 {
				ps := &portState{
					synSeq: seq,
					fake:   buildClientHello(cfg.FakeSNI),
					done:   make(chan struct{}),
				}
				ports.Store(srcPort, ps)
				log.Printf("[sniff] OUT SYN  port=%d isn=%d flags=0x%02x", srcPort, seq, flags)
				continue
			}

			// 3rd-handshake ACK: ACK only, no payload.
			if flags&ACK != 0 && flags&(SYN|FIN|RST) == 0 && plen == 0 {
				log.Printf("[sniff] OUT ACK  port=%d seq=%d flags=0x%02x plen=0", srcPort, seq, flags)
				v, ok := ports.Load(srcPort)
				if !ok {
					continue
				}
				ps := v.(*portState)
				ps.mu.Lock()
				if ps.fakeSent {
					ps.mu.Unlock()
					continue
				}
				ps.fakeSent = true
				synSeq := ps.synSeq
				fake := ps.fake
				ps.mu.Unlock()

				// Mutate a copy of the captured frame and inject after 1ms
				// (matches fake_send_thread in the Python version).
				tplCopy := append([]byte(nil), pkt...)
				go func() {
					time.Sleep(1 * time.Millisecond)
					frame := buildFakeFrame(tplCopy, synSeq, fake)
					if err := sendFrame(frame); err != nil {
						log.Printf("port=%d inject err: %v", srcPort, err)
					} else {
						log.Printf("port=%d: injected fake ClientHello sni=%s seq=%d (ISN=%d)",
							srcPort, cfg.FakeSNI, synSeq+1-uint32(len(fake)), synSeq)
					}
				}()
			}
		}

		if inbound {
			dstPort := binary.BigEndian.Uint16(tcp[2:4])
			ackNum := binary.BigEndian.Uint32(tcp[8:12])
			log.Printf("[sniff] IN       port=%d ack=%d flags=0x%02x plen=%d", dstPort, ackNum, flags, plen)
			// After fake sent: server's ACK with ack==syn_seq+1 proves the
			// fake was ignored (server is still at the real expected seq).
			if flags&ACK != 0 && flags&(SYN|FIN|RST) == 0 && plen == 0 {
				v, ok := ports.Load(dstPort)
				if !ok {
					continue
				}
				ps := v.(*portState)
				ps.mu.Lock()
				if ps.fakeSent && ackNum == ps.synSeq+1 {
					select {
					case <-ps.done:
					default:
						close(ps.done)
						log.Printf("[sniff] port=%d: CONFIRMED server acked isn+1=%d (fake ignored)", dstPort, ps.synSeq+1)
					}
				} else if ps.fakeSent {
					log.Printf("[sniff] port=%d: post-fake ACK ack=%d != isn+1=%d", dstPort, ackNum, ps.synSeq+1)
				}
				ps.mu.Unlock()
			}
		}
	}
}

// ---- TCP handler ----

func handle(client net.Conn) {
	defer client.Close()
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: localIP},
		Timeout:   5 * time.Second,
	}
	server, err := d.Dial("tcp", fmt.Sprintf("%s:%d", cfg.ConnectIP, cfg.ConnectPort))
	if err != nil {
		log.Println("dial:", err)
		return
	}
	defer server.Close()

	port := uint16(server.LocalAddr().(*net.TCPAddr).Port)
	defer ports.Delete(port)

	// The sniffer created the portState when it saw the SYN. Poll briefly
	// in case the goroutine scheduler hasn't run the sniffer yet.
	var ps *portState
	for i := 0; i < 100; i++ {
		if v, ok := ports.Load(port); ok {
			ps = v.(*portState)
			break
		}
		time.Sleep(1 * time.Millisecond)
	}
	if ps == nil {
		log.Printf("port=%d: sniffer never registered this connection; aborting", port)
		return
	}

	// Wait up to 2s for server's post-fake ACK (matches Python t2a_event).
	// No fallback: if we don't get it, the fake probably didn't make it and
	// relaying real data would just expose the real SNI to DPI.
	select {
	case <-ps.done:
	case <-time.After(2 * time.Second):
		log.Printf("port=%d: timeout waiting for server ACK of ISN+1; aborting", port)
		return
	}

	log.Printf("port=%d: fake confirmed, starting relay", port)

	done := make(chan struct{}, 2)
	go func() { io.Copy(server, client); done <- struct{}{} }()
	go func() { io.Copy(client, server); done <- struct{}{} }()
	<-done
}

// ---- Startup ----

func getLocalIPAndIface(targetIP string) (net.IP, string, int) {
	c, err := net.Dial("udp", targetIP+":53")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	lip := c.LocalAddr().(*net.UDPAddr).IP.To4()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if ok && ipn.IP.To4() != nil && ipn.IP.Equal(lip) {
				return lip, iface.Name, iface.Index
			}
		}
	}
	log.Fatalf("no interface for local IP %s", lip)
	return nil, "", 0
}

func main() {
	path := "config.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatal(err)
	}
	connectIP = net.ParseIP(cfg.ConnectIP).To4()
	if connectIP == nil {
		log.Fatalf("bad CONNECT_IP: %s", cfg.ConnectIP)
	}
	localIP, ifaceName, ifaceIdx = getLocalIPAndIface(cfg.ConnectIP)

	if err := openRaw(); err != nil {
		log.Fatal("open raw socket: ", err)
	}

	log.Printf("iface=%s ifindex=%d local=%s remote=%s:%d listen=%s:%d fake_sni=%s",
		ifaceName, ifaceIdx, localIP, cfg.ConnectIP, cfg.ConnectPort,
		cfg.ListenHost, cfg.ListenPort, cfg.FakeSNI)

	go sniffLoop()

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.ListenHost, cfg.ListenPort))
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handle(c)
	}
}
