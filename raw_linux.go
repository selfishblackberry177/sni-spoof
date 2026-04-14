//go:build linux

// Linux raw-socket backend: AF_PACKET SOCK_RAW bound to the egress interface.
// Requires CAP_NET_RAW (run as root).

package main

import "golang.org/x/sys/unix"

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func openRaw() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifaceIdx,
	}); err != nil {
		unix.Close(fd)
		return err
	}
	rawFd = fd
	return nil
}

func recvFrame(buf []byte) (int, error) {
	for {
		n, _, err := unix.Recvfrom(rawFd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		return n, err
	}
}

func sendFrame(frame []byte) error {
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  ifaceIdx,
		Halen:    6,
	}
	copy(sll.Addr[:6], frame[0:6])
	return unix.Sendto(rawFd, frame, 0, sll)
}
