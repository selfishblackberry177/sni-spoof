//go:build darwin

// macOS raw-socket backend: BPF (/dev/bpfN).
// Requires r/w on a /dev/bpf* device (usually root).
//
// BPF gives us both directions of traffic on the bound interface, delivers
// frames prefixed with a bpf_hdr (possibly multiple per read), and lets us
// inject a raw Ethernet frame with write(). BIOCSHDRCMPLT=1 tells the kernel
// to send the frame verbatim (do not overwrite the source MAC).

package main

import (
	"fmt"
	"io"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	bpfBuf   []byte
	bpfAvail int
	bpfPos   int
	bpfMu    sync.Mutex
)

func bpfWordAlign(x int) int { return (x + 3) &^ 3 }

func ioctlSetUint32(fd int, req uint, val uint32) error {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&val)))
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlGetUint32(fd int, req uint) (uint32, error) {
	var val uint32
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(&val)))
	if errno != 0 {
		return 0, errno
	}
	return val, nil
}

// struct ifreq on Darwin: IFNAMSIZ (16) bytes of name plus a 16-byte union.
type ifReq struct {
	Name [unix.IFNAMSIZ]byte
	_    [16]byte
}

func openRaw() error {
	var (
		fd  int
		err error
	)
	for i := 0; i < 256; i++ {
		fd, err = unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR, 0)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("open /dev/bpf*: %w", err)
	}

	// BIOCSETIF: bind the bpf device to the egress interface.
	var ifr ifReq
	if len(ifaceName) >= len(ifr.Name) {
		unix.Close(fd)
		return fmt.Errorf("iface name too long: %s", ifaceName)
	}
	copy(ifr.Name[:], ifaceName)
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		unix.Close(fd)
		return fmt.Errorf("BIOCSETIF %s: %v", ifaceName, errno)
	}

	// Deliver packets as soon as they arrive (no buffering timeout).
	if err := ioctlSetUint32(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		unix.Close(fd)
		return fmt.Errorf("BIOCIMMEDIATE: %w", err)
	}

	// We build the full Ethernet header ourselves (src MAC from the captured
	// 3rd-handshake ACK frame), so tell the kernel not to fix it up.
	if err := ioctlSetUint32(fd, unix.BIOCSHDRCMPLT, 1); err != nil {
		unix.Close(fd)
		return fmt.Errorf("BIOCSHDRCMPLT: %w", err)
	}

	// See locally-sent packets too. Usually the default, but make it explicit.
	_ = ioctlSetUint32(fd, unix.BIOCSSEESENT, 1)

	// Use the kernel's BPF read buffer size, fall back to 32 KiB.
	bl, err := ioctlGetUint32(fd, unix.BIOCGBLEN)
	if err != nil || bl < 4096 {
		bl = 32768
	}
	bpfBuf = make([]byte, bl)

	rawFd = fd
	return nil
}

// recvFrame returns the next Ethernet frame from the BPF device, stripping
// the bpf_hdr. BPF reads may contain multiple frames; we iterate through the
// buffered read before issuing the next read().
func recvFrame(out []byte) (int, error) {
	bpfMu.Lock()
	defer bpfMu.Unlock()

	for {
		if bpfPos >= bpfAvail {
			n, err := unix.Read(rawFd, bpfBuf)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				return 0, err
			}
			if n <= 0 {
				return 0, io.ErrUnexpectedEOF
			}
			bpfAvail = n
			bpfPos = 0
		}

		hdrSize := int(unsafe.Sizeof(unix.BpfHdr{}))
		if bpfPos+hdrSize > bpfAvail {
			bpfPos = bpfAvail
			continue
		}
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&bpfBuf[bpfPos]))
		hdrLen := int(hdr.Hdrlen)
		capLen := int(hdr.Caplen)
		pktStart := bpfPos + hdrLen
		pktEnd := pktStart + capLen
		if pktEnd > bpfAvail {
			bpfPos = bpfAvail
			continue
		}
		bpfPos = bpfWordAlign(pktEnd)

		n := copy(out, bpfBuf[pktStart:pktEnd])
		return n, nil
	}
}

func sendFrame(frame []byte) error {
	_, err := unix.Write(rawFd, frame)
	return err
}
