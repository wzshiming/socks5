//go:build !windows

package socks5

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setReuseAddrAndPort(fd uintptr) error {
	// Enable SO_REUSEADDR to allow binding to an address in TIME_WAIT state
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	// Enable SO_REUSEPORT to allow multiple sockets to bind to the same address/port
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
