//go:build windows

package socks5

import (
	"golang.org/x/sys/windows"
)

func setReuseAddrAndPort(fd uintptr) error {
	// Enable SO_REUSEADDR to allow binding to an address in TIME_WAIT state
	// Note: Windows doesn't have SO_REUSEPORT, but SO_REUSEADDR behaves similarly
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
}
