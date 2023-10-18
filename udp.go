package socks5

import (
	"bytes"
	"errors"
	"net"
)

var (
	errBadHeader = errors.New("bad header")
)

type UDPConn struct {
	bufRead       [maxUdpPacket]byte
	bufWrite      [maxUdpPacket]byte
	proxyAddress  net.Addr
	defaultTarget net.Addr
	prefix        []byte
	net.PacketConn
}

func NewUDPConn(raw net.PacketConn, proxyAddress net.Addr, defaultTarget net.Addr) (*UDPConn, error) {
	conn := &UDPConn{
		PacketConn:    raw,
		proxyAddress:  proxyAddress,
		defaultTarget: defaultTarget,
		prefix:        []byte{0, 0, 0},
	}
	return conn, nil
}

// ReadFrom implements the net.PacketConn ReadFrom method.
func (c *UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(c.bufRead[:])
	if err != nil {
		return 0, nil, err
	}
	if n < len(c.prefix) || addr.String() != c.proxyAddress.String() {
		return 0, nil, errBadHeader
	}
	buf := bytes.NewBuffer(c.bufRead[len(c.prefix):n])
	a, err := readAddr(buf)
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, buf.Bytes())
	return n, a, nil
}

// WriteTo implements the net.PacketConn WriteTo method.
func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := bytes.NewBuffer(c.bufWrite[:0])
	buf.Write(c.prefix)
	err = writeAddrWithStr(buf, addr.String())
	if err != nil {
		return 0, err
	}
	n, err = buf.Write(p)
	if err != nil {
		return 0, err
	}

	data := buf.Bytes()
	_, err = c.PacketConn.WriteTo(data, c.proxyAddress)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Read implements the net.Conn Read method.
func (c *UDPConn) Read(b []byte) (int, error) {
	n, addr, err := c.ReadFrom(b)
	if err != nil {
		return 0, err
	}
	if addr.String() != c.defaultTarget.String() {
		return c.Read(b)
	}
	return n, nil
}

// Write implements the net.Conn Write method.
func (c *UDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.defaultTarget)
}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (c *UDPConn) RemoteAddr() net.Addr {
	return c.defaultTarget
}
