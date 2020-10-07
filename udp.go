package socks5

import (
	"bytes"
	"errors"
	"net"
	"reflect"
)

var (
	errBadHeader  = errors.New("bad header")
	errBadAddress = errors.New("bad address")
)

type UDPConn struct {
	bufRead  [maxUdpPacket]byte
	bufWrite [maxUdpPacket]byte
	addr     net.Addr
	prefix   []byte
	net.Conn
}

func NewUDPConn(raw net.Conn, address string) (*UDPConn, error) {
	buf := bytes.NewBuffer([]byte{0, 0, 0})
	err := writeAddrWithStr(buf, address)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	conn := &UDPConn{
		Conn:   raw,
		addr:   addr,
		prefix: buf.Bytes(),
	}
	return conn, nil
}

// ReadFrom implements the net.PacketConn ReadFrom method.
func (c *UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(p)
	return n, c.addr, err
}

// WriteTo implements the net.PacketConn WriteTo method.
func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if !reflect.DeepEqual(addr, c.addr) {
		return 0, errBadAddress
	}
	return c.Write(p)
}

// Read implements the net.Conn Read method.
func (c *UDPConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(c.bufWrite[:])
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(c.prefix, c.bufWrite[:len(c.prefix)]) {
		return 0, errBadHeader
	}
	n = copy(b[:n-len(c.prefix)], c.bufWrite[len(c.prefix):n])
	return n, err
}

// Write implements the net.Conn Write method.
func (c *UDPConn) Write(b []byte) (int, error) {
	n := copy(c.bufRead[:], c.prefix)
	n = copy(c.bufRead[n:], b)
	n, err := c.Conn.Write(c.bufRead[:n+len(c.prefix)])
	if err != nil {
		return 0, err
	}
	return n - len(c.prefix), nil
}
