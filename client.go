package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// Conn is a forward proxy connection.
type Conn struct {
	net.Conn
	boundAddr net.Addr
}

// BoundAddr returns the address assigned by the proxy server for
// connecting to the command target address from the proxy server.
func (c *Conn) BoundAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.boundAddr
}

// Dialer is a SOCKS5 dialer.
type Dialer struct {
	// ProxyNetwork network between a proxy server and a client
	ProxyNetwork string
	// ProxyAddress proxy server address
	ProxyAddress string
	// ProxyDial specifies the optional dial function for
	// establishing the transport connection.
	ProxyDial func(context.Context, string, string) (net.Conn, error)
	// Username use username authentication if not empty
	Username string
	// Password use password authentication if not empty,
	// only valid if username is set
	Password string
	// IsResolve resolve domain name on locally
	IsResolve bool
	// Resolver optionally specifies an alternate resolver to use
	Resolver *net.Resolver
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. The default is no timeout
	Timeout time.Duration
}

// NewDialer returns a new Dialer that dials through the provided
// proxy server's network and address.
func NewDialer(addr string) (*Dialer, error) {
	d := &Dialer{ProxyNetwork: "tcp"}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "socks5":
		d.IsResolve = true
	case "socks5h":
	default:
		return nil, fmt.Errorf("unsupported protocol '%s'", u.Scheme)
	}
	host := u.Host
	port := u.Port()
	if port == "" {
		port = "1080"
		hostname := u.Hostname()
		host = net.JoinHostPort(hostname, port)
	}
	if u.User != nil {
		d.Username = u.User.Username()
		d.Password, _ = u.User.Password()
	}
	d.ProxyAddress = host
	return d, nil
}

// DialContext connects to the provided address on the provided network.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.IsResolve {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			ipaddr, err := d.resolver().LookupIP(ctx, "ip4", host)
			if err != nil {
				ipaddr, err = d.resolver().LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
			}
			host := ipaddr[0].String()
			address = net.JoinHostPort(host, port)
		}
	}

	conn, err := d.proxyDial(ctx, d.ProxyNetwork, d.ProxyAddress)
	if err != nil {
		return nil, err
	}

	addr, err := d.connect(ctx, conn, network, address)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &Conn{Conn: conn, boundAddr: addr}, nil
}

// Dial connects to the provided address on the provided network.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *Dialer) connect(ctx context.Context, conn net.Conn, network, address string) (net.Addr, error) {
	if d.Timeout != 0 {
		deadline := time.Now().Add(d.Timeout)
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	err := d.connectAuth(conn)
	if err != nil {
		return nil, err
	}

	return d.connectCommand(conn, network, address)
}

func (d *Dialer) connectAuth(conn net.Conn) error {
	_, err := conn.Write([]byte{socks5Version})
	if err != nil {
		return err
	}
	if d.Username == "" {
		err = writeBytes(conn, []byte{byte(noAuth)})
		if err != nil {
			return err
		}
	} else {
		err = writeBytes(conn, []byte{byte(noAuth), byte(userAuth)})
		if err != nil {
			return err
		}
	}

	var header [2]byte
	_, err = io.ReadFull(conn, header[:])
	if err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unexpected protocol version %d", header[0])
	}
	if authMethod(header[1]) == noAcceptable {
		return fmt.Errorf("no acceptable authentication methods %d", authMethod(header[1]))
	}
	switch authMethod(header[1]) {
	default:
		return fmt.Errorf("authentication method not supported %d", authMethod(header[1]))
	case noAuth:
	case userAuth:
		if d.Username == "" {
			return errors.New("need username/password")
		}

		if len(d.Username) == 0 || len(d.Username) > 255 || len(d.Password) == 0 || len(d.Password) > 255 {
			return errors.New("invalid username/password")
		}
		_, err = conn.Write([]byte{userAuthVersion})
		if err != nil {
			return err
		}
		err = writeBytes(conn, []byte(d.Username))
		if err != nil {
			return err
		}
		err = writeBytes(conn, []byte(d.Password))
		if err != nil {
			return err
		}

		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			return err
		}
		if header[0] != userAuthVersion {
			return fmt.Errorf("invalid username/password version %d", header[0])
		}
		if header[1] != authSuccess {
			return fmt.Errorf("username/password authentication failed %d", header[1])
		}
	}
	return nil
}

func (d *Dialer) connectCommand(conn net.Conn, network, address string) (net.Addr, error) {
	_, err := conn.Write([]byte{socks5Version, byte(connectCommand), 0})
	if err != nil {
		return nil, err
	}
	err = writeAddrWithStr(conn, address)
	if err != nil {
		return nil, err
	}

	var header [3]byte
	_, err = io.ReadFull(conn, header[:])
	if err != nil {
		return nil, err
	}

	if header[0] != socks5Version {
		return nil, fmt.Errorf("unexpected protocol version %d", header[0])
	}

	if reply(header[1]) != successReply {
		return nil, fmt.Errorf("unknown error %s", reply(header[1]).String())
	}

	return readAddr(conn)
}

func (d *Dialer) resolver() *net.Resolver {
	if d.Resolver == nil {
		return net.DefaultResolver
	}
	return d.Resolver
}

func (d *Dialer) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := d.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}
	return proxyDial(ctx, network, address)
}
