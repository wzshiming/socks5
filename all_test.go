package socks5

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var testServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte("ok"))
}))

func TestServerAndStdClient(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	cli := testServer.Client()
	cli.Transport = &http.Transport{
		Proxy: func(request *http.Request) (*url.URL, error) {
			return url.Parse("socks5://" + listen.Addr().String())
		},
	}
	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestServerAndAuthStdClient(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	proxy.Authentication = UserAuth("u", "p")
	go proxy.Serve(listen)

	cli := testServer.Client()
	cli.Transport = &http.Transport{
		Proxy: func(request *http.Request) (*url.URL, error) {
			return url.Parse("socks5://u:p@" + listen.Addr().String())
		},
	}
	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestServerAndAuthClient(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	proxy.Authentication = UserAuth("u", "p")
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://u:p@" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}

	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

}

func TestServerAndClient(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}

	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

}

func TestServerAndClientWithDomain(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}
	resp, err := cli.Get(strings.ReplaceAll(testServer.URL, "127.0.0.1", "localhost"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestServerAndClientWithServerDomain(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5h://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}
	resp, err := cli.Get(strings.ReplaceAll(testServer.URL, "127.0.0.1", "localhost"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestUDP(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() {
		var buf [maxUdpPacket]byte
		for {
			n, addr, err := packet.ReadFrom(buf[:])
			if err != nil {
				return
			}
			_, err = packet.WriteTo(buf[:n], addr)
			if err != nil {
				return
			}
		}
	}()

	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dial.Dial("udp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	want := make([]byte, 1024)
	rand.Read(want)
	_, err = conn.Write(want)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	_, err = conn.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fail()
	}
}

func TestUDPMultiple(t *testing.T) {
	// Create multiple UDP echo servers
	const numServers = 3
	echoServers := make([]net.PacketConn, numServers)
	for i := 0; i < numServers; i++ {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer packet.Close()
		echoServers[i] = packet

		// Start echo server
		go func(p net.PacketConn) {
			var buf [maxUdpPacket]byte
			for {
				n, addr, err := p.ReadFrom(buf[:])
				if err != nil {
					return
				}
				_, err = p.WriteTo(buf[:n], addr)
				if err != nil {
					return
				}
			}
		}(packet)
	}

	// Start SOCKS5 proxy
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Create UDP association to first server
	conn, err := dial.Dial("udp", echoServers[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatal("connection is not a PacketConn")
	}

	// Test sending to multiple different destinations
	for i := 0; i < numServers; i++ {
		echoAddr := echoServers[i].LocalAddr()
		want := []byte(strings.Repeat(string(rune('A'+i)), 100))

		// Send to this echo server
		_, err = pc.WriteTo(want, echoAddr)
		if err != nil {
			t.Fatalf("WriteTo server %d failed: %v", i, err)
		}

		// Read response
		got := make([]byte, len(want)*2)
		n, addr, err := pc.ReadFrom(got)
		if err != nil {
			t.Fatalf("ReadFrom server %d failed: %v", i, err)
		}
		got = got[:n]

		// Verify response came from correct server
		if addr.String() != echoAddr.String() {
			t.Errorf("Response from wrong address: got %v, want %v", addr, echoAddr)
		}

		// Verify data
		if !bytes.Equal(want, got) {
			t.Errorf("Echo from server %d failed: got %x, want %x", i, got, want)
		}
	}
}

func TestBind(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	listener, err := dial.Listen(context.Background(), "tcp", ":10000")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(listener, nil)
	time.Sleep(time.Second / 10)
	resp, err := http.Get("http://127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestBindWithSerialAndParallel(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	listener, err := dial.Listen(context.Background(), "tcp", ":10001")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(listener, nil)
	time.Sleep(time.Second)

	for i := 0; i < 3; i++ {
		resp, err := http.Get("http://127.0.0.1:10001")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	const numRequests = 5
	errCh := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			resp, err := http.Get("http://127.0.0.1:10001")
			if err != nil {
				errCh <- err
				return
			}
			resp.Body.Close()
			errCh <- nil
		}()
	}

	for i := 0; i < numRequests; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSimpleServer(t *testing.T) {
	s, err := NewSimpleServer("socks5://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Start(context.Background())
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}

	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestUDPWithSeparateConnections(t *testing.T) {
	// Create UDP echo server
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() {
		var buf [maxUdpPacket]byte
		for {
			n, addr, err := packet.ReadFrom(buf[:])
			if err != nil {
				return
			}
			_, err = packet.WriteTo(buf[:n], addr)
			if err != nil {
				return
			}
		}
	}()

	// Start SOCKS5 proxy with separate outgoing connection
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()

	// Configure to use separate connections
	proxy.ProxyOutgoingListenPacket = func(ctx context.Context, network string, address string) (net.PacketConn, error) {
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, network, "127.0.0.1:0")
	}

	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dial.Dial("udp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send data through the proxy
	want := make([]byte, 1024)
	rand.Read(want)
	_, err = conn.Write(want)
	if err != nil {
		t.Fatal(err)
	}

	// Receive echoed data
	got := make([]byte, len(want))
	_, err = conn.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("data mismatch")
	}
}

type closeNotifyPacketConn struct {
	net.PacketConn
	once   sync.Once
	closed chan struct{}
}

func (c *closeNotifyPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.PacketConn.Close()
}

type acceptNotifyListener struct {
	net.Listener
	conns chan net.Conn
}

func (l *acceptNotifyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.conns <- conn
	}
	return conn, err
}

func TestUDPCloseEndsAssociation(t *testing.T) {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	relayClosed := make(chan struct{})
	proxy := NewServer()
	proxy.ProxyListenPacket = func(ctx context.Context, network string, address string) (net.PacketConn, error) {
		var lc net.ListenConfig
		packet, err := lc.ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &closeNotifyPacketConn{PacketConn: packet, closed: relayClosed}, nil
	}
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial.Dial("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-relayClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("association still open after Close")
	}
	conn.Close()
}

func TestUDPCloseAfterControlClosed(t *testing.T) {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	l := &acceptNotifyListener{Listener: listen, conns: make(chan net.Conn, 1)}
	proxy := NewServer()
	go proxy.Serve(l)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial.Dial("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	control := <-l.conns
	control.Close()
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Read succeeded after the control connection closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked after the control connection closed")
	}
	conn.Close()
	conn.Close()
}

func udpPacket(t *testing.T, from string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0})
	if err := writeAddrWithStr(&buf, from); err != nil {
		t.Fatal(err)
	}
	buf.Write(payload)
	return buf.Bytes()
}

func listenUDPPair(t *testing.T) (raw, relay net.PacketConn) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	relay, err = net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	return raw, relay
}

func TestUDPReadSkipsForeignAndMalformedDatagrams(t *testing.T) {
	const source = "10.0.0.1:53"
	reads := map[string]func(c *UDPConn, p []byte) (int, string, error){
		"ReadFrom": func(c *UDPConn, p []byte) (int, string, error) {
			n, addr, err := c.ReadFrom(p)
			if err != nil {
				return 0, "", err
			}
			return n, addr.String(), nil
		},
		"ReadFromUDP": func(c *UDPConn, p []byte) (int, string, error) {
			n, addr, err := c.ReadFromUDP(p)
			if err != nil {
				return 0, "", err
			}
			return n, addr.String(), nil
		},
		"Read": func(c *UDPConn, p []byte) (int, string, error) {
			n, err := c.Read(p)
			return n, source, err
		},
		"ReadMsgUDP": func(c *UDPConn, p []byte) (int, string, error) {
			n, _, _, addr, err := c.ReadMsgUDP(p, nil)
			if err != nil {
				return 0, "", err
			}
			return n, addr.String(), nil
		},
		"ReadFromUDPAddrPort": func(c *UDPConn, p []byte) (int, string, error) {
			n, addr, err := c.ReadFromUDPAddrPort(p)
			return n, addr.String(), err
		},
		"ReadMsgUDPAddrPort": func(c *UDPConn, p []byte) (int, string, error) {
			n, _, _, addr, err := c.ReadMsgUDPAddrPort(p, nil)
			return n, addr.String(), err
		},
	}
	for name, read := range reads {
		read := read
		t.Run(name, func(t *testing.T) {
			raw, relay := listenUDPPair(t)
			foreign, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()

			c, err := newUDPConn(raw, relay.LocalAddr(), &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 53}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Second))

			to := raw.LocalAddr()
			datagrams := []struct {
				from net.PacketConn
				data []byte
			}{
				{foreign, udpPacket(t, source, []byte("foreign"))},
				{relay, []byte{}},
				{relay, []byte{0, 0}},
				{relay, []byte{0, 0, 0, 0x09, 1, 2}},
				{relay, []byte{0, 0, 0, ipv4Address, 10, 0}},
				{relay, udpPacket(t, source, []byte("reply"))},
			}
			for _, d := range datagrams {
				if _, err := d.from.WriteTo(d.data, to); err != nil {
					t.Fatal(err)
				}
			}

			p := make([]byte, 64)
			n, from, err := read(c, p)
			if err != nil {
				t.Fatal(err)
			}
			if from != source || string(p[:n]) != "reply" {
				t.Fatalf("got %q from %s, want %q from %s", p[:n], from, "reply", source)
			}
		})
	}
}

func TestUDPReadDeadlineEndsSkipping(t *testing.T) {
	raw, relay := listenUDPPair(t)
	foreign, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()

	c, err := newUDPConn(raw, relay.LocalAddr(), &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 53}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	to := raw.LocalAddr()
	if _, err := foreign.WriteTo(udpPacket(t, "10.0.0.1:53", []byte("foreign")), to); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.WriteTo([]byte{0, 0, 0, 0x09, 1, 2}, to); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 64))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("got %v, want a timeout error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFrom still blocked after the read deadline")
	}
}

func dialUDPEcho(t *testing.T, host string, d *Dialer) net.Conn {
	echo, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		var buf [maxUdpPacket]byte
		for {
			n, addr, err := echo.ReadFrom(buf[:])
			if err != nil {
				return
			}
			if _, err := echo.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	listen, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listen.Close() })
	go NewServer().Serve(listen)

	d.ProxyNetwork = "tcp"
	d.ProxyAddress = listen.Addr().String()
	conn, err := d.Dial("udp", echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	want := []byte("ping")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 64)
	n, err := conn.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got[:n]) {
		t.Fatalf("got %q, want %q", got[:n], want)
	}
	return conn
}

func testUDPProxyPacketDialFamily(t *testing.T, host, wantNetwork string) {
	var mu sync.Mutex
	var calls []string
	d := &Dialer{
		ProxyPacketDial: func(ctx context.Context, network, address string) (net.PacketConn, error) {
			mu.Lock()
			calls = append(calls, network+" "+address)
			mu.Unlock()
			var lc net.ListenConfig
			return lc.ListenPacket(ctx, network, address)
		},
	}
	dialUDPEcho(t, host, d)

	mu.Lock()
	defer mu.Unlock()
	if want := wantNetwork + " :0"; len(calls) != 1 || calls[0] != want {
		t.Fatalf("ProxyPacketDial calls %q, want [%q]", calls, want)
	}
}

func TestUDPProxyPacketDialIPv4Relay(t *testing.T) {
	testUDPProxyPacketDialFamily(t, "127.0.0.1", "udp4")
}

func TestUDPProxyPacketDialIPv6Relay(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	l.Close()
	testUDPProxyPacketDialFamily(t, "::1", "udp6")
}

func TestUDPDefaultPacketDialIPv4Relay(t *testing.T) {
	conn := dialUDPEcho(t, "127.0.0.1", &Dialer{})
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil {
		t.Fatalf("local address %v is not an IPv4 address", conn.LocalAddr())
	}
}

func TestUDPReadFromReturnsErrorOnClose(t *testing.T) {
	raw, relay := listenUDPPair(t)
	c, err := newUDPConn(raw, relay.LocalAddr(), &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 53}, nil)
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 64))
		errCh <- err
	}()
	c.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReadFrom succeeded on a closed conn")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFrom still blocked after Close")
	}
}
