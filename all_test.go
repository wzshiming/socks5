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
