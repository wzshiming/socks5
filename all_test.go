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

func TestSimpleServer(t *testing.T) {
	s, err := NewSimpleServer("socks5://u:p@:0")

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

func TestBindParallel(t *testing.T) {
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

	// Create two listeners on the same port in parallel
	const bindPort = ":10001"
	ctx := context.Background()

	listener1, err := dial.Listen(ctx, "tcp", bindPort)
	if err != nil {
		t.Fatal(err)
	}
	defer listener1.Close()

	listener2, err := dial.Listen(ctx, "tcp", bindPort)
	if err != nil {
		t.Fatal(err)
	}
	defer listener2.Close()

	// Start accepting on both listeners
	done1 := make(chan net.Conn)
	done2 := make(chan net.Conn)

	go func() {
		conn, err := listener1.Accept()
		if err != nil {
			t.Logf("listener1.Accept error: %v", err)
			close(done1)
			return
		}
		done1 <- conn
	}()

	go func() {
		conn, err := listener2.Accept()
		if err != nil {
			t.Logf("listener2.Accept error: %v", err)
			close(done2)
			return
		}
		done2 <- conn
	}()

	// Give the listeners time to start
	time.Sleep(time.Millisecond * 100)

	// Connect to the bound port from two different clients concurrently
	var wg sync.WaitGroup
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		conn, err := net.Dial("tcp", "127.0.0.1:10001")
		if err != nil {
			t.Errorf("failed to dial: %v", err)
			return
		}
		time.Sleep(time.Millisecond * 500) // Keep connection open
		conn.Close()
	}()
	
	go func() {
		defer wg.Done()
		conn, err := net.Dial("tcp", "127.0.0.1:10001")
		if err != nil {
			t.Errorf("failed to dial: %v", err)
			return
		}
		time.Sleep(time.Millisecond * 500) // Keep connection open
		conn.Close()
	}()

	// Verify both listeners received a connection
	select {
	case conn := <-done1:
		if conn != nil {
			conn.Close()
		}
	case <-time.After(time.Second * 2):
		t.Fatal("timeout waiting for connection on listener1")
	}

	select {
	case conn := <-done2:
		if conn != nil {
			conn.Close()
		}
	case <-time.After(time.Second * 2):
		t.Fatal("timeout waiting for connection on listener2")
	}
	
	wg.Wait()
}

func TestBindSerial(t *testing.T) {
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

	const bindPort = ":10002"
	ctx := context.Background()

	// Create multiple BIND listeners on the same port in a short period of time
	listener1, err := dial.Listen(ctx, "tcp", bindPort)
	if err != nil {
		t.Fatal(err)
	}
	defer listener1.Close()

	listener2, err := dial.Listen(ctx, "tcp", bindPort)
	if err != nil {
		t.Fatal(err)
	}
	defer listener2.Close()

	listener3, err := dial.Listen(ctx, "tcp", bindPort)
	if err != nil {
		t.Fatal(err)
	}
	defer listener3.Close()

	// Start accepting on all listeners
	done := make(chan net.Conn, 3)

	go func() {
		conn, err := listener1.Accept()
		if err != nil {
			t.Logf("listener1.Accept error: %v", err)
			return
		}
		done <- conn
	}()

	go func() {
		conn, err := listener2.Accept()
		if err != nil {
			t.Logf("listener2.Accept error: %v", err)
			return
		}
		done <- conn
	}()

	go func() {
		conn, err := listener3.Accept()
		if err != nil {
			t.Logf("listener3.Accept error: %v", err)
			return
		}
		done <- conn
	}()

	time.Sleep(time.Millisecond * 100)

	// Connect to the bound port from multiple clients in a short period
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:10002")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
	}

	// Verify all listeners received connections
	for i := 0; i < 3; i++ {
		select {
		case conn := <-done:
			if conn != nil {
				conn.Close()
			}
		case <-time.After(time.Second * 2):
			t.Fatalf("timeout waiting for connection %d", i+1)
		}
	}
}

