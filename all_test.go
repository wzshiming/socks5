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

func TestBindWithReservation(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	// Enable port reservation for 2 seconds
	proxy.BindReserveDuration = 2 * time.Second
	go proxy.Serve(listen)

	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Create a SOCKS5 listener that will bind to a specific port
	targetAddr := ":10005"
	listener, err := dial.Listen(context.Background(), "tcp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}

	// First Accept - triggers first BIND on server
	acceptChan := make(chan net.Conn, 2)
	errChan := make(chan error, 2)
	
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
		} else {
			acceptChan <- conn
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Make first connection
	conn1, err := net.Dial("tcp", "127.0.0.1:10005")
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	select {
	case accepted1 := <-acceptChan:
		t.Log("First connection accepted")
		accepted1.Close()
	case err := <-errChan:
		t.Fatal("First accept failed:", err)
	case <-time.After(2 * time.Second):
		t.Fatal("First accept timeout")
	}

	// Wait a bit but less than reservation duration
	time.Sleep(500 * time.Millisecond)

	// Second Accept - triggers second BIND on server (should reuse port)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
		} else {
			acceptChan <- conn
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Make second connection to same port
	conn2, err := net.Dial("tcp", "127.0.0.1:10005")
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	select {
	case accepted2 := <-acceptChan:
		t.Log("Second connection accepted")
		accepted2.Close()
	case err := <-errChan:
		t.Fatal("Second accept failed:", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Second accept timeout")
	}

	t.Log("SUCCESS: Both BIND operations completed on same port")
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
