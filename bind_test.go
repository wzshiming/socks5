package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestBindSerialRequests(t *testing.T) {
	// Start SOCKS5 server
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	// Create client
	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Create a listener through SOCKS5
	listener, err := dial.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Check that Addr() returns a non-nil address
	addr := listener.Addr()
	if addr == nil {
		t.Fatal("listener.Addr() returned nil")
	}
	t.Logf("Listening on: %s", addr.String())

	// Start HTTP server on the listener
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "OK")
		}),
	}
	go server.Serve(listener)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Make serial requests
	for i := 0; i < 10; i++ {
		resp, err := http.Get("http://" + addr.String())
		if err != nil {
			t.Fatalf("Request %d failed: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "OK" {
			t.Fatalf("Request %d: unexpected response: %s", i+1, string(body))
		}
	}
}

func TestBindListenerClose(t *testing.T) {
	// Start SOCKS5 server
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := NewServer()
	go proxy.Serve(listen)

	// Create client
	dial, err := NewDialer("socks5://" + listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Create a listener through SOCKS5
	listener, err := dial.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	// Start accepting in background
	acceptDone := make(chan struct{})
	acceptErr := make(chan error, 1)
	go func() {
		close(acceptDone)
		_, err := listener.Accept()
		acceptErr <- err
	}()

	// Wait for Accept to start
	<-acceptDone
	time.Sleep(50 * time.Millisecond)
	
	// Close the listener
	err = listener.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Check that Accept returns an error
	select {
	case err = <-acceptErr:
		if err == nil {
			t.Fatal("Accept should have returned an error after Close")
		}
		// Any error is acceptable (could be net.ErrClosed or connection error)
		t.Logf("Accept returned error after Close: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Accept did not return after Close")
	}

	// Verify that subsequent Accept calls also return an error
	_, err = listener.Accept()
	if err == nil {
		t.Fatal("Accept should return an error after Close")
	}
}
