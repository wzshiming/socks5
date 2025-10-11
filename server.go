package socks5

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Server is accepting connections and handling the details of the SOCKS5 protocol
type Server struct {
	// Authentication is proxy authentication
	Authentication Authentication
	// ProxyDial specifies the optional proxyDial function for
	// establishing the transport connection.
	ProxyDial func(ctx context.Context, network string, address string) (net.Conn, error)
	// ProxyListen specifies the optional proxyListen function for
	// establishing the transport connection.
	ProxyListen func(context.Context, string, string) (net.Listener, error)
	// ProxyListenPacket specifies the optional proxyListenPacket function for
	// establishing the transport connection.
	ProxyListenPacket func(ctx context.Context, network string, address string) (net.PacketConn, error)
	// PacketForwardAddress specifies the packet forwarding address
	PacketForwardAddress func(ctx context.Context, destinationAddr string, packet net.PacketConn, conn net.Conn) (net.IP, int, error)
	// Logger error log
	Logger Logger
	// Context is default context
	Context context.Context
	// BytesPool getting and returning temporary bytes for use by io.CopyBuffer
	BytesPool BytesPool
	// BindReserveDuration specifies how long to keep a BIND port reserved for reuse after accepting a connection.
	// If zero, ports are not reserved for reuse (default behavior).
	BindReserveDuration time.Duration

	bindListeners   map[string]*bindListener
	bindListenersMu sync.Mutex
}

type Logger interface {
	Println(v ...interface{})
}

// NewServer creates a new Server
func NewServer() *Server {
	return &Server{}
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := s.proxyListen(s.context(), network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

func (s *Server) proxyListen(ctx context.Context, network, address string) (net.Listener, error) {
	proxyListen := s.ProxyListen
	if proxyListen == nil {
		var listenConfig net.ListenConfig
		proxyListen = listenConfig.Listen
	}
	return proxyListen(ctx, network, address)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	err := s.serveConn(conn)
	if err != nil && s.Logger != nil && !isClosedConnError(err) {
		s.Logger.Println(err)
	}
}

func (s *Server) serveConn(conn net.Conn) error {
	version, err := readByte(conn)
	if err != nil {
		return err
	}
	if version != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	req := &request{
		Version: socks5Version,
		Conn:    conn,
	}

	methods, err := readBytes(conn)
	if err != nil {
		return err
	}

	if s.Authentication != nil && bytes.IndexByte(methods, byte(userAuth)) != -1 {
		_, err := conn.Write([]byte{socks5Version, byte(userAuth)})
		if err != nil {
			return err
		}

		header, err := readByte(conn)
		if err != nil {
			return err
		}
		if header != userAuthVersion {
			return fmt.Errorf("unsupported auth version: %d", header)
		}

		username, err := readBytes(conn)
		if err != nil {
			return err
		}
		req.Username = string(username)

		password, err := readBytes(conn)
		if err != nil {
			return err
		}
		req.Password = string(password)

		if !s.Authentication.Auth(req.Command, req.Username, req.Password) {
			_, err := conn.Write([]byte{userAuthVersion, authFailure})
			if err != nil {
				return err
			}
			return errUserAuthFailed
		}
		_, err = conn.Write([]byte{userAuthVersion, authSuccess})
		if err != nil {
			return err
		}
	} else if s.Authentication == nil && bytes.IndexByte(methods, byte(noAuth)) != -1 {
		_, err := conn.Write([]byte{socks5Version, byte(noAuth)})
		if err != nil {
			return err
		}
	} else {
		_, err := conn.Write([]byte{socks5Version, byte(noAcceptable)})
		if err != nil {
			return err
		}
		return errNoSupportedAuth
	}

	var header [3]byte
	_, err = io.ReadFull(conn, header[:])
	if err != nil {
		return err
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported Command version: %d", header[0])
	}

	req.Command = Command(header[1])

	dest, err := readAddr(conn)
	if err != nil {
		if err == errUnrecognizedAddrType {
			err := sendReply(conn, addrTypeNotSupported, nil)
			if err != nil {
				return err
			}
		}
		return err
	}
	req.DestinationAddr = dest
	err = s.handle(req)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) handle(req *request) error {
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(req)
	case BindCommand:
		return s.handleBind(req)
	case AssociateCommand:
		return s.handleAssociate(req)
	default:
		if err := sendReply(req.Conn, commandNotSupported, nil); err != nil {
			return err
		}
		return fmt.Errorf("unsupported Command: %v", req.Command)
	}
}

func (s *Server) handleConnect(req *request) error {
	ctx := s.context()
	target, err := s.proxyDial(ctx, "tcp", req.DestinationAddr.Address())
	if err != nil {
		if err := sendReply(req.Conn, errToReply(err), nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DestinationAddr, err)
	}
	defer target.Close()

	localAddr := target.LocalAddr()
	local, ok := localAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("connect to %v failed: local address is %s://%s", req.DestinationAddr, localAddr.Network(), localAddr.String())
	}
	bind := address{IP: local.IP, Port: local.Port}
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
	}
	return tunnel(ctx, target, req.Conn, buf1, buf2)
}

func (s *Server) handleBind(req *request) error {
	ctx := s.context()

	listener, reused, err := s.getOrCreateBindListener(ctx, req.DestinationAddr.String())
	if err != nil {
		if err := sendReply(req.Conn, errToReply(err), nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DestinationAddr, err)
	}

	localAddr := listener.Addr()
	local, ok := localAddr.(*net.TCPAddr)
	if !ok {
		if !reused {
			listener.Close()
		}
		return fmt.Errorf("connect to %v failed: local address is %s://%s", req.DestinationAddr, localAddr.Network(), localAddr.String())
	}
	bind := address{IP: local.IP, Port: local.Port}
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		if !reused {
			listener.Close()
		}
		return fmt.Errorf("failed to send reply: %v", err)
	}

	conn, err := listener.Accept()
	if err != nil {
		if !reused {
			listener.Close()
		}
		if err := sendReply(req.Conn, errToReply(err), nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DestinationAddr, err)
	}
	
	// Release the listener for potential reuse instead of immediately closing
	s.releaseBindListener(listener, reused)

	remoteAddr := conn.RemoteAddr()
	local, ok = remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("connect to %v failed: remote address is %s://%s", req.DestinationAddr, localAddr.Network(), localAddr.String())
	}
	bind = address{IP: local.IP, Port: local.Port}
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	var buf1, buf2 []byte
	if s.BytesPool != nil {
		buf1 = s.BytesPool.Get()
		buf2 = s.BytesPool.Get()
		defer func() {
			s.BytesPool.Put(buf1)
			s.BytesPool.Put(buf2)
		}()
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
	}
	return tunnel(ctx, conn, req.Conn, buf1, buf2)
}

func (s *Server) handleAssociate(req *request) error {
	ctx := s.context()
	destinationAddr := req.DestinationAddr.String()
	udpConn, err := s.proxyListenPacket(ctx, "udp", destinationAddr)
	if err != nil {
		if err := sendReply(req.Conn, errToReply(err), nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DestinationAddr, err)
	}
	defer udpConn.Close()

	replyPacketForwardAddress := defaultReplyPacketForwardAddress
	if s.PacketForwardAddress != nil {
		replyPacketForwardAddress = s.PacketForwardAddress
	}
	ip, port, err := replyPacketForwardAddress(ctx, destinationAddr, udpConn, req.Conn)
	if err != nil {
		return err
	}
	bind := address{IP: ip, Port: port}
	if err := sendReply(req.Conn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	go func() {
		var buf [1]byte
		for {
			_, err := req.Conn.Read(buf[:])
			if err != nil {
				udpConn.Close()
				break
			}
		}
	}()

	var (
		sourceAddr  net.Addr
		wantSource  string
		targetAddr  net.Addr
		wantTarget  string
		replyPrefix []byte
		buf         [maxUdpPacket]byte
	)

	for {
		n, addr, err := udpConn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		if sourceAddr == nil {
			sourceAddr = addr
			wantSource = sourceAddr.String()
		}

		gotAddr := addr.String()
		if wantSource == gotAddr {
			if n < 3 {
				continue
			}
			reader := bytes.NewBuffer(buf[3:n])
			addr, err := readAddr(reader)
			if err != nil {
				if s.Logger != nil {
					s.Logger.Println(err)
				}
				continue
			}
			if targetAddr == nil {
				targetAddr = &net.UDPAddr{
					IP:   addr.IP,
					Port: addr.Port,
				}
				wantTarget = targetAddr.String()
			}
			if addr.String() != wantTarget {
				if s.Logger != nil {
					s.Logger.Println(fmt.Errorf("ignore non-target addresses %s", addr))
				}
				continue
			}
			_, err = udpConn.WriteTo(reader.Bytes(), targetAddr)
			if err != nil {
				return err
			}
		} else if targetAddr != nil && wantTarget == gotAddr {
			if replyPrefix == nil {
				b := bytes.NewBuffer(make([]byte, 3, 16))
				err = writeAddrWithStr(b, wantTarget)
				if err != nil {
					return err
				}
				replyPrefix = b.Bytes()
			}
			copy(buf[len(replyPrefix):len(replyPrefix)+n], buf[:n])
			copy(buf[:len(replyPrefix)], replyPrefix)
			_, err = udpConn.WriteTo(buf[:len(replyPrefix)+n], sourceAddr)
			if err != nil {
				return err
			}
		}
	}
}

func (s *Server) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := s.ProxyDial
	if proxyDial == nil {
		var dialer net.Dialer
		proxyDial = dialer.DialContext
	}
	return proxyDial(ctx, network, address)
}

func (s *Server) proxyListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	proxyListenPacket := s.ProxyListenPacket
	if proxyListenPacket == nil {
		var listener net.ListenConfig
		proxyListenPacket = listener.ListenPacket
	}
	return proxyListenPacket(ctx, network, address)
}

func (s *Server) context() context.Context {
	if s.Context == nil {
		return context.Background()
	}
	return s.Context
}

func sendReply(w io.Writer, resp reply, addr *address) error {
	_, err := w.Write([]byte{socks5Version, byte(resp), 0})
	if err != nil {
		return err
	}
	err = writeAddr(w, addr)
	return err
}

type request struct {
	Version         uint8
	Command         Command
	DestinationAddr *address
	Username        string
	Password        string
	Conn            net.Conn
}

func defaultReplyPacketForwardAddress(ctx context.Context, destinationAddr string, packet net.PacketConn, conn net.Conn) (net.IP, int, error) {
	udpLocal := packet.LocalAddr()
	udpLocalAddr, ok := udpLocal.(*net.UDPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("connect to %v failed: local address is %s://%s", destinationAddr, udpLocal.Network(), udpLocal.String())
	}

	tcpLocal := conn.LocalAddr()
	tcpLocalAddr, ok := tcpLocal.(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("connect to %v failed: local address is %s://%s", destinationAddr, tcpLocal.Network(), tcpLocal.String())
	}
	return tcpLocalAddr.IP, udpLocalAddr.Port, nil
}

// bindListener tracks a listener for BIND operations with reuse support
type bindListener struct {
	listener net.Listener
	addr     string
	timer    *time.Timer
	inUse    bool
}

// getOrCreateBindListener gets an existing listener for reuse or creates a new one
func (s *Server) getOrCreateBindListener(ctx context.Context, addr string) (net.Listener, bool, error) {
	if s.BindReserveDuration <= 0 {
		// Port reservation disabled, create new listener
		var lc net.ListenConfig
		listener, err := lc.Listen(ctx, "tcp", addr)
		return listener, false, err
	}

	s.bindListenersMu.Lock()
	defer s.bindListenersMu.Unlock()

	if s.bindListeners == nil {
		s.bindListeners = make(map[string]*bindListener)
	}

	// First try to find an existing listener for the requested address
	// We need to check all listeners because the requested address (e.g., ":10003")
	// might match an actual bound address (e.g., "[::]:10003")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		var lc net.ListenConfig
		listener, err := lc.Listen(ctx, "tcp", addr)
		return listener, false, err
	}

	// Look for available listeners on the same port
	for _, bl := range s.bindListeners {
		if !bl.inUse {
			_, blPort, err := net.SplitHostPort(bl.addr)
			if err == nil && blPort == port {
				// Check if the host matches or is compatible
				blHost, _, _ := net.SplitHostPort(bl.addr)
				if host == "" || blHost == "::" || host == blHost {
					// Stop the cleanup timer
					if bl.timer != nil {
						bl.timer.Stop()
					}
					bl.inUse = true
					return bl.listener, true, nil
				}
			}
		}
	}

	// Create a new listener
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, false, err
	}

	// Store using the actual bound address
	actualAddr := listener.Addr().String()
	
	// Register the listener for future reuse
	bl := &bindListener{
		listener: listener,
		addr:     actualAddr,
		inUse:    true,
	}
	s.bindListeners[actualAddr] = bl

	return listener, false, nil
}

// releaseBindListener marks a listener as available for reuse or closes it
func (s *Server) releaseBindListener(listener net.Listener, reused bool) {
	if s.BindReserveDuration <= 0 {
		// Port reservation disabled, just close the listener
		listener.Close()
		return
	}

	s.bindListenersMu.Lock()
	defer s.bindListenersMu.Unlock()

	addr := listener.Addr().String()
	bl, exists := s.bindListeners[addr]
	if !exists {
		listener.Close()
		return
	}

	bl.inUse = false

	// Set up a timer to close and clean up the listener after the reservation period
	bl.timer = time.AfterFunc(s.BindReserveDuration, func() {
		s.bindListenersMu.Lock()
		defer s.bindListenersMu.Unlock()

		// Double-check the listener is still not in use
		if entry, exists := s.bindListeners[addr]; exists && !entry.inUse {
			entry.listener.Close()
			delete(s.bindListeners, addr)
		}
	})
}
