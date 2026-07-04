// Package managesieveserver implements a ManageSieve (RFC 5804) server.
//
// The library owns the wire protocol: command parsing (including quoted
// strings and {N}/{N+} literals), SASL PLAIN framing, STARTTLS, response
// formatting, the RFC 5804 state machine, and abuse controls (line/literal
// bounds, idle/absolute timeouts, progressive error delays). The embedding
// application supplies the business logic — authentication, script storage,
// Sieve validation, quotas — through the Session interface, created
// per-connection by Options.NewSession.
//
// Proxies can take over the raw socket after authenticating via Conn.Hijack.
package managesieveserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime/debug"
	"sync"
	"time"
)

// Server is a ManageSieve server that accepts connections and dispatches
// them to sessions created by the Options.NewSession callback.
type Server struct {
	opts     Options
	listener net.Listener
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc

	// mu guards conns, the set of live connections the library still owns
	// (hijacked connections are removed). Close walks it to kick blocked
	// reads, which context cancellation alone cannot unblock.
	mu    sync.Mutex
	conns map[*Conn]struct{}
}

// New creates a new ManageSieve server with the given options.
func New(opts Options) *Server {
	resolved := opts.defaults()
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		opts:   resolved,
		ctx:    ctx,
		cancel: cancel,
		conns:  make(map[*Conn]struct{}),
	}
}

func (s *Server) registerConn(c *Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) unregisterConn(c *Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Serve accepts connections on the given listener. It blocks until the
// listener is closed or the server is shut down via Close. For implicit
// TLS listeners, wrap the listener with tls.NewListener before calling
// Serve.
//
// Serve spawns one goroutine per accepted connection and imposes no built-in
// cap on the number of concurrent connections. To bound concurrency, enforce
// the limit in Options.NewSession: return a *managesieveserver.Error for a
// polite "NO" rejection or ErrSilentReject to drop without a banner.
func (s *Server) Serve(ln net.Listener) error {
	s.listener = ln
	s.opts.Logger.Info("ManageSieve: server listening", "addr", ln.Addr())

	// backoff bounds the retry rate on transient Accept errors (e.g. EMFILE)
	// so a persistent failure cannot spin the loop hot.
	const maxBackoff = 1 * time.Second
	var backoff time.Duration

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil // graceful shutdown
			default:
			}

			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else {
				backoff *= 2
			}
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			s.opts.Logger.Error("ManageSieve: accept error; backing off",
				"error", err, "delay", backoff)

			select {
			case <-time.After(backoff):
			case <-s.ctx.Done():
				return nil
			}
			continue
		}
		backoff = 0

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.recoverConn(conn)
			s.handleConn(conn)
		}()
	}
}

// ListenAndServe creates a plaintext TCP listener on addr and calls Serve.
// It does NOT wrap the listener with TLS even when TLSConfig is set; for
// implicit-TLS ports use ListenAndServeTLS, and for a listener you wrap
// yourself pass it to Serve directly.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// ListenAndServeTLS creates a TLS listener on addr and calls Serve.
func (s *Server) ListenAndServeTLS(addr string) error {
	if s.opts.TLSConfig == nil {
		return net.ErrClosed // no TLS configured
	}
	ln, err := tls.Listen("tcp", addr, s.opts.TLSConfig)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Close gracefully shuts down the server. It closes the listener, cancels
// all active connections — kicking any that are blocked in a read, since
// context cancellation alone cannot unblock a net.Conn — and waits for them
// to finish. Each kicked client is sent a BYE before its connection closes.
// Hijacked connections are caller-owned and are left untouched.
func (s *Server) Close() error {
	s.cancel()
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	// Expire every tracked connection's read deadline so blocked reads fail
	// now; their serve loops observe the cancelled context and exit. Without
	// this, an idle connection stalls the Wait below for up to IdleTimeout —
	// or forever when idle timeouts are disabled. A connection accepted
	// concurrently with this walk is not missed: its serve loop starts with
	// the context already cancelled and exits at the top-of-loop check.
	s.mu.Lock()
	for c := range s.conns {
		c.forceReadUnblock()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// newWriter builds the buffered writer for a connection, wrapping the raw
// conn so each network write is bounded by WriteTimeout when configured.
func (s *Server) newWriter(conn net.Conn) *bufio.Writer {
	if s.opts.WriteTimeout > 0 {
		return bufio.NewWriter(&writeDeadlineConn{Conn: conn, timeout: s.opts.WriteTimeout})
	}
	return bufio.NewWriter(conn)
}

// ServeConn runs the ManageSieve command loop on a single connection. The
// caller owns the listener; panics are recovered exactly as in Serve
// (logged, reported via OnPanic, connection closed).
func (s *Server) ServeConn(netConn net.Conn) {
	defer s.recoverConn(netConn)
	s.handleConn(netConn)
}

// recoverConn is the shared per-connection panic handler for Serve and
// ServeConn. It must be invoked directly by a defer so recover() applies to
// the panicking goroutine. Closing the connection here also covers a panic
// inside the NewSession callback, before any session teardown exists.
func (s *Server) recoverConn(conn net.Conn) {
	if r := recover(); r != nil {
		stack := debug.Stack()
		s.opts.Logger.Error("ManageSieve: panic in connection handler",
			"panic", r, "remote", conn.RemoteAddr())
		if h := s.opts.OnPanic; h != nil {
			h(r, stack)
		}
		conn.Close()
	}
}

// handleConn sets up a Conn and runs the command loop.
func (s *Server) handleConn(netConn net.Conn) {
	var ctx context.Context
	var cancel context.CancelFunc

	if s.opts.AbsoluteSessionTimeout > 0 {
		ctx, cancel = context.WithTimeout(s.ctx, s.opts.AbsoluteSessionTimeout)
	} else {
		ctx, cancel = context.WithCancel(s.ctx)
	}
	// Release the context on every exit — including a panic in the
	// NewSession callback below, which recoverConn (our caller's defer)
	// otherwise cleans up without ever reaching serve's own cancel.
	defer cancel()

	// Detect implicit TLS, unwrapping any listener/conn wrappers (e.g. a
	// PROXY-protocol wrapper) that embed the tls.Conn but are not themselves
	// *tls.Conn. Consumers can still override via Conn.SetTLS in NewSession.
	c := &Conn{
		netConn:   netConn,
		rawConn:   netConn,
		server:    s,
		reader:    bufio.NewReader(netConn),
		writer:    s.newWriter(netConn),
		ctx:       ctx,
		cancel:    cancel,
		isTLS:     isTLSConn(netConn),
		startTime: time.Now(),
	}

	// Track the connection so Close can kick it out of a blocked read.
	// Unregistering twice (here and in Hijack) is harmless.
	s.registerConn(c)
	defer s.unregisterConn(c)

	// Create the session via the consumer's callback.
	session, err := s.opts.NewSession(c)
	if err != nil {
		// A silent rejection closes the socket without any banner (abuse
		// control: don't inform the peer it is being limited).
		if errors.Is(err, ErrSilentReject) {
			s.opts.Logger.Debug("ManageSieve: connection silently rejected",
				"remote", netConn.RemoteAddr(), "error", err)
			netConn.Close()
			return
		}
		s.opts.Logger.Warn("ManageSieve: session creation failed",
			"remote", netConn.RemoteAddr(), "error", err)
		// A limiter can steer the rejection banner by returning an *Error,
		// e.g. NO (TRYLATER) "Too many connections".
		msg := s.opts.RejectMessage
		var merr *Error
		if errors.As(err, &merr) {
			msg = merr.wireMessage()
		}
		c.no(msg)
		c.writer.Flush()
		netConn.Close()
		return
	}

	c.session = session
	c.serve()
}

// isTLSConn reports whether conn is (or wraps) a *tls.Conn. It follows the
// conventional Unwrap() net.Conn chain used by connection wrappers.
func isTLSConn(conn net.Conn) bool {
	for conn != nil {
		if _, ok := conn.(*tls.Conn); ok {
			return true
		}
		u, ok := conn.(interface{ Unwrap() net.Conn })
		if !ok {
			return false
		}
		conn = u.Unwrap()
	}
	return false
}

// writeDeadlineConn wraps a net.Conn to arm a write deadline before every
// Write, so a slow-reading client cannot block a flush indefinitely. Only the
// write path is wrapped; read deadlines are managed separately by the command
// loop.
type writeDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (w *writeDeadlineConn) Write(p []byte) (int, error) {
	if w.timeout > 0 {
		_ = w.Conn.SetWriteDeadline(time.Now().Add(w.timeout))
	}
	return w.Conn.Write(p)
}
