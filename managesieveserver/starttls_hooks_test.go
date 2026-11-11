package managesieveserver_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// bufferedTLSFlight sends ClientHello normally, then combines the TLS 1.3
// client's Finished and first application command into one transport write.
type bufferedTLSFlight struct {
	net.Conn
	first, released bool
	pending         bytes.Buffer
}

func (c *bufferedTLSFlight) Write(p []byte) (int, error) {
	if !c.first || c.released {
		c.first = true
		return c.Conn.Write(p)
	}
	return c.pending.Write(p)
}

func TestStartTLSHooksOrderAndCoalescedCommand(t *testing.T) {
	store := newTestStore()
	started, completed := make(chan struct{}), make(chan struct{})
	allowStart, allowComplete := make(chan struct{}), make(chan struct{})
	var releaseStart, releaseComplete sync.Once
	defer releaseStart.Do(func() { close(allowStart) })
	defer releaseComplete.Do(func() { close(allowComplete) })
	var original net.Conn
	var protocolConn *managesieveserver.Conn
	var calls atomic.Int32
	dispatched := make(chan struct{}, 1)
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(c *managesieveserver.Conn) (managesieveserver.Session, error) {
			protocolConn, original = c, c.NetConn()
			return store.NewSession(c)
		},
		TLSConfig:   serverTLSConfig(t),
		IdleTimeout: 5 * time.Second,
		OnStartTLS: func(plain net.Conn) {
			if calls.Add(1) != 1 || plain != original || protocolConn.IsTLS() {
				t.Error("OnStartTLS did not observe the original plaintext connection")
			}
			close(started)
			<-allowStart
		},
		OnTLSHandshakeComplete: func(plain net.Conn, secure *tls.Conn) {
			if calls.Add(1) != 2 || plain != original || secure.NetConn() != plain ||
				protocolConn.NetConn() != secure || !protocolConn.IsTLS() || !secure.ConnectionState().HandshakeComplete {
				t.Error("OnTLSHandshakeComplete ran before the TLS connection was published")
			}
			close(completed)
			<-allowComplete
		},
		UnknownCommandHandler: func(_ context.Context, c *managesieveserver.Conn, cmd string, _ []string) (bool, bool) {
			if cmd != "XPROBE" {
				return false, false
			}
			dispatched <- struct{}{}
			c.OK(`"probe"`)
			return true, false
		},
	})
	c := dial(t, addr)
	c.greet()
	c.send("STARTTLS")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("OnStartTLS was not called")
	}
	ack := make(chan string, 1)
	go func() {
		line, _ := c.r.ReadString('\n')
		ack <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ack:
		t.Fatalf("positive reply %q arrived before OnStartTLS returned", line)
	case <-time.After(30 * time.Millisecond):
	}
	releaseStart.Do(func() { close(allowStart) })
	if line := <-ack; line != `OK "Begin TLS negotiation"` {
		t.Fatalf("STARTTLS acknowledgement = %q", line)
	}
	flight := &bufferedTLSFlight{Conn: c.conn}
	secure := tls.Client(flight, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err := secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(secure, "XPROBE\r\n"); err != nil {
		t.Fatal(err)
	}
	flight.released = true
	if _, err := c.conn.Write(flight.pending.Bytes()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
	case <-time.After(2 * time.Second):
		t.Fatal("OnTLSHandshakeComplete was not called")
	}
	// The client may already have sent application data with Finished, but the
	// completion hook still precedes both the greeting and command dispatch.
	postTLS := &client{t: t, conn: secure, r: bufio.NewReader(secure)}
	greeting := make(chan string, 1)
	go func() {
		line, _ := postTLS.r.ReadString('\n')
		greeting <- line
	}()
	select {
	case line := <-greeting:
		t.Fatalf("post-TLS greeting %q arrived before completion hook returned", line)
	case <-dispatched:
		t.Fatal("coalesced command was dispatched before completion hook returned")
	case <-time.After(30 * time.Millisecond):
	}
	releaseComplete.Do(func() { close(allowComplete) })
	if line := <-greeting; !strings.HasPrefix(line, `"IMPLEMENTATION"`) {
		t.Fatalf("post-TLS greeting starts with %q", line)
	}
	postTLS.greet()
	if line, _ := postTLS.readResponse(); line != `OK "probe"` {
		t.Fatalf("coalesced command response = %q", line)
	}
	<-dispatched
	// A second upgrade is rejected without invoking either hook again.
	postTLS.send("STARTTLS")
	if line, _ := postTLS.readResponse(); line != `NO "TLS already active"` {
		t.Fatalf("second STARTTLS response = %q", line)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("hook calls = %d, want one of each", got)
	}
}

func TestStartTLSHooksRejectionAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name, command, response string
		tls, authenticate       bool
		wantStarted             int32
	}{
		{name: "unsupported", command: "STARTTLS\r\n", response: `NO "STARTTLS not supported"`},
		{name: "authenticated", command: "STARTTLS\r\n", response: `NO "STARTTLS not permitted after authentication"`, tls: true, authenticate: true},
		{name: "pipelined", command: "STARTTLS\r\nNOOP\r\n", response: `NO "Pipelined data after STARTTLS is not allowed"`, tls: true},
		{name: "failed handshake", command: "STARTTLS\r\n", response: `OK "Begin TLS negotiation"`, tls: true, wantStarted: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var started, completed atomic.Int32
			opts := managesieveserver.Options{
				NewSession: newTestStore().NewSession, InsecureAuth: true, IdleTimeout: 5 * time.Second,
				OnStartTLS:             func(net.Conn) { started.Add(1) },
				OnTLSHandshakeComplete: func(net.Conn, *tls.Conn) { completed.Add(1) },
			}
			if tc.tls {
				opts.TLSConfig = serverTLSConfig(t)
			}
			c := dial(t, startServer(t, opts))
			if tc.authenticate {
				c.authenticate("user@example.com", "secret")
			} else {
				c.greet()
			}
			c.sendRaw(tc.command)
			if line, _ := c.readResponse(); line != tc.response {
				t.Fatalf("response = %q, want %q", line, tc.response)
			}
			if tc.wantStarted > 0 {
				c.sendRaw("invalid TLS handshake\r\n")
				if _, err := c.r.ReadByte(); err == nil {
					t.Fatal("connection remained open after handshake failure")
				}
			}
			if got := started.Load(); got != tc.wantStarted {
				t.Errorf("OnStartTLS calls = %d, want %d", got, tc.wantStarted)
			}
			if got := completed.Load(); got != 0 {
				t.Errorf("OnTLSHandshakeComplete calls = %d, want none", got)
			}
		})
	}
}

func TestStartTLSHooksOmittedForImplicitTLS(t *testing.T) {
	var calls atomic.Int32
	srv := managesieveserver.New(managesieveserver.Options{
		NewSession:             newTestStore().NewSession,
		TLSConfig:              serverTLSConfig(t),
		OnStartTLS:             func(net.Conn) { calls.Add(1) },
		OnTLSHandshakeComplete: func(net.Conn, *tls.Conn) { calls.Add(1) },
	})
	defer srv.Close()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go srv.ServeConn(tls.Server(serverConn, serverTLSConfig(t)))
	secure := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	c := &client{t: t, conn: secure, r: bufio.NewReader(secure)}
	c.greet()
	c.send("STARTTLS")
	if line, _ := c.readResponse(); line != `NO "TLS already active"` {
		t.Fatalf("implicit-TLS STARTTLS response = %q", line)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("implicit TLS called STARTTLS hooks %d times", got)
	}
}
