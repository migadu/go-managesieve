package managesieveserver_test

// Regression tests for connection-lifecycle findings: Hijack must hand over a
// socket free of the library's per-write deadline, and a panic inside the
// NewSession callback must be contained (connection closed, OnPanic invoked,
// server keeps accepting).

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// deadlineHijackSession hijacks during authentication and writes its success
// line only after a delay — longer than the library's WriteTimeout, so a
// stale write deadline left on the handed-over socket would fail the write.
// The embedded hijackSession supplies the script-method stubs.
type deadlineHijackSession struct {
	hijackSession
	conn     *managesieveserver.Conn
	delay    time.Duration
	writeErr chan error
}

func (s *deadlineHijackSession) AuthenticatePlain(ctx context.Context, identity, username, password string) error {
	netConn, _, err := s.conn.Hijack()
	if err != nil {
		return &managesieveserver.Error{Message: "hijack failed", Close: true}
	}
	go func() {
		time.Sleep(s.delay)
		_, werr := netConn.Write([]byte("OK \"relay\"\r\n"))
		s.writeErr <- werr
		netConn.Close()
	}()
	return nil
}

func TestHijackClearsStaleWriteDeadline(t *testing.T) {
	writeErr := make(chan error, 1)
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			return &deadlineHijackSession{conn: conn, delay: 500 * time.Millisecond, writeErr: writeErr}, nil
		},
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		WriteTimeout: 200 * time.Millisecond,
	})

	c := dial(t, addr)
	c.greet()

	// Continuation-SASL path: the `""` challenge write re-arms the per-write
	// deadline mid-command (the per-command deadline clear has already run),
	// so it is still pending when the session hijacks.
	c.send(`AUTHENTICATE "PLAIN"`)
	if line := c.readLine(); line != `""` {
		t.Fatalf("continuation challenge = %q", line)
	}
	payload := base64.StdEncoding.EncodeToString([]byte("\x00user\x00secret"))
	c.send(payload)

	// The relay's line lands 500ms after that challenge write armed the
	// 200ms deadline. Hijack must hand over a deadline-free socket.
	if line := c.readLine(); line != `OK "relay"` {
		t.Fatalf("relay line after hijack = %q", line)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("relay write on hijacked conn failed: %v", err)
	}
}

// TestNewSessionPanicContained guards the NewSession panic path: the
// connection is closed, OnPanic fires, and the server keeps serving new
// connections (recoverConn owns the cleanup — including the connection
// context's cancel, which must not leak).
func TestNewSessionPanicContained(t *testing.T) {
	store := newTestStore()
	var first, panicked atomic.Bool
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			if first.CompareAndSwap(false, true) {
				panic("boom in NewSession")
			}
			return store.NewSession(conn)
		},
		OnPanic:      func(recovered any, stack []byte) { panicked.Store(true) },
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
	})

	// First connection: the panic closes the socket without a banner.
	c1 := dial(t, addr)
	if line, err := c1.r.ReadString('\n'); err == nil {
		t.Fatalf("expected close after NewSession panic, got %q", line)
	}
	if !panicked.Load() {
		t.Error("OnPanic hook not invoked")
	}

	// The server is unaffected: a fresh connection works end to end.
	c2 := dial(t, addr)
	c2.greet()
	c2.send("NOOP")
	if resp, _ := c2.readResponse(); resp != "OK" {
		t.Errorf("NOOP after recovered panic = %q", resp)
	}
}
