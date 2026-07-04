package managesieveclient

// White-box test for the guard/deadline poisoning race: guard() unblocks a
// cancelled operation by forcing the connection deadline into the past, but
// readLine/writeCmd re-arm the deadline from ctx.Deadline() — an arm that
// lands after the poison used to override it, leaving the operation blocked
// until the (possibly distant) context deadline.

import (
	"bufio"
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// deadlineConn is a net.Conn stub whose Read blocks until the read deadline
// is in the past, mirroring a silent server.
type deadlineConn struct {
	mu       sync.Mutex
	deadline time.Time
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		d := c.deadline
		c.mu.Unlock()
		if !d.IsZero() && !d.After(time.Now()) {
			return 0, os.ErrDeadlineExceeded
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (c *deadlineConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineConn) Close() error                { return nil }
func (c *deadlineConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *deadlineConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}
func (c *deadlineConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *deadlineConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *deadlineConn) currentDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

// TestGuardPoisonNotOverridden: once the guard has poisoned the deadline for
// a cancelled context, a subsequent per-read deadline arm (the next readLine
// of a multi-line operation, using ctx.Deadline() far in the future) must not
// resurrect a live deadline — the read must fail immediately.
func TestGuardPoisonNotOverridden(t *testing.T) {
	conn := &deadlineConn{}
	c := &Client{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		writer:  bufio.NewWriter(conn),
		maxLine: 8192,
		maxCaps: 64,
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancel()

	stop := c.guard(ctx)
	defer stop()

	cancel()
	// Wait until the guard's poke has landed.
	deadlineIsPast := func() bool {
		d := conn.currentDeadline()
		return !d.IsZero() && !d.After(time.Now())
	}
	for i := 0; i < 500 && !deadlineIsPast(); i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if !deadlineIsPast() {
		t.Fatal("guard never poisoned the deadline after cancellation")
	}

	// The next read of the (cancelled) operation re-arms from ctx.Deadline()
	// — one hour away. It must not override the poison.
	errCh := make(chan error, 1)
	go func() {
		_, err := c.readLine(ctx)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("readLine returned nil error on a poisoned connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readLine re-armed the deadline over the cancellation poison and blocked")
	}
}
