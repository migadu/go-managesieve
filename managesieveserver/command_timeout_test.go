package managesieveserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// blockingSession wraps a real session but blocks GETSCRIPT until the
// per-command context is cancelled, simulating a wedged backend (slow DB,
// stuck lock). It records whether the context carried a deadline.
type blockingSession struct {
	managesieveserver.Session
	sawDeadline chan bool
}

func (s *blockingSession) GetScript(ctx context.Context, name string) (string, error) {
	_, hasDeadline := ctx.Deadline()
	s.sawDeadline <- hasDeadline
	<-ctx.Done()
	return "", ctx.Err()
}

// TestCommandTimeoutAbortsBlockedHandler verifies that Options.CommandTimeout
// deadlines the per-command context: a handler blocked until ctx.Done() is
// released promptly and the client receives a NO, instead of the session
// wedging until the idle timeout or server shutdown.
func TestCommandTimeoutAbortsBlockedHandler(t *testing.T) {
	store := newTestStore()
	sawDeadline := make(chan bool, 1)
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(c *managesieveserver.Conn) (managesieveserver.Session, error) {
			sess, err := store.NewSession(c)
			if err != nil {
				return nil, err
			}
			return &blockingSession{Session: sess, sawDeadline: sawDeadline}, nil
		},
		InsecureAuth:   true,
		IdleTimeout:    time.Minute, // must NOT be what releases the handler
		CommandTimeout: 200 * time.Millisecond,
		MaxScriptSize:  4096,
		Greeting:       `"Test" ManageSieve server ready.`,
	})

	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	start := time.Now()
	c.send(`GETSCRIPT "any"`)
	resp, _ := c.readResponse()
	elapsed := time.Since(start)

	expectPrefix(t, resp, "NO")
	// The client dial deadline is 10s and IdleTimeout is 1m; a response well
	// under those bounds proves the per-command deadline released the handler.
	if elapsed > 5*time.Second {
		t.Fatalf("blocked handler released after %v, want ~CommandTimeout (200ms)", elapsed)
	}
	if hasDeadline := <-sawDeadline; !hasDeadline {
		t.Error("per-command context has no deadline; CommandTimeout was not applied")
	}
}
