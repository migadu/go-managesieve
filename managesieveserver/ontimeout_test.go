package managesieveserver_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// timeoutKindRecorder collects OnTimeout invocations for assertions.
type timeoutKindRecorder struct {
	mu    sync.Mutex
	kinds []string
}

func (r *timeoutKindRecorder) record(kind string) {
	r.mu.Lock()
	r.kinds = append(r.kinds, kind)
	r.mu.Unlock()
}

func (r *timeoutKindRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.kinds...)
}

func TestOnTimeoutHookIdle(t *testing.T) {
	store := newTestStore()
	rec := &timeoutKindRecorder{}
	addr := startServer(t, managesieveserver.Options{
		NewSession:   store.NewSession,
		InsecureAuth: true,
		IdleTimeout:  1 * time.Second,
		OnTimeout:    rec.record,
	})

	c := dial(t, addr)
	c.greet()

	// Go idle past the timeout; the server must send a single BYE.
	time.Sleep(2 * time.Second)

	line := c.readLine()
	if !strings.HasPrefix(line, "BYE") || !strings.Contains(line, "timed out") {
		t.Fatalf("expected BYE idle-timeout notice, got %q", line)
	}

	// The connection must be closed with nothing else buffered: a second
	// line would mean two timeout owners both wrote a notice.
	if b, err := c.r.ReadByte(); err == nil {
		t.Fatalf("expected connection close after BYE, read %q", b)
	}

	// The hook must fire exactly once, with the idle kind — embedders count
	// disconnects from it, so a double invocation would skew their metrics.
	if kinds := rec.snapshot(); len(kinds) != 1 || kinds[0] != managesieveserver.TimeoutIdle {
		t.Fatalf("expected exactly one OnTimeout(%q), got %v", managesieveserver.TimeoutIdle, kinds)
	}
}

func TestOnTimeoutHookAbsolute(t *testing.T) {
	store := newTestStore()
	rec := &timeoutKindRecorder{}
	addr := startServer(t, managesieveserver.Options{
		NewSession:             store.NewSession,
		InsecureAuth:           true,
		IdleTimeout:            10 * time.Second,
		AbsoluteSessionTimeout: 1 * time.Second,
		OnTimeout:              rec.record,
	})

	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// Sit past the absolute limit; the capped read deadline fires and the
	// server must classify it as an absolute (not idle) timeout.
	time.Sleep(2 * time.Second)

	line := c.readLine()
	if !strings.HasPrefix(line, "BYE") || !strings.Contains(line, "session duration") {
		t.Fatalf("expected BYE absolute-timeout notice, got %q", line)
	}

	if b, err := c.r.ReadByte(); err == nil {
		t.Fatalf("expected connection close after BYE, read %q", b)
	}

	if kinds := rec.snapshot(); len(kinds) != 1 || kinds[0] != managesieveserver.TimeoutAbsolute {
		t.Fatalf("expected exactly one OnTimeout(%q), got %v", managesieveserver.TimeoutAbsolute, kinds)
	}
}
