package managesieveserver_test

// Regression tests for response-hygiene findings: RFC 5804 §4 wants the
// human-readable text of OK/NO/BYE responses framed as a quoted string, every
// client-fault rejection must flow through the MaxErrors/ErrorDelay choke
// point, closure on MaxErrors is announced with BYE (§1.2), and text echoed
// back to the client (NOOP tags, LISTSCRIPTS names) must be neutralized
// against response splitting.

import (
	"errors"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
)

// TestNameValidationCountsTowardMaxErrors pins that script-name validation
// failures are client protocol errors like any other: they must feed the
// MaxErrors budget (and its progressive delay), not bypass it via a direct NO.
func TestNameValidationCountsTowardMaxErrors(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:   store.NewSession,
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		MaxErrors:    3,
	})
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	for i := 0; i < 2; i++ {
		c.send(`PUTSCRIPT "" "keep;"`)
		resp, _ := c.readResponse()
		if resp != `NO "script name cannot be empty"` {
			t.Fatalf("invalid PUTSCRIPT name %d = %q", i, resp)
		}
	}

	// The third invalid name trips MaxErrors: response, BYE notice, close.
	c.send(`RENAMESCRIPT "" "x"`)
	resp, _ := c.readResponse()
	if resp != `NO "Script name cannot be empty"` {
		t.Fatalf("invalid RENAMESCRIPT name = %q", resp)
	}
	resp, _ = c.readResponse()
	if resp != `BYE "Too many errors, closing connection"` {
		t.Fatalf("max errors notice = %q", resp)
	}
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after MaxErrors, got %q", line)
	}
}

// TestNoopTagSanitized: a raw CR inside a quoted NOOP tag survives line
// parsing (lines are split on LF), so the TAG echo must neutralize it rather
// than reflect it into the response.
func TestNoopTagSanitized(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.sendRaw("NOOP \"a\rb\"\r\n")
	resp, _ := c.readResponse()
	if resp != `OK (TAG "a b") "Done"` {
		t.Errorf("NOOP raw-CR tag echo = %q", resp)
	}
}

// TestListScriptsSanitizesNames: managesievemem.AddScript bypasses
// ValidateScriptName — the out-of-band path (bulk import, DB seed) that can
// carry a hostile name. LISTSCRIPTS must emit it as one neutralized line,
// not split the response.
func TestListScriptsSanitizesNames(t *testing.T) {
	store := newTestStore()
	if err := store.AddScript("user@example.com", "evil\r\nOK injected", "keep;", false); err != nil {
		t.Fatal(err)
	}
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.send("LISTSCRIPTS")
	resp, data := c.readResponse()
	if resp != "OK" {
		t.Fatalf("LISTSCRIPTS = %q (response splitting?)", resp)
	}
	if len(data) != 1 || data[0] != `"evil  OK injected"` {
		t.Fatalf("LISTSCRIPTS lines = %q, want one sanitized name line", data)
	}
}

// TestPlainRejectMessageQuoted: the default NewSession rejection banner is
// RFC-framed as a quoted string.
func TestPlainRejectMessageQuoted(t *testing.T) {
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			return nil, errors.New("db down")
		},
	})
	c := dial(t, addr)
	resp, _ := c.readResponse()
	if resp != `NO "Service not available"` {
		t.Errorf("plain reject banner = %q", resp)
	}
}
