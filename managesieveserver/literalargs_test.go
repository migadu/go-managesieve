package managesieveserver_test

// Regression tests for literal-string handling findings:
//
//   - The SASL continuation response is a string (RFC 5804 §2.1) and may
//     arrive literal-framed, not only as a quoted/bare base64 line.
//   - A non-synchronizing {N+} literal commits its body: when the server
//     rejects the size it must close the connection, or a body arriving in a
//     later segment is parsed as commands (stream desync). Reject-and-retry
//     is only sound for the synchronizing {N} form.
//   - Any string argument may be a literal (§4: sieve-name is a string), not
//     just the trailing script content.

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestAuthenticateContinuationLiteral: the continuation response arrives as a
// non-sync literal instead of a bare/quoted base64 line.
func TestAuthenticateContinuationLiteral(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send(`AUTHENTICATE "PLAIN"`)
	if line := c.readLine(); line != `""` {
		t.Fatalf("continuation challenge = %q", line)
	}
	payload := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	c.sendRaw(fmt.Sprintf("{%d+}\r\n%s\r\n", len(payload), payload))
	resp, _ := c.readResponse()
	if resp != `OK "Authenticated"` {
		t.Errorf("literal continuation auth = %q", resp)
	}
}

// TestAuthenticateContinuationLiteralTooLarge: an oversized continuation
// literal is rejected, and — since the body is committed — the connection is
// closed rather than left to parse the body as commands.
func TestAuthenticateContinuationLiteralTooLarge(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send(`AUTHENTICATE "PLAIN"`)
	if line := c.readLine(); line != `""` {
		t.Fatalf("continuation challenge = %q", line)
	}
	c.send("{999999+}")
	resp, _ := c.readResponse()
	if resp != `NO "Invalid literal size"` {
		t.Errorf("oversized continuation literal = %q", resp)
	}
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after oversized continuation literal, got %q", line)
	}
}

// TestAuthenticateOversizeLiteralClosesConnection: AUTHENTICATE literals have
// no continuation step, so {N} and {N+} both commit the body — an oversized
// one must close the connection even when the body has not arrived yet.
func TestAuthenticateOversizeLiteralClosesConnection(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	for _, form := range []string{"{999999}", "{999999+}"} {
		c := dial(t, addr)
		c.greet()
		c.send(`AUTHENTICATE "PLAIN" ` + form)
		resp, _ := c.readResponse()
		if resp != `NO "Invalid literal size"` {
			t.Errorf("form %s: oversized auth literal = %q", form, resp)
		}
		if line, err := c.r.ReadString('\n'); err == nil {
			t.Errorf("form %s: connection still open, got %q", form, line)
		}
	}
}

// TestOversizeNonSyncLiteralLateBodyClosesConnection: the {N+} body arrives in
// a LATER segment than the rejected command line (nothing buffered at
// rejection time). The server must still close — resuming would execute the
// body as commands.
func TestOversizeNonSyncLiteralLateBodyClosesConnection(t *testing.T) {
	addr := startDefaultServer(t, newTestStore()) // MaxScriptSize: 4096
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.send(`PUTSCRIPT "x" {100000+}`)
	resp, _ := c.readResponse()
	if !strings.HasPrefix(resp, "NO (QUOTA/MAXSIZE)") {
		t.Fatalf("oversize non-sync literal = %q", resp)
	}

	// The committed body lands after the rejection, embedding a smuggled
	// command. A write error is fine (server already closed); what must NOT
	// happen is a response to the smuggled command.
	c.conn.Write([]byte("DELETESCRIPT \"victim\"\r\n"))
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("expected close after oversized non-sync literal, got %q", line)
	}
}

// TestLiteralScriptNameArguments: sieve-name arguments framed as literals
// (RFC 5804 §4: sieve-name = string = quoted / literal).
func TestLiteralScriptNameArguments(t *testing.T) {
	store := newTestStore()
	store.AddScript("user@example.com", "lit-name", "keep;", false)
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// GETSCRIPT with a non-sync literal name.
	c.sendRaw("GETSCRIPT {8+}\r\nlit-name\r\n")
	resp, data := c.readResponse()
	if resp != "OK" || len(data) < 2 || data[1] != "keep;" {
		t.Fatalf("GETSCRIPT literal name = %q %q", resp, data)
	}

	// RENAMESCRIPT with two literal names in one command.
	c.sendRaw("RENAMESCRIPT {8+}\r\nlit-name {7+}\r\nrenamed\r\n")
	resp, _ = c.readResponse()
	if resp != "OK" {
		t.Fatalf("RENAMESCRIPT literal names = %q", resp)
	}

	// The synchronizing {N} form gets a `+` continuation before the body
	// (library extension, consistent with PUTSCRIPT content literals).
	c.send("DELETESCRIPT {7}")
	if line := c.readLine(); line != "+" {
		t.Fatalf("sync literal name continuation = %q", line)
	}
	c.sendRaw("renamed\r\n")
	resp, _ = c.readResponse()
	if resp != `OK "Script deleted"` {
		t.Fatalf("DELETESCRIPT sync literal name = %q", resp)
	}

	// PUTSCRIPT with a literal name AND literal content: the name resolves
	// inline, the content keeps the deferred reject-before-read path.
	c.sendRaw("PUTSCRIPT {5+}\r\nfresh {5+}\r\nkeep;\r\n")
	resp, _ = c.readResponse()
	if resp != `OK "Script stored"` {
		t.Fatalf("PUTSCRIPT literal name+content = %q", resp)
	}
	c.send(`GETSCRIPT "fresh"`)
	resp, data = c.readResponse()
	if resp != "OK" || len(data) < 2 || data[1] != "keep;" {
		t.Fatalf("GETSCRIPT after literal-name PUTSCRIPT = %q %q", resp, data)
	}
}

// TestLiteralNameArgumentTooLarge: a name-position literal is bounded like
// the command line it replaces (MaxLineLength); the committed {N+} form
// closes on rejection.
func TestLiteralNameArgumentTooLarge(t *testing.T) {
	addr := startDefaultServer(t, newTestStore()) // MaxLineLength default 8192
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.send(`GETSCRIPT {99999+}`)
	resp, _ := c.readResponse()
	if resp != `NO "Literal argument too large"` {
		t.Errorf("oversized literal name = %q", resp)
	}
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after oversized name literal, got %q", line)
	}
}
