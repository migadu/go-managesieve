package managesieveserver_test

// PUTSCRIPT can carry validation warnings exactly like CHECKSCRIPT
// (RFC 5804 §2.6 example: OK (WARNINGS) "..."), via the optional
// SessionPutScriptWarnings interface.

import (
	"strings"
	"testing"
)

func TestPutScriptWarnings(t *testing.T) {
	store := newTestStore()
	store.Validate = func(content string) (string, error) {
		if strings.Contains(content, "deprecated") {
			return "line 1: deprecated construct", nil
		}
		return "", nil
	}
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.send(`PUTSCRIPT "warned" "deprecated;"`)
	resp, _ := c.readResponse()
	if resp != `OK (WARNINGS) "line 1: deprecated construct"` {
		t.Errorf("PUTSCRIPT with warnings = %q", resp)
	}

	// The script is stored despite the warnings.
	c.send(`GETSCRIPT "warned"`)
	resp, data := c.readResponse()
	if resp != "OK" || len(data) < 2 || data[1] != "deprecated;" {
		t.Errorf("GETSCRIPT after warned PUTSCRIPT = %q %q", resp, data)
	}

	// No warnings: unchanged response.
	c.send(`PUTSCRIPT "clean" "keep;"`)
	resp, _ = c.readResponse()
	if resp != `OK "Script stored"` {
		t.Errorf("PUTSCRIPT without warnings = %q", resp)
	}
}
