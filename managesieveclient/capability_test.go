package managesieveclient_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveclient"
)

// TestCapabilityUnquotedNoPrefix verifies the client does not mistake a
// capability whose name begins with "NO" (e.g. an unquoted NOTIFY) for a "NO"
// status response and abort the connection. Compliant servers quote
// capability names, but the client parses unquoted names leniently, so the
// status detection must be token-aware.
func TestCapabilityUnquotedNoPrefix(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Unquoted capability starting with "NO", then the OK greeting line.
		conn.Write([]byte("\"IMPLEMENTATION\" \"Test\"\r\nNOTIFY \"xmpp mailto\"\r\nOK \"ready\"\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	c, err := managesieveclient.Dial(ctx, ln.Addr().String(), managesieveclient.Options{})
	if err != nil {
		t.Fatalf("Dial errored on an unquoted NO-prefixed capability: %v", err)
	}
	defer c.Close()

	if got := c.Capabilities()["NOTIFY"]; got != "xmpp mailto" {
		t.Errorf("NOTIFY capability = %q, want %q (caps: %v)", got, "xmpp mailto", c.Capabilities())
	}
}

// TestCapabilityRealNoResponseStillDetected guards the fix: a genuine NO
// status line during the capability block must still surface as an error.
func TestCapabilityRealNoResponseStillDetected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("\"IMPLEMENTATION\" \"Test\"\r\nNO \"go away\"\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := managesieveclient.Dial(ctx, ln.Addr().String(), managesieveclient.Options{}); err == nil {
		t.Error("Dial should have failed on a NO status line in the greeting")
	}
}
