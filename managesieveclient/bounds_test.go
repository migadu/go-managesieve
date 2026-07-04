package managesieveclient_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveclient"
)

// capServer serves one connection whose greeting is n capability lines
// followed by the OK line.
func capServer(t *testing.T, n int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "\"CAP%d\" \"v\"\r\n", i)
		}
		b.WriteString("OK \"ready\"\r\n")
		conn.Write([]byte(b.String()))
		time.Sleep(200 * time.Millisecond)
	}()
	return ln.Addr().String()
}

// TestMaxCapabilityLinesBound: MaxCapabilityLines bounds the TOTAL number of
// lines accepted in a block (including the terminating OK). A block of
// exactly the limit is accepted; one more line is rejected — previously an
// off-by-one accepted limit+1 lines.
func TestMaxCapabilityLinesBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 3 capability lines + OK = 4 lines: exactly at the bound, accepted.
	c, err := managesieveclient.Dial(ctx, capServer(t, 3), managesieveclient.Options{MaxCapabilityLines: 4})
	if err != nil {
		t.Fatalf("block of exactly MaxCapabilityLines lines rejected: %v", err)
	}
	c.Close()

	// 4 capability lines + OK = 5 lines: one over the bound, rejected.
	if c, err := managesieveclient.Dial(ctx, capServer(t, 4), managesieveclient.Options{MaxCapabilityLines: 4}); err == nil {
		c.Close()
		t.Error("block of MaxCapabilityLines+1 lines accepted (off-by-one)")
	}
}
