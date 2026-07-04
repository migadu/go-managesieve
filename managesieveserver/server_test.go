package managesieveserver_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesievemem"
	"github.com/migadu/go-managesieve/managesieveserver"
)

// newTestStore builds a mem store with one account.
func newTestStore() *managesievemem.Store {
	store := managesievemem.New()
	store.AddUser("user@example.com", "secret")
	return store
}

// startServer starts a server with the given options on a random port.
func startServer(t *testing.T, opts managesieveserver.Options) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := managesieveserver.New(opts)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// startDefaultServer starts a server backed by the given store with
// permissive test defaults.
func startDefaultServer(t *testing.T, store *managesievemem.Store) string {
	t.Helper()
	return startServer(t, managesieveserver.Options{
		NewSession:    store.NewSession,
		InsecureAuth:  true, // no TLS in most tests
		IdleTimeout:   5 * time.Second,
		MaxScriptSize: 4096,
		Greeting:      `"Test" ManageSieve server ready.`,
		SieveExtensions: []string{
			"fileinto", "vacation",
		},
	})
}

// client is a line-oriented test client.
type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, conn: conn, r: bufio.NewReader(conn)}
}

func (c *client) send(line string) {
	c.t.Helper()
	if _, err := c.conn.Write([]byte(line + "\r\n")); err != nil {
		c.t.Fatalf("send %q: %v", line, err)
	}
}

func (c *client) sendRaw(data string) {
	c.t.Helper()
	if _, err := c.conn.Write([]byte(data)); err != nil {
		c.t.Fatalf("sendRaw: %v", err)
	}
}

func (c *client) readLine() string {
	c.t.Helper()
	line, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("readLine: %v (got %q)", err, line)
	}
	return strings.TrimRight(line, "\r\n")
}

// readResponse reads lines until an OK/NO/BYE response line, returning the
// response line and any preceding data lines (capability lines, literals).
func (c *client) readResponse() (resp string, data []string) {
	c.t.Helper()
	for {
		line := c.readLine()
		if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			return line, data
		}
		data = append(data, line)
	}
}

// greet consumes the capability greeting, returning the OK line and
// capability lines.
func (c *client) greet() (okLine string, caps []string) {
	c.t.Helper()
	return c.readResponse()
}

// authenticate performs SASL PLAIN with an inline initial response.
func (c *client) authenticate(username, password string) {
	c.t.Helper()
	c.greet()
	payload := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
	c.send(fmt.Sprintf(`AUTHENTICATE "PLAIN" "%s"`, payload))
	resp, _ := c.readResponse()
	if resp != `OK "Authenticated"` {
		c.t.Fatalf("authenticate: got %q, want %q", resp, `OK "Authenticated"`)
	}
}

func expectPrefix(t *testing.T, got, wantPrefix string) {
	t.Helper()
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("got %q, want prefix %q", got, wantPrefix)
	}
}

// --- Greeting and capabilities ---

func TestGreeting(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)

	okLine, caps := c.greet()
	if okLine != `OK "Test" ManageSieve server ready.` {
		t.Errorf("greeting OK line = %q", okLine)
	}

	joined := strings.Join(caps, "\n")
	wanted := []string{
		`"IMPLEMENTATION" "Go ManageSieve server"`,
		`"VERSION" "1.0"`,
		`"SIEVE" "fileinto vacation"`,
		`"SASL" "PLAIN"`, // InsecureAuth allows SASL pre-TLS
		`"MAXSCRIPTSIZE" "4096"`,
	}
	for _, want := range wanted {
		if !strings.Contains(joined, want) {
			t.Errorf("capability greeting missing %q; got:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, `"STARTTLS"`) {
		t.Errorf("STARTTLS advertised without TLSConfig:\n%s", joined)
	}
}

func TestCapabilityCommand(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send("CAPABILITY")
	resp, caps := c.readResponse()
	if resp != "OK" {
		t.Errorf("CAPABILITY response = %q, want bare OK", resp)
	}
	if len(caps) == 0 || !strings.Contains(strings.Join(caps, "\n"), `"VERSION" "1.0"`) {
		t.Errorf("CAPABILITY block missing VERSION: %v", caps)
	}
}

func TestNoSASLWithoutTLSOrInsecureAuth(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:   store.NewSession,
		InsecureAuth: false,
		IdleTimeout:  5 * time.Second,
	})
	c := dial(t, addr)
	_, caps := c.greet()
	joined := strings.Join(caps, "\n")
	// RFC 5804 §1.7: SASL is a required capability; with no mechanism
	// available it is advertised with an empty value, never with PLAIN.
	if !strings.Contains(joined, `"SASL" ""`) {
		t.Errorf("SASL capability line missing on insecure connection: %v", caps)
	}
	if strings.Contains(joined, `"SASL" "PLAIN"`) {
		t.Errorf("SASL PLAIN advertised on insecure connection without InsecureAuth: %v", caps)
	}

	payload := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	c.send(fmt.Sprintf(`AUTHENTICATE "PLAIN" "%s"`, payload))
	resp, _ := c.readResponse()
	if resp != `NO "Authentication not permitted on insecure connection. Use STARTTLS first."` {
		t.Errorf("insecure AUTHENTICATE = %q", resp)
	}
}

// --- Authentication ---

func TestAuthenticateInline(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")
}

func TestAuthenticateContinuation(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send(`AUTHENTICATE "PLAIN"`)
	// The server challenges with an empty string continuation (RFC 5804 §2.1).
	if line := c.readLine(); line != `""` {
		t.Fatalf("continuation = %q, want %q", line, `""`)
	}
	payload := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	c.send(payload)
	resp, _ := c.readResponse()
	if resp != `OK "Authenticated"` {
		t.Errorf("continuation auth = %q", resp)
	}
}

func TestAuthenticateAbort(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send(`AUTHENTICATE "PLAIN"`)
	if line := c.readLine(); line != `""` {
		t.Fatalf("continuation = %q", line)
	}
	c.send("*")
	resp, _ := c.readResponse()
	if resp != `NO "Authentication cancelled"` {
		t.Errorf("abort = %q", resp)
	}
	// Connection stays usable.
	c.send("NOOP")
	resp, _ = c.readResponse()
	if resp != "OK" {
		t.Errorf("NOOP after abort = %q", resp)
	}
}

func TestAuthenticateLiteral(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	payload := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))

	for _, form := range []string{"{%d+}", "{%d}"} {
		c := dial(t, addr)
		c.greet()
		// Both literal forms are accepted; the server reads the literal
		// without emitting a continuation for AUTHENTICATE.
		c.sendRaw(fmt.Sprintf(`AUTHENTICATE "PLAIN" `+form+"\r\n", len(payload)))
		c.sendRaw(payload + "\r\n")
		resp, _ := c.readResponse()
		if resp != `OK "Authenticated"` {
			t.Errorf("literal form %q auth = %q", form, resp)
		}
	}
}

func TestAuthenticateLiteralTooLarge(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()
	c.send(`AUTHENTICATE "PLAIN" {999999+}`)
	resp, _ := c.readResponse()
	if resp != `NO "Invalid literal size"` {
		t.Errorf("oversize auth literal = %q", resp)
	}
}

func TestAuthenticateFailures(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())

	cases := []struct {
		name, line, want string
	}{
		{"wrong password",
			`AUTHENTICATE "PLAIN" "` + base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00wrong")) + `"`,
			`NO "Authentication failed"`},
		{"empty password",
			`AUTHENTICATE "PLAIN" "` + base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00")) + `"`,
			`NO "Authentication failed"`},
		{"bad base64", `AUTHENTICATE "PLAIN" "!!!not-base64!!!"`, `NO "Invalid authentication data"`},
		{"bad frame",
			`AUTHENTICATE "PLAIN" "` + base64.StdEncoding.EncodeToString([]byte("only-one-part")) + `"`,
			`NO "Invalid authentication format"`},
		{"bad mechanism", `AUTHENTICATE "CRAM-MD5"`, `NO "Unsupported authentication mechanism"`},
		{"no mechanism", `AUTHENTICATE`, `NO "Syntax: AUTHENTICATE mechanism"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dial(t, addr)
			c.greet()
			c.send(tc.line)
			resp, _ := c.readResponse()
			if resp != tc.want {
				t.Errorf("got %q, want %q", resp, tc.want)
			}
		})
	}
}

func TestReAuthenticationRejected(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// RFC 5804: AUTHENTICATE/LOGIN are invalid in the authenticated state.
	// The guard must reject without invoking the session.
	c.send(`AUTHENTICATE "PLAIN" "ignored"`)
	resp, _ := c.readResponse()
	if resp != `NO "Already authenticated"` {
		t.Errorf("re-AUTHENTICATE = %q", resp)
	}
	c.send(`LOGIN "user@example.com" "secret"`)
	resp, _ = c.readResponse()
	if resp != `NO "Already authenticated"` {
		t.Errorf("re-LOGIN = %q", resp)
	}
	// Session still works.
	c.send("LISTSCRIPTS")
	resp, _ = c.readResponse()
	if resp != "OK" {
		t.Errorf("LISTSCRIPTS after rejected re-auth = %q", resp)
	}
}

func TestLoginVerb(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send(`LOGIN "user@example.com" "secret"`)
	resp, _ := c.readResponse()
	if resp != `OK "Authenticated"` {
		t.Errorf("LOGIN = %q", resp)
	}
}

func TestLoginSyntax(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()
	c.send(`LOGIN "user@example.com"`)
	resp, _ := c.readResponse()
	if resp != `NO "Syntax: LOGIN address password"` {
		t.Errorf("LOGIN syntax error = %q", resp)
	}
}

// --- State machine ---

func TestNotAuthenticated(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	for _, cmd := range []string{
		"LISTSCRIPTS", `GETSCRIPT "x"`, `PUTSCRIPT "x" "keep;"`, `CHECKSCRIPT "keep;"`,
		`HAVESPACE "x" 100`, `RENAMESCRIPT "a" "b"`, `SETACTIVE "x"`, `DELETESCRIPT "x"`,
	} {
		c.send(cmd)
		resp, _ := c.readResponse()
		if resp != `NO "Not authenticated"` {
			t.Errorf("%s pre-auth = %q, want NO Not authenticated", cmd, resp)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()
	c.send("BOGUS")
	resp, _ := c.readResponse()
	if resp != `NO "Unknown command"` {
		t.Errorf("unknown = %q", resp)
	}
}

func TestNoop(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send("NOOP")
	resp, _ := c.readResponse()
	if resp != "OK" {
		t.Errorf("NOOP = %q", resp)
	}

	// NOOP with a tag echoes it in a TAG response code (used by
	// sieve-connect for STARTTLS capability resync).
	c.send(`NOOP "STARTTLS-RESYNC-CAPA"`)
	resp, _ = c.readResponse()
	if resp != `OK (TAG "STARTTLS-RESYNC-CAPA") "Done"` {
		t.Errorf("NOOP tag = %q", resp)
	}
}

func TestLogout(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()
	c.send("LOGOUT")
	resp, _ := c.readResponse()
	if resp != `OK "Goodbye"` {
		t.Errorf("LOGOUT = %q", resp)
	}
	// Server closes the connection.
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Error("connection still open after LOGOUT")
	}
}

// --- Script commands ---

func TestScriptLifecycle(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	script := "require \"fileinto\";\r\nkeep;\r\n"

	// PUTSCRIPT with a synchronizing literal: expect the `+` continuation.
	c.send(fmt.Sprintf(`PUTSCRIPT "test1" {%d}`, len(script)))
	if line := c.readLine(); line != "+" {
		t.Fatalf("sync literal continuation = %q, want +", line)
	}
	c.sendRaw(script + "\r\n")
	resp, _ := c.readResponse()
	if resp != `OK "Script stored"` {
		t.Fatalf("PUTSCRIPT = %q", resp)
	}

	// Replacing it reports updated.
	c.sendRaw(fmt.Sprintf("PUTSCRIPT \"test1\" {%d+}\r\n%s\r\n", len(script), script))
	resp, _ = c.readResponse()
	if resp != `OK "Script updated"` {
		t.Fatalf("PUTSCRIPT update = %q", resp)
	}

	// GETSCRIPT: literal framing {N} CRLF content CRLF then OK.
	c.send(`GETSCRIPT "test1"`)
	if line := c.readLine(); line != fmt.Sprintf("{%d}", len(script)) {
		t.Fatalf("GETSCRIPT literal header = %q", line)
	}
	got := make([]byte, len(script))
	if _, err := c.r.Read(got); err != nil || string(got) != script {
		t.Fatalf("GETSCRIPT content = %q, err=%v", got, err)
	}
	// The literal is terminated by CRLF before the OK line.
	if line := c.readLine(); line != "" {
		t.Fatalf("expected literal-terminating CRLF, got %q", line)
	}
	if line := c.readLine(); line != "OK" {
		t.Fatalf("GETSCRIPT OK = %q", line)
	}

	// LISTSCRIPTS
	c.send("LISTSCRIPTS")
	resp, data := c.readResponse()
	if resp != "OK" || len(data) != 1 || data[0] != `"test1"` {
		t.Fatalf("LISTSCRIPTS = %q %v", resp, data)
	}

	// SETACTIVE + ACTIVE marker.
	c.send(`SETACTIVE "test1"`)
	resp, _ = c.readResponse()
	if resp != "OK" {
		t.Fatalf("SETACTIVE = %q", resp)
	}
	c.send("LISTSCRIPTS")
	resp, data = c.readResponse()
	if resp != "OK" || len(data) != 1 || data[0] != `"test1" ACTIVE` {
		t.Fatalf("LISTSCRIPTS active = %q %v", resp, data)
	}

	// The active script must not be deletable (RFC 5804 §2.10).
	c.send(`DELETESCRIPT "test1"`)
	resp, _ = c.readResponse()
	if resp != `NO (ACTIVE) "Cannot delete the active script; deactivate it first"` {
		t.Fatalf("DELETESCRIPT active = %q", resp)
	}

	// SETACTIVE "" deactivates all, then delete succeeds.
	c.send(`SETACTIVE ""`)
	resp, _ = c.readResponse()
	if resp != "OK" {
		t.Fatalf(`SETACTIVE "" = %q`, resp)
	}
	c.send(`DELETESCRIPT "test1"`)
	resp, _ = c.readResponse()
	if resp != `OK "Script deleted"` {
		t.Fatalf("DELETESCRIPT = %q", resp)
	}

	// Missing scripts yield NONEXISTENT.
	for _, cmd := range []string{`GETSCRIPT "gone"`, `SETACTIVE "gone"`, `DELETESCRIPT "gone"`} {
		c.send(cmd)
		resp, _ = c.readResponse()
		if resp != `NO (NONEXISTENT) "Script does not exist"` {
			t.Errorf("%s = %q", cmd, resp)
		}
	}
}

func TestRenameScript(t *testing.T) {
	store := newTestStore()
	store.AddScript("user@example.com", "one", "keep;", false)
	store.AddScript("user@example.com", "two", "keep;", false)
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.send(`RENAMESCRIPT "one" "renamed"`)
	resp, _ := c.readResponse()
	if resp != "OK" {
		t.Errorf("RENAMESCRIPT = %q", resp)
	}

	c.send(`RENAMESCRIPT "renamed" "two"`)
	resp, _ = c.readResponse()
	if resp != `NO (ALREADYEXISTS) "A script with the new name already exists"` {
		t.Errorf("RENAMESCRIPT collision = %q", resp)
	}

	c.send(`RENAMESCRIPT "missing" "other"`)
	resp, _ = c.readResponse()
	if resp != `NO (NONEXISTENT) "Script does not exist"` {
		t.Errorf("RENAMESCRIPT missing = %q", resp)
	}

	c.send(`RENAMESCRIPT "" "other"`)
	resp, _ = c.readResponse()
	if resp != `NO "Script name cannot be empty"` {
		t.Errorf("RENAMESCRIPT empty old = %q", resp)
	}

	// The new name is held to PUTSCRIPT hygiene (quoted validation error).
	c.send(`RENAMESCRIPT "two" ""`)
	resp, _ = c.readResponse()
	if resp != `NO "script name cannot be empty"` {
		t.Errorf("RENAMESCRIPT empty new = %q", resp)
	}
}

func TestPutScriptInvalidName(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.sendRaw("PUTSCRIPT \"\" {5+}\r\nkeep;\r\n")
	resp, _ := c.readResponse()
	if resp != `NO "script name cannot be empty"` {
		t.Errorf("PUTSCRIPT empty name = %q", resp)
	}
}

func TestPutScriptQuotedContent(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// RFC 5804 allows the script content as a quoted string too.
	c.send(`PUTSCRIPT "quoted" "keep;"`)
	resp, _ := c.readResponse()
	if resp != `OK "Script stored"` {
		t.Fatalf("PUTSCRIPT quoted = %q", resp)
	}
	c.send(`GETSCRIPT "quoted"`)
	resp, data := c.readResponse()
	if resp != "OK" || len(data) < 2 || data[1] != "keep;" {
		t.Errorf("GETSCRIPT quoted-stored = %q %v", resp, data)
	}
}

func TestOversizeLiteralRejectedBeforeRead(t *testing.T) {
	addr := startDefaultServer(t, newTestStore()) // MaxScriptSize: 4096
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// The rejection must arrive WITHOUT the server reading (or waiting for)
	// the announced literal content — a hostile {N} must not force an
	// allocation or a read stall. We send only the command line; if the
	// server tried to consume the literal first, this read would time out.
	// Only the synchronizing {N} form supports reject-and-retry: the client
	// has not committed a body until the `+` continuation arrives.
	c.send(`PUTSCRIPT "big" {100000}`)
	resp, _ := c.readResponse()
	if resp != `NO (QUOTA/MAXSIZE) "Script size 100000 exceeds maximum allowed size 4096"` {
		t.Errorf("oversize literal = %q", resp)
	}

	c.send(`CHECKSCRIPT {50000}`)
	resp, _ = c.readResponse()
	if resp != `NO (QUOTA/MAXSIZE) "Script size 50000 exceeds maximum allowed size 4096"` {
		t.Errorf("oversize CHECKSCRIPT literal = %q", resp)
	}
}

// TestOversizeLiteralPipelinedBodyClosesConnection verifies that when a client
// pipelines the literal body (which may embed commands) in the same segment as
// an over-max PUTSCRIPT, the server rejects AND closes rather than misparsing
// the unread body as commands in the session. The compliant reject-and-retry
// flow (no body pipelined) stays connected — see
// TestOversizeLiteralRejectedBeforeRead.
func TestOversizeLiteralPipelinedBodyClosesConnection(t *testing.T) {
	addr := startDefaultServer(t, newTestStore()) // MaxScriptSize: 4096
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// The literal body (a smuggled DELETESCRIPT) arrives in the same write as
	// the over-max command line, so it is buffered when the server rejects.
	c.sendRaw("PUTSCRIPT \"x\" {100000+}\r\nDELETESCRIPT \"victim\"\r\n")
	resp, _ := c.readResponse()
	if !strings.HasPrefix(resp, "NO (QUOTA/MAXSIZE)") {
		t.Fatalf("expected NO (QUOTA/MAXSIZE), got %q", resp)
	}
	// Connection is closed; the smuggled DELETESCRIPT is never executed (a
	// second response would mean the body was parsed as a command).
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("expected connection close after pipelined oversize literal, got %q", line)
	}
}

func TestInvalidLiteralLength(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// The synchronizing form has no committed body: reject and stay usable.
	c.send(`PUTSCRIPT "x" {abc}`)
	resp, _ := c.readResponse()
	if resp != `NO "Invalid literal string length"` {
		t.Errorf("bad literal = %q", resp)
	}
	c.send("NOOP")
	resp, _ = c.readResponse()
	if resp != "OK" {
		t.Errorf("NOOP after rejected sync literal = %q", resp)
	}

	// The non-sync form commits a body of unknowable size: the stream cannot
	// be trusted, so the server must reject AND close.
	c.send(`PUTSCRIPT "x" {abc+}`)
	resp, _ = c.readResponse()
	if resp != `NO "Invalid literal string length"` {
		t.Errorf("bad non-sync literal = %q", resp)
	}
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("connection still open after invalid non-sync literal, got %q", line)
	}
}

func TestHaveSpace(t *testing.T) {
	store := newTestStore()
	store.MaxScripts = 1
	store.AddScript("user@example.com", "existing", "keep;", false)
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	// Replacement of an existing script: fits.
	c.send(`HAVESPACE "existing" 100`)
	resp, _ := c.readResponse()
	if resp != "OK" {
		t.Errorf("HAVESPACE existing = %q", resp)
	}

	// A new name would exceed the script-count quota.
	c.send(`HAVESPACE "new" 100`)
	resp, _ = c.readResponse()
	if resp != `NO (QUOTA/MAXSCRIPTS) "Maximum number of scripts reached"` {
		t.Errorf("HAVESPACE quota = %q", resp)
	}

	// Size above MaxScriptSize.
	c.send(`HAVESPACE "new" 100000`)
	resp, _ = c.readResponse()
	if resp != `NO (QUOTA/MAXSIZE) "Script size 100000 exceeds maximum allowed size 4096"` {
		t.Errorf("HAVESPACE oversize = %q", resp)
	}

	c.send(`HAVESPACE "new" notanumber`)
	resp, _ = c.readResponse()
	if resp != `NO "Invalid script size"` {
		t.Errorf("HAVESPACE bad size = %q", resp)
	}

	c.send(`HAVESPACE "new"`)
	resp, _ = c.readResponse()
	if resp != `NO "Syntax: HAVESPACE scriptName scriptSize"` {
		t.Errorf("HAVESPACE syntax = %q", resp)
	}
}

func TestPutScriptQuotaMaxScripts(t *testing.T) {
	store := newTestStore()
	store.MaxScripts = 1
	store.AddScript("user@example.com", "existing", "keep;", false)
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.sendRaw("PUTSCRIPT \"second\" {5+}\r\nkeep;\r\n")
	resp, _ := c.readResponse()
	if resp != `NO (QUOTA/MAXSCRIPTS) "Too many scripts for this account"` {
		t.Errorf("PUTSCRIPT quota = %q", resp)
	}
}

func TestCheckScript(t *testing.T) {
	store := newTestStore()
	store.Validate = func(content string) (string, error) {
		if strings.Contains(content, "bogus") {
			return "", fmt.Errorf(`unknown extension "bogus"`)
		}
		if strings.Contains(content, "deprecated") {
			return "line 1: deprecated construct", nil
		}
		return "", nil
	}
	addr := startDefaultServer(t, store)
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.send(`CHECKSCRIPT "keep;"`)
	resp, _ := c.readResponse()
	if resp != "OK" {
		t.Errorf("CHECKSCRIPT ok = %q", resp)
	}

	// Validation failure: quoted error string (response-splitting safe).
	c.send(`CHECKSCRIPT "require bogus;"`)
	resp, _ = c.readResponse()
	if resp != `NO "Script validation failed: unknown extension \"bogus\""` {
		t.Errorf("CHECKSCRIPT invalid = %q", resp)
	}

	// Warnings render as OK (WARNINGS) "..." (RFC 5804 §2.12).
	c.send(`CHECKSCRIPT "deprecated;"`)
	resp, _ = c.readResponse()
	if resp != `OK (WARNINGS) "line 1: deprecated construct"` {
		t.Errorf("CHECKSCRIPT warnings = %q", resp)
	}
}

// --- Abuse controls ---

func TestMaxErrors(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:   store.NewSession,
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
		MaxErrors:    3,
	})
	c := dial(t, addr)
	c.greet()

	for i := 0; i < 2; i++ {
		c.send("GARBAGE")
		resp, _ := c.readResponse()
		if resp != `NO "Unknown command"` {
			t.Fatalf("garbage %d = %q", i, resp)
		}
	}
	// The third error trips MaxErrors: response, then the courtesy NO, then close.
	c.send("GARBAGE")
	resp, _ := c.readResponse()
	if resp != `NO "Unknown command"` {
		t.Fatalf("final garbage = %q", resp)
	}
	resp, _ = c.readResponse()
	if resp != `BYE "Too many errors, closing connection"` {
		t.Fatalf("max errors notice = %q", resp)
	}
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Error("connection still open after MaxErrors")
	}
}

func TestLineTooLong(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:    store.NewSession,
		InsecureAuth:  true,
		IdleTimeout:   5 * time.Second,
		MaxLineLength: 64,
	})
	c := dial(t, addr)
	c.greet()

	c.send("NOOP " + strings.Repeat("x", 200))
	resp, _ := c.readResponse()
	if resp != `NO "Command line too long"` {
		t.Errorf("long line = %q", resp)
	}
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Error("connection still open after oversized line")
	}
}

func TestIdleTimeoutBye(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:   store.NewSession,
		InsecureAuth: true,
		IdleTimeout:  150 * time.Millisecond,
	})
	c := dial(t, addr)
	c.greet()

	resp, _ := c.readResponse()
	if resp != `BYE (TRYLATER) "Connection timed out due to inactivity, please reconnect"` {
		t.Errorf("idle BYE = %q", resp)
	}
}

func TestAbsoluteSessionTimeoutBye(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:             store.NewSession,
		InsecureAuth:           true,
		IdleTimeout:            5 * time.Second,
		AbsoluteSessionTimeout: 200 * time.Millisecond,
	})
	c := dial(t, addr)
	c.greet()

	resp, _ := c.readResponse()
	if resp != `BYE (TRYLATER) "Maximum session duration exceeded, please reconnect"` {
		t.Errorf("absolute BYE = %q", resp)
	}
}

func TestParseErrorResponse(t *testing.T) {
	addr := startDefaultServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send(`GETSCRIPT "unclosed`)
	resp, _ := c.readResponse()
	expectPrefix(t, resp, `NO "Invalid command syntax:`)
}

// --- NewSession rejection ---

func TestNewSessionErrorReject(t *testing.T) {
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			return nil, &managesieveserver.Error{Code: "TRYLATER", Message: "Too many connections"}
		},
	})
	c := dial(t, addr)
	resp, _ := c.readResponse()
	if resp != `NO (TRYLATER) "Too many connections"` {
		t.Errorf("reject banner = %q", resp)
	}
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Error("connection still open after rejection")
	}
}

func TestNewSessionSilentReject(t *testing.T) {
	addr := startServer(t, managesieveserver.Options{
		NewSession: func(conn *managesieveserver.Conn) (managesieveserver.Session, error) {
			return nil, managesieveserver.ErrSilentReject
		},
	})
	c := dial(t, addr)
	// No banner: the read hits EOF.
	if line, err := c.r.ReadString('\n'); err == nil {
		t.Errorf("expected silent close, got %q", line)
	}
}
