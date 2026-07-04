// Package managesieveclient is a minimal ManageSieve (RFC 5804) client for
// connecting to an upstream ManageSieve server. It is intended for proxy
// front-ends: after connecting, (optionally) upgrading via STARTTLS and
// authenticating, the caller takes over the raw connection and buffered
// reader to relay bytes bidirectionally between the downstream client and
// this upstream connection.
//
// All network operations honour both the deadline and the cancellation of
// the context passed to them: a deadline is applied to the socket, and a
// cancellation forces the in-flight read/write to unblock immediately. After
// a cancellation the Client is no longer usable and must be Closed. Line
// reads are bounded by Options.MaxLineLength; capability blocks by
// Options.MaxCapabilityLines.
package managesieveclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/go-managesieve/managesieve"
)

// Options configures a Client.
type Options struct {
	// TLSConfig, when set, enables TLS. With STARTTLS false the connection is
	// TLS from the start (implicit TLS). With STARTTLS true the client
	// connects in plaintext, reads the greeting, issues STARTTLS and
	// upgrades (re-reading the post-TLS capability block).
	TLSConfig *tls.Config

	// STARTTLS selects the STARTTLS upgrade path (see TLSConfig).
	STARTTLS bool

	// MaxLineLength bounds a single response line, so a server that never
	// sends a newline cannot grow the read buffer without limit. Default 8192.
	MaxLineLength int

	// MaxCapabilityLines bounds the total number of lines accepted in a
	// greeting or CAPABILITY block (including the terminating OK line), so a
	// misbehaving server cannot grow the result without limit. Default 64.
	MaxCapabilityLines int

	// Dialer, when set, establishes the TCP connection. Use it to bind a
	// source address, set keep-alive, emit PROXY-protocol via a custom
	// DialContext, etc. Default: &net.Dialer{}.
	Dialer *net.Dialer
}

// Client is a ManageSieve client connection.
type Client struct {
	conn     net.Conn
	reader   *bufio.Reader
	writer   *bufio.Writer
	maxLine  int
	maxCaps  int
	caps     map[string]string
	greeting string

	// deadlineMu serialises per-operation deadline arming against the
	// guard's cancellation poisoning: once poisoned is set, no later arm may
	// resurrect a live deadline, or a read/write racing with the
	// cancellation could block until the (possibly distant) ctx deadline.
	deadlineMu sync.Mutex
	poisoned   bool
}

// ProtocolError reports an unexpected (non-"OK") response from the server.
type ProtocolError struct {
	// Response is the offending server response line.
	Response string
}

func (e *ProtocolError) Error() string {
	return "managesieveclient: unexpected response: " + e.Response
}

// Dial connects to addr, completes the greeting (and, when configured, the
// implicit-TLS handshake or STARTTLS upgrade). The returned Client is ready
// for AuthenticatePlain before hand-off to a relay.
func Dial(ctx context.Context, addr string, opts Options) (*Client, error) {
	dialer := opts.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewClient(ctx, rawConn, opts)
}

// NewClient wraps an established connection (e.g. one that already carried a
// PROXY protocol header) and completes the greeting and any TLS upgrade, as
// Dial does.
func NewClient(ctx context.Context, rawConn net.Conn, opts Options) (*Client, error) {
	maxLine := opts.MaxLineLength
	if maxLine <= 0 {
		maxLine = 8192
	}
	maxCaps := opts.MaxCapabilityLines
	if maxCaps <= 0 {
		maxCaps = 64
	}

	conn := rawConn

	// Implicit TLS: wrap before reading the greeting.
	if opts.TLSConfig != nil && !opts.STARTTLS {
		tconn := tls.Client(rawConn, opts.TLSConfig)
		if dl, ok := ctx.Deadline(); ok {
			_ = tconn.SetDeadline(dl)
		}
		if err := tconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		conn = tconn
	}

	c := &Client{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		writer:  bufio.NewWriter(conn),
		maxLine: maxLine,
		maxCaps: maxCaps,
	}

	// Make the greeting read and any STARTTLS upgrade interruptible by ctx
	// cancellation (the deadline, when set, is applied per read/write).
	stop := c.guard(ctx)
	defer stop()

	if err := c.readCapabilityBlock(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	// STARTTLS upgrade path.
	if opts.TLSConfig != nil && opts.STARTTLS {
		if err := c.startTLS(ctx, opts.TLSConfig); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return c, nil
}

// Greeting returns the greeting's final OK line (from the most recent
// capability block — post-TLS when STARTTLS was used).
func (c *Client) Greeting() string { return c.greeting }

// Capabilities returns the capabilities advertised in the most recent
// greeting/CAPABILITY block, keyed by upper-cased name (e.g. "SIEVE", "SASL",
// "IMPLEMENTATION"). Valueless capabilities (e.g. "STARTTLS") map to "".
func (c *Client) Capabilities() map[string]string {
	out := make(map[string]string, len(c.caps))
	for k, v := range c.caps {
		out[k] = v
	}
	return out
}

// Conn returns the underlying net.Conn. After authentication, the caller
// typically clears deadlines (conn.SetDeadline(time.Time{})) and relays bytes
// between this conn and the downstream client.
func (c *Client) Conn() net.Conn { return c.conn }

// Reader returns the buffered reader over the connection. It may already hold
// bytes read ahead from the server; a relay must drain it before reading the
// raw conn so no server data is lost.
func (c *Client) Reader() *bufio.Reader { return c.reader }

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// SetDeadline sets the read/write deadline on the underlying connection. Pass
// the zero Time to clear deadlines before entering a relay.
func (c *Client) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// Capability issues CAPABILITY and returns the refreshed capability map.
func (c *Client) Capability(ctx context.Context) (map[string]string, error) {
	defer c.guard(ctx)()
	if err := c.writeCmd(ctx, "CAPABILITY"); err != nil {
		return nil, err
	}
	if err := c.readCapabilityBlock(ctx); err != nil {
		return nil, err
	}
	return c.Capabilities(), nil
}

// AuthenticatePlain authenticates with SASL PLAIN, sending the initial
// response on the AUTHENTICATE line. identity may be empty (the common case);
// a proxy impersonating a user via master credentials passes the target user
// as identity.
func (c *Client) AuthenticatePlain(ctx context.Context, identity, username, password string) error {
	defer c.guard(ctx)()
	payload := identity + "\x00" + username + "\x00" + password
	enc := base64.StdEncoding.EncodeToString([]byte(payload))
	if err := c.writeCmd(ctx, `AUTHENTICATE "PLAIN" `+managesieve.Quote(enc)); err != nil {
		return err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		return err
	}
	if !isOK(status) {
		return &ProtocolError{Response: status}
	}
	return nil
}

// Cmd sends a single command line and returns the server's single-line
// response verbatim (including "OK"/"NO"/"BYE"). It does not read
// capability blocks or literals; use Reader for those.
func (c *Client) Cmd(ctx context.Context, line string) (string, error) {
	defer c.guard(ctx)()
	if err := c.writeCmd(ctx, line); err != nil {
		return "", err
	}
	return c.readLine(ctx)
}

// Logout sends LOGOUT and expects "OK".
func (c *Client) Logout(ctx context.Context) error {
	status, err := c.Cmd(ctx, "LOGOUT")
	if err != nil {
		return err
	}
	if !isOK(status) {
		return &ProtocolError{Response: status}
	}
	return nil
}

// --- internal helpers ---

// guard makes the current operation interruptible by ctx *cancellation* (a
// ctx *deadline* is already applied to the socket by readLine/writeCmd): if
// ctx is cancelled while the operation is in flight, the connection deadline
// is forced into the past, unblocking any blocked read or write with a
// timeout error. The returned stop function must be called when the
// operation completes; nesting guards is harmless.
//
// The conn is captured at guard creation: even after a STARTTLS upgrade,
// poisoning the deadline of the underlying conn unblocks reads on the TLS
// layer above it.
func (c *Client) guard(ctx context.Context) (stop func()) {
	if ctx == nil || ctx.Done() == nil {
		return func() {}
	}
	conn := c.conn
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.deadlineMu.Lock()
			select {
			case <-done:
				// The operation already completed: a cancellation arriving
				// afterwards (e.g. a deferred cancel) must not poison the
				// connection for subsequent operations.
			default:
				// Poison, don't just poke: readLine/writeCmd re-arm the
				// deadline from ctx.Deadline(), and an arm racing with this
				// poke would otherwise resurrect a live deadline.
				c.poisoned = true
				_ = conn.SetDeadline(time.Now().Add(-time.Second))
			}
			c.deadlineMu.Unlock()
		case <-done:
		}
	}()
	return func() {
		// Taking the mutex orders this stop against an in-flight poke: after
		// stop returns, either the poke has fully landed (cancelled mid-op)
		// or it will observe done closed and skip.
		c.deadlineMu.Lock()
		close(done)
		c.deadlineMu.Unlock()
	}
}

// armReadDeadline applies ctx's deadline to reads unless the connection has
// been poisoned by a cancellation, in which case the expired deadline stays.
func (c *Client) armReadDeadline(ctx context.Context) {
	dl, ok := ctx.Deadline()
	if !ok {
		return
	}
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.poisoned {
		return
	}
	_ = c.conn.SetReadDeadline(dl)
}

// armWriteDeadline is armReadDeadline's write-side counterpart.
func (c *Client) armWriteDeadline(ctx context.Context) {
	dl, ok := ctx.Deadline()
	if !ok {
		return
	}
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.poisoned {
		return
	}
	_ = c.conn.SetWriteDeadline(dl)
}

func (c *Client) startTLS(ctx context.Context, cfg *tls.Config) error {
	if err := c.writeCmd(ctx, "STARTTLS"); err != nil {
		return err
	}
	status, err := c.readLine(ctx)
	if err != nil {
		return err
	}
	if !isOK(status) {
		return &ProtocolError{Response: status}
	}

	tconn := tls.Client(c.conn, cfg)
	if dl, ok := ctx.Deadline(); ok {
		_ = tconn.SetDeadline(dl)
	}
	if err := tconn.HandshakeContext(ctx); err != nil {
		return err
	}
	c.conn = tconn
	// Fresh reader/writer over the TLS conn; any plaintext buffered after the
	// OK response is discarded (guards against STARTTLS response injection).
	c.reader = bufio.NewReader(tconn)
	c.writer = bufio.NewWriter(tconn)

	// RFC 5804 §2.2: the server re-issues the capability block after TLS.
	return c.readCapabilityBlock(ctx)
}

// readCapabilityBlock consumes a capability listing terminated by an OK line
// (the greeting, a CAPABILITY response, or the post-STARTTLS re-issue),
// replacing the stored capability map.
func (c *Client) readCapabilityBlock(ctx context.Context) error {
	caps := make(map[string]string)
	for i := 0; ; i++ {
		if i >= c.maxCaps {
			return errors.New("managesieveclient: capability block too long")
		}
		line, err := c.readLine(ctx)
		if err != nil {
			return err
		}
		if isOK(line) {
			c.caps = caps
			c.greeting = line
			return nil
		}
		if isStatus(line, "NO") || isStatus(line, "BYE") {
			return &ProtocolError{Response: line}
		}
		name, value := parseCapabilityLine(line)
		if name != "" {
			caps[strings.ToUpper(name)] = value
		}
	}
}

// parseCapabilityLine splits a capability line into its (unquoted) name and
// optional (unquoted) value.
func parseCapabilityLine(line string) (name, value string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if line[0] != '"' {
		// Non-quoted single token (lenient).
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			return parts[0], unquote(strings.TrimSpace(parts[1]))
		}
		return parts[0], ""
	}
	// Quoted name, optionally followed by a quoted value.
	end := closingQuote(line)
	if end < 0 {
		return "", ""
	}
	name = unquote(line[:end+1])
	rest := strings.TrimSpace(line[end+1:])
	if rest == "" {
		return name, ""
	}
	return name, unquote(rest)
}

// closingQuote returns the index of the unescaped closing quote of a quoted
// string starting at index 0, or -1.
func closingQuote(s string) int {
	escaped := false
	for i := 1; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch s[i] {
		case '\\':
			escaped = true
		case '"':
			return i
		}
	}
	return -1
}

// unquote removes surrounding quotes and backslash escapes, passing
// non-quoted strings through unchanged.
func unquote(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	inner := s[1 : len(s)-1]
	var b strings.Builder
	b.Grow(len(inner))
	escaped := false
	for i := 0; i < len(inner); i++ {
		if escaped {
			b.WriteByte(inner[i])
			escaped = false
		} else if inner[i] == '\\' {
			escaped = true
		} else {
			b.WriteByte(inner[i])
		}
	}
	return b.String()
}

func (c *Client) writeCmd(ctx context.Context, line string) error {
	c.armWriteDeadline(ctx)
	if _, err := c.writer.WriteString(line + "\r\n"); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *Client) readLine(ctx context.Context) (string, error) {
	c.armReadDeadline(ctx)
	var line []byte
	for {
		chunk, isPrefix, err := c.reader.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, chunk...)
		if len(line) > c.maxLine {
			return "", errors.New("managesieveclient: response line too long")
		}
		if !isPrefix {
			break
		}
	}
	return string(line), nil
}

func isOK(line string) bool {
	return isStatus(line, "OK")
}

// isStatus reports whether line is a status response with the given code
// ("OK", "NO", "BYE") as a distinct token, not merely a capability whose name
// begins with those letters (e.g. "NOTIFY" must not be read as a "NO"
// response). A status line is the bare code, or the code followed by a space
// or a response-code parenthesis.
func isStatus(line, code string) bool {
	return line == code ||
		strings.HasPrefix(line, code+" ") ||
		strings.HasPrefix(line, code+"(") ||
		strings.HasPrefix(line, code+" (")
}
