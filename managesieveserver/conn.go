package managesieveserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/go-managesieve/managesieve"
)

// Conn is a ManageSieve connection. It holds the per-connection state and
// drives the command loop. The consumer receives a *Conn in the NewSession
// callback to inspect the peer address, TLS state, etc.
type Conn struct {
	netConn net.Conn
	server  *Server
	reader  *bufio.Reader
	writer  *bufio.Writer
	session Session
	ctx     context.Context
	cancel  context.CancelFunc

	// rawConn is the connection as originally accepted. STARTTLS replaces
	// netConn with a *tls.Conn that wraps it, but never rawConn, so deadline
	// operations on rawConn always reach the socket — including from another
	// goroutine while this one is blocked mid-handshake.
	rawConn net.Conn

	// deadlineMu serialises read-deadline changes against forceReadUnblock.
	// Once poisoned is set (server shutdown), no later SetReadDeadline may
	// re-arm or clear the expired deadline, or a read racing with Close could
	// block again and outlive Server.Close.
	deadlineMu sync.Mutex
	poisoned   bool

	// authenticated tracks the RFC 5804 state: false = NON-AUTHENTICATED,
	// true = AUTHENTICATED.
	authenticated bool

	// Error tracking
	errorCount int

	// TLS state
	isTLS bool

	// Session start time for absolute session timeout.
	startTime time.Time

	// cmdStart is when the current command's measured execution began, for
	// the OnCommand hook. Literal-consuming handlers reset it after the
	// literal is received so the reported duration excludes client upload
	// time.
	cmdStart time.Time

	// hijacked is set by Hijack: the library stops driving the connection
	// and no longer closes the underlying net.Conn.
	hijacked bool

	// closePending is set when a handler's error requests connection closure
	// (via *Error{Close:true} or ErrCloseConnection) or when the stream is
	// no longer safe to resume (e.g. a failed literal read).
	closePending bool

	// lastErr holds the error produced by the current command, for the
	// OnCommand observability hook.
	lastErr error
}

// Context returns the connection-scoped context, cancelled when the
// connection is closed or the server shuts down.
func (c *Conn) Context() context.Context {
	return c.ctx
}

// NetConn returns the underlying net.Conn. Useful for consumers that need
// to inspect the peer address, apply PROXY protocol, etc.
func (c *Conn) NetConn() net.Conn {
	return c.netConn
}

// IsTLS reports whether the connection is currently using TLS (either
// implicit TLS or upgraded via STARTTLS).
func (c *Conn) IsTLS() bool {
	return c.isTLS
}

// SetTLS overrides the library's TLS detection. Call it from NewSession when
// the connection is TLS but the library cannot detect it (e.g. an implicit-TLS
// listener that hands out a wrapper type the unwrap walk does not recognise).
func (c *Conn) SetTLS(v bool) {
	c.isTLS = v
}

// Session returns the session associated with this connection. It is set once
// NewSession returns and is primarily intended for UnknownCommandHandler
// implementations that need to reach the consumer's own session state.
func (c *Conn) Session() Session {
	return c.session
}

// OK writes an "OK" response line. The message is emitted verbatim after
// "OK " (empty for a bare "OK"), so include RFC 5804 quoting yourself.
// Exposed for UnknownCommandHandler implementations.
func (c *Conn) OK(msg string) { c.ok(msg) }

// No writes a "NO" response line. The message is emitted verbatim after
// "NO " (empty for a bare "NO"). Exposed for UnknownCommandHandler
// implementations.
func (c *Conn) No(msg string) { c.no(msg) }

// Hijack detaches the underlying connection from the library's command loop.
// It may only be called from within a Session's AuthenticatePlain or Login
// method (i.e. while the connection is still in the NON-AUTHENTICATED state).
//
// On success the library will not write any further response for the current
// command, will exit the command loop as soon as the authenticating method
// returns, and will NOT close the returned net.Conn (the caller owns it).
// Session.Close is still invoked exactly once during teardown.
//
// It returns the raw net.Conn together with a *bufio.Reader holding any bytes
// already buffered from the client, so a command pipelined in the same TCP
// segment as the authentication exchange is preserved for the caller (e.g. a
// proxy taking over the relay). This is analogous to net/http's Hijacker.
//
// The connection-scoped context (Conn.Context) is cancelled as soon as the
// authenticating method returns, because the library's command loop exits at
// that point. The hijacker must therefore manage the relay's lifetime with
// its own context and must not derive it from Conn.Context.
func (c *Conn) Hijack() (net.Conn, *bufio.Reader, error) {
	if c.authenticated {
		return nil, nil, errors.New("managesieveserver: Hijack only valid during authentication")
	}
	if c.hijacked {
		return nil, nil, errors.New("managesieveserver: connection already hijacked")
	}
	// Flush anything we may have queued before handing off write ownership.
	if err := c.writer.Flush(); err != nil {
		return nil, nil, err
	}
	// Hand over a deadline-free socket: a mid-command write (e.g. the SASL
	// `""` challenge) armed a short per-write deadline that would otherwise
	// fire on the hijacker's relay writes long after the hand-off.
	c.setDeadline(time.Time{})
	c.hijacked = true
	// Ownership transfers to the hijacker: drop the connection from the
	// server's tracking so Server.Close does not poison its read deadline.
	c.server.unregisterConn(c)
	return c.netConn, c.reader, nil
}

// serve runs the ManageSieve command loop for this connection.
func (c *Conn) serve() {
	defer c.cancel()
	defer c.close()

	opts := c.server.opts

	// Send the capability greeting (RFC 5804 §1.1: the server sends its
	// capabilities followed by an OK line as soon as the connection opens).
	c.sendGreeting()
	if err := c.writer.Flush(); err != nil {
		return
	}

	for {
		// Shutdown (or absolute-timeout context expiry) that landed while a
		// command was executing: exit before blocking on another read. The
		// poisoned read deadline set by Server.Close covers a read already in
		// flight; this check covers the gap between commands.
		if c.ctx.Err() != nil {
			c.shutdownBye()
			return
		}

		// Set idle timeout for reading the next command.
		if d := c.nextReadDeadline(); !d.IsZero() {
			c.setReadDeadline(d)
		}

		line, err := c.readLine()
		if err != nil {
			if c.ctx.Err() != nil {
				// Server.Close kicked this connection out of its blocked read.
				c.shutdownBye()
			} else if isTimeout(err) {
				// Distinguish absolute session timeout from idle timeout.
				if opts.AbsoluteSessionTimeout > 0 && time.Since(c.startTime) >= opts.AbsoluteSessionTimeout {
					c.writeLine(`BYE (TRYLATER) "Maximum session duration exceeded, please reconnect"`)
					c.writer.Flush()
					opts.Logger.Info("ManageSieve: absolute session timeout",
						"duration", time.Since(c.startTime))
				} else {
					c.writeLine(`BYE (TRYLATER) "Connection timed out due to inactivity, please reconnect"`)
					c.writer.Flush()
					opts.Logger.Info("ManageSieve: connection timed out")
				}
			} else if errors.Is(err, errLineTooLong) {
				// Courtesy response before dropping: after an oversized line
				// the parser cannot safely resume.
				c.writeLine(`NO "Command line too long"`)
				c.writer.Flush()
			} else if errors.Is(err, errMissingCRLF) {
				// Malformed framing (bare LF or truncated-by-EOF line): the
				// line must not execute and the stream cannot resume.
				c.writeLine(`NO "Command line must end with CRLF"`)
				c.writer.Flush()
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var quit bool
		cmd, args, parseErr := parseLine(line)
		var argsOK bool
		if parseErr == nil && cmd != "" {
			// Resolve literal-framed arguments (RFC 5804 §4: any string
			// argument may be a literal) before dispatch. Content-position
			// literals are left to their handlers, which enforce their own
			// size bounds before reading.
			args, argsOK = c.resolveLiteralArgs(cmd, args)
		}
		if parseErr != nil {
			c.lastErr = parseErr
			c.clientError(fmt.Sprintf("Invalid command syntax: %v", parseErr))
		} else if cmd == "" {
			continue
		} else if !argsOK {
			// A response for the failed literal argument has been written;
			// the central enforcement below applies closePending/MaxErrors.
		} else {
			// Create per-command context with optional timeout.
			cmdCtx := c.ctx
			var cmdCancel context.CancelFunc
			if opts.CommandTimeout > 0 {
				cmdCtx, cmdCancel = context.WithTimeout(c.ctx, opts.CommandTimeout)
			} else {
				cmdCtx, cmdCancel = context.WithCancel(c.ctx)
			}

			// Clear the connection deadline during command execution (the
			// per-command context governs cancellation now). Continuation and
			// literal reads inside handlers re-arm it. Write deadlines, when
			// configured, are re-armed per write by writeDeadlineConn.
			c.setDeadline(time.Time{})

			c.lastErr = nil
			c.cmdStart = time.Now()
			quit = c.dispatch(cmdCtx, cmd, args)
			cmdCancel()

			if h := opts.OnCommand; h != nil {
				h(cmd, time.Since(c.cmdStart), c.lastErr)
			}
		}

		// A handler hijacked the connection: ownership has transferred, so
		// do not flush or close via the loop.
		if c.hijacked {
			return
		}

		// Central enforcement: a handler may have requested closure, and any
		// error-counting path (failed auth, bad literal, unknown command) is
		// checked here so no path can bypass MaxErrors.
		if !quit && c.closePending {
			quit = true
		}
		if !quit && c.maxErrorsExceeded() {
			// RFC 5804 §1.2: the server SHOULD announce closure with BYE.
			c.writeLine(`BYE "Too many errors, closing connection"`)
			quit = true
		}

		// Flush response to the client.
		if err := c.writer.Flush(); err != nil {
			if isTimeout(err) {
				opts.Logger.Info("ManageSieve: write timeout", "command", cmd)
			}
			return
		}

		if quit {
			return
		}
	}
}

// setReadDeadline arms (or, with the zero Time, clears) the read deadline,
// unless the connection has been poisoned by server shutdown, in which case
// the already-expired deadline is left in place so pending and future reads
// fail immediately.
func (c *Conn) setReadDeadline(t time.Time) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.poisoned {
		return
	}
	c.netConn.SetReadDeadline(t)
}

// setDeadline is setReadDeadline's counterpart for the paths that arm both
// read and write deadlines (the STARTTLS handshake, the per-command clear).
func (c *Conn) setDeadline(t time.Time) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.poisoned {
		return
	}
	c.netConn.SetDeadline(t)
}

// forceReadUnblock permanently expires the read deadline. Server.Close uses
// it to kick a connection out of a blocked read (cancelling a context cannot
// unblock net.Conn reads); serve then observes the cancelled context and
// exits. It targets rawConn so the poke reaches the socket even while netConn
// is being swapped by a STARTTLS upgrade, and it marks the connection
// poisoned so a SetReadDeadline racing with shutdown cannot re-arm a live
// deadline. Writes are unaffected, so the shutdown BYE still gets out.
func (c *Conn) forceReadUnblock() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.poisoned = true
	c.rawConn.SetReadDeadline(time.Now())
}

// shutdownBye tells the client why its connection is going away after the
// connection context was cancelled: the absolute session timeout if that is
// what expired (handleConn derives the context from it), otherwise server
// shutdown.
func (c *Conn) shutdownBye() {
	opts := c.server.opts
	if opts.AbsoluteSessionTimeout > 0 && time.Since(c.startTime) >= opts.AbsoluteSessionTimeout {
		c.writeLine(`BYE (TRYLATER) "Maximum session duration exceeded, please reconnect"`)
		opts.Logger.Info("ManageSieve: absolute session timeout",
			"duration", time.Since(c.startTime))
	} else {
		c.writeLine(`BYE (TRYLATER) "Server shutting down, please reconnect"`)
	}
	c.writer.Flush()
}

// nextReadDeadline computes the read deadline for the next command, honouring
// AuthIdleTimeout before authentication and capping to AbsoluteSessionTimeout.
// Returns the zero Time when no deadline applies.
func (c *Conn) nextReadDeadline() time.Time {
	opts := c.server.opts

	idleTimeout := opts.IdleTimeout
	if !c.authenticated && opts.AuthIdleTimeout > 0 {
		idleTimeout = opts.AuthIdleTimeout
	}

	var deadline time.Time
	if idleTimeout > 0 {
		deadline = time.Now().Add(idleTimeout)
	}
	if opts.AbsoluteSessionTimeout > 0 {
		absDeadline := c.startTime.Add(opts.AbsoluteSessionTimeout)
		if deadline.IsZero() || absDeadline.Before(deadline) {
			deadline = absDeadline
		}
	}
	return deadline
}

// dispatch executes a single ManageSieve command. Returns true if the
// connection should be closed.
func (c *Conn) dispatch(ctx context.Context, cmd string, args []string) bool {
	switch cmd {
	case "CAPABILITY":
		c.sendCapabilityBlock()
		c.writeLine("OK")
	case "STARTTLS":
		return c.handleStartTLS(ctx)
	case "AUTHENTICATE":
		c.handleAuthenticate(ctx, args)
	case "LOGIN":
		if login, ok := c.session.(SessionLogin); ok {
			c.handleLogin(ctx, login, args)
		} else {
			return c.dispatchUnknown(ctx, cmd, args)
		}
	case "NOOP":
		// NOOP takes an optional tag argument (e.g. NOOP "STARTTLS-RESYNC-CAPA");
		// sieve-connect uses this to verify capabilities were received.
		if len(args) > 0 {
			tag := unquoteString(args[0])
			c.writeLine(fmt.Sprintf("OK (TAG %s) \"Done\"", managesieve.Quote(managesieve.SanitizeText(tag))))
		} else {
			c.writeLine("OK")
		}
	case "LOGOUT":
		c.writeLine(`OK "Goodbye"`)
		return true
	case "LISTSCRIPTS", "GETSCRIPT", "PUTSCRIPT", "CHECKSCRIPT", "HAVESPACE",
		"RENAMESCRIPT", "SETACTIVE", "DELETESCRIPT":
		if !c.authenticated {
			c.clientError("Not authenticated")
			return false
		}
		switch cmd {
		case "LISTSCRIPTS":
			c.handleListScripts(ctx)
		case "GETSCRIPT":
			c.handleGetScript(ctx, args)
		case "PUTSCRIPT":
			c.handlePutScript(ctx, args)
		case "CHECKSCRIPT":
			c.handleCheckScript(ctx, args)
		case "HAVESPACE":
			c.handleHaveSpace(ctx, args)
		case "RENAMESCRIPT":
			c.handleRenameScript(ctx, args)
		case "SETACTIVE":
			c.handleSetActive(ctx, args)
		case "DELETESCRIPT":
			c.handleDeleteScript(ctx, args)
		}
	default:
		return c.dispatchUnknown(ctx, cmd, args)
	}
	return false
}

// dispatchUnknown handles a command not recognised by the built-in
// dispatcher, giving the consumer's UnknownCommandHandler first refusal
// before counting the command against MaxErrors.
func (c *Conn) dispatchUnknown(ctx context.Context, cmd string, args []string) bool {
	if h := c.server.opts.UnknownCommandHandler; h != nil {
		if handled, closeConn := h(ctx, c, cmd, args); handled {
			return closeConn
		}
	}
	c.lastErr = fmt.Errorf("unknown command: %s", cmd)
	c.clientError("Unknown command")
	// Closure, if warranted, is applied centrally in serve via maxErrorsExceeded.
	return false
}

// --- Capability advertisement ---

// startTLSAvailable reports whether the STARTTLS upgrade is currently offered.
func (c *Conn) startTLSAvailable() bool {
	return c.server.opts.TLSConfig != nil && !c.isTLS
}

func (c *Conn) authAllowed() bool {
	return c.server.opts.InsecureAuth || c.isTLS
}

// sendCapabilityBlock writes the capability lines (without a trailing OK)
// used in the greeting, the CAPABILITY response, and after STARTTLS.
func (c *Conn) sendCapabilityBlock() {
	opts := c.server.opts

	c.writeLine(`"IMPLEMENTATION" ` + managesieve.Quote(opts.Implementation))
	c.writeLine(`"VERSION" "1.0"`)
	c.writeLine(`"SIEVE" ` + managesieve.Quote(strings.Join(opts.SieveExtensions, " ")))

	if c.startTLSAvailable() {
		c.writeLine(`"STARTTLS"`)
	}
	// RFC 5804 §1.7: SASL is a required capability. Mechanisms are only
	// advertised where authentication is actually accepted — after STARTTLS,
	// on implicit TLS, or pre-TLS when the operator opted into InsecureAuth;
	// otherwise the value is empty (don't advertise mechanisms the AUTH gate
	// would reject).
	if c.authAllowed() {
		c.writeLine(`"SASL" "PLAIN"`)
	} else {
		c.writeLine(`"SASL" ""`)
	}
	if opts.MaxScriptSize > 0 {
		c.writeLine(fmt.Sprintf(`"MAXSCRIPTSIZE" "%d"`, opts.MaxScriptSize))
	}
	for _, capa := range opts.ExtraCapabilities {
		if capa.HasValue {
			c.writeLine(managesieve.Quote(capa.Name) + " " + managesieve.Quote(capa.Value))
		} else {
			c.writeLine(managesieve.Quote(capa.Name))
		}
	}
}

// sendGreeting writes the capability block followed by the OK greeting line.
// RFC 5804 requires the same block to be re-sent after a STARTTLS upgrade.
func (c *Conn) sendGreeting() {
	opts := c.server.opts
	c.sendCapabilityBlock()
	if opts.GreetingStartTLSHint && c.startTLSAvailable() {
		c.writeLine("OK (STARTTLS) " + opts.Greeting)
	} else {
		c.writeLine("OK " + opts.Greeting)
	}
}

// --- Authentication ---

func (c *Conn) handleAuthenticate(ctx context.Context, args []string) {
	// RFC 5804: AUTHENTICATE is only valid in the non-authenticated state.
	// Rejecting re-authentication also protects sessions whose success path
	// registers per-connection resources exactly once.
	if c.authenticated {
		c.clientError("Already authenticated")
		return
	}
	if len(args) < 1 {
		c.clientError("Syntax: AUTHENTICATE mechanism")
		return
	}

	// Cleartext-auth gate.
	if !c.authAllowed() {
		c.clientError("Authentication not permitted on insecure connection. Use STARTTLS first.")
		return
	}

	mechanism := strings.ToUpper(unquoteString(args[0]))
	if mechanism != "PLAIN" {
		c.clientError("Unsupported authentication mechanism")
		return
	}

	var authData string
	if len(args) > 1 {
		// Initial response provided (either quoted string or literal).
		arg := args[1]
		if length, _, isLit, litErr := literalLength(arg); isLit {
			// Bound the literal before allocating: a hostile size must not
			// force a pre-auth memory blow-up.
			if litErr != nil || length > c.server.opts.MaxAuthLiteral {
				c.clientError("Invalid literal size")
				// AUTHENTICATE literals have no continuation step ({N} and
				// {N+} alike), so the client has committed the body: the
				// stream is desynced no matter when it arrives — close
				// rather than misparse the body as commands.
				c.closePending = true
				return
			}

			var ok bool
			if authData, ok = c.readAuthLiteral(length); !ok {
				return
			}
		} else {
			authData = unquoteString(arg)
		}
	} else {
		// No initial response: send the empty-string continuation (RFC 5804
		// §2.1: server challenges are string-framed, and PLAIN has no
		// challenge data).
		c.writeLine(`""`)
		if err := c.writer.Flush(); err != nil {
			c.closePending = true
			return
		}

		// Bound the continuation read so a client that requests AUTHENTICATE
		// and then goes silent cannot hold the connection open.
		if d := c.nextReadDeadline(); !d.IsZero() {
			c.setReadDeadline(d)
		}
		authLine, err := c.readLine()
		c.setReadDeadline(time.Time{})
		if err != nil {
			c.lastErr = err
			c.no(`"Authentication failed"`)
			c.closePending = true
			return
		}
		authData = strings.TrimSpace(authLine)

		// Client abort (RFC 5804 §2.1).
		if authData == "*" {
			c.lastErr = &Error{Message: "Authentication cancelled"}
			c.no(`"Authentication cancelled"`)
			return
		}

		// RFC 5804 §2.1: the continuation response is a string, so it may
		// arrive literal-framed rather than as a quoted/bare base64 line.
		if length, _, isLit, litErr := literalLength(authData); isLit {
			if litErr != nil || length > c.server.opts.MaxAuthLiteral {
				c.clientError("Invalid literal size")
				// The body is committed (no continuation step): close rather
				// than misparse it as commands.
				c.closePending = true
				return
			}
			var ok bool
			if authData, ok = c.readAuthLiteral(length); !ok {
				return
			}
		} else {
			authData = unquoteString(authData)
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		c.lastErr = err
		c.clientError("Invalid authentication data")
		return
	}

	// SASL PLAIN format: authzid \x00 authcid \x00 password
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		c.clientError("Invalid authentication format")
		return
	}
	authzID, authnID, password := parts[0], parts[1], parts[2]

	// Reject empty passwords immediately without invoking the session:
	// they are never valid under any condition.
	if password == "" {
		c.authFailure(&Error{Message: `"Authentication failed"`})
		return
	}

	if err := c.session.AuthenticatePlain(ctx, authzID, authnID, password); err != nil {
		c.authFailure(err)
		return
	}

	// The session may have hijacked the connection (proxy hand-off): if so,
	// do not emit a success response.
	if c.hijacked {
		return
	}

	c.authenticated = true
	c.writeLine(`OK "Authenticated"`)
}

// readAuthLiteral consumes an AUTHENTICATE literal body (initial response or
// continuation response) of the given pre-validated size, plus its trailing
// CRLF, under a read deadline — this path runs pre-auth, so an unbounded read
// here would let an unauthenticated peer park connections. On failure it
// writes the NO, marks the connection for closure and returns ok=false.
func (c *Conn) readAuthLiteral(length int64) (string, bool) {
	if d := c.nextReadDeadline(); !d.IsZero() {
		c.setReadDeadline(d)
	}
	data := make([]byte, int(length))
	_, err := io.ReadFull(c.reader, data)
	if err == nil {
		_, err = c.readLine()
	}
	c.setReadDeadline(time.Time{})
	if err != nil {
		// The stream is desynced (partial literal) or dead; respond and
		// tear down.
		c.lastErr = err
		c.no(`"Authentication failed"`)
		c.closePending = true
		return "", false
	}
	return string(data), true
}

func (c *Conn) handleLogin(ctx context.Context, login SessionLogin, args []string) {
	if c.authenticated {
		c.clientError("Already authenticated")
		return
	}

	// LOGIN carries the password as a plaintext command argument, so it
	// honors the same transport-security policy as AUTHENTICATE.
	if !c.authAllowed() {
		c.clientError("Authentication not permitted on insecure connection. Use STARTTLS first.")
		return
	}

	if len(args) < 2 {
		c.clientError("Syntax: LOGIN address password")
		return
	}
	username := unquoteString(args[0])
	password := unquoteString(args[1])

	if err := login.Login(ctx, username, password); err != nil {
		c.authFailure(err)
		return
	}

	if c.hijacked {
		return
	}

	c.authenticated = true
	c.writeLine(`OK "Authenticated"`)
}

// authFailure applies the auth-failure bookkeeping (MaxErrors counting unless
// exempt, progressive delay) and renders the session's error.
func (c *Conn) authFailure(err error) {
	if !c.server.opts.AuthFailuresExemptFromMaxErrors {
		c.errorCount++
	}
	c.applyErrorDelay()
	c.sessionError(err)
}

// --- STARTTLS ---

func (c *Conn) handleStartTLS(ctx context.Context) bool {
	opts := c.server.opts

	if opts.TLSConfig == nil {
		c.clientError("STARTTLS not supported")
		return false
	}
	if c.isTLS {
		c.clientError("TLS already active")
		return false
	}
	// RFC 5804 §2.2: STARTTLS resets to the non-authenticated state and prior
	// knowledge MUST be discarded. Rather than silently re-authenticate,
	// reject STARTTLS once authenticated (real clients always negotiate TLS
	// before auth).
	if c.authenticated {
		c.clientError("STARTTLS not permitted after authentication")
		return false
	}
	// RFC 5804 §2.2 / RFC 3207: reject (and close) if the client pipelined
	// any data after STARTTLS before the TLS handshake. Such buffered
	// plaintext may be a MITM command-injection attempt; it must not be
	// processed post-TLS.
	if c.reader.Buffered() > 0 {
		c.lastErr = errors.New("pipelined data after STARTTLS")
		c.no(`"Pipelined data after STARTTLS is not allowed"`)
		return true
	}

	c.writeLine(`OK "Begin TLS negotiation"`)
	if err := c.writer.Flush(); err != nil {
		return true
	}

	tlsConn := tls.Server(c.netConn, opts.TLSConfig)

	// Bound the handshake: a client that sends STARTTLS and then stalls
	// mid-negotiation must not hold the connection open indefinitely (a
	// pre-auth slowloris). The per-command ctx additionally aborts the
	// handshake on server shutdown or CommandTimeout.
	if d := c.nextReadDeadline(); !d.IsZero() {
		c.setDeadline(d)
	}
	err := tlsConn.HandshakeContext(ctx)
	c.setDeadline(time.Time{})
	if err != nil {
		// The peer has already switched to TLS, so no plaintext NO can be
		// delivered; drop the connection rather than looping in a broken
		// state (the old plaintext reader would only see TLS record bytes).
		opts.Logger.Warn("ManageSieve: TLS handshake failed", "error", err)
		c.lastErr = err
		return true
	}

	c.netConn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.writer = c.server.newWriter(tlsConn)
	c.isTLS = true

	// RFC 5804 §2.2: the server MUST re-issue the capability listing
	// (followed by an OK) immediately after a successful TLS negotiation.
	c.sendGreeting()
	return false
}

// --- Script commands (AUTHENTICATED state) ---

func (c *Conn) handleListScripts(ctx context.Context) {
	scripts, err := c.session.ListScripts(ctx)
	if err != nil {
		c.sessionError(err)
		return
	}
	for _, script := range scripts {
		line := managesieve.Quote(managesieve.SanitizeText(script.Name))
		if script.Active {
			line += " ACTIVE"
		}
		c.writeLine(line)
	}
	c.writeLine("OK")
}

func (c *Conn) handleGetScript(ctx context.Context, args []string) {
	if len(args) < 1 {
		c.clientError("Syntax: GETSCRIPT scriptName")
		return
	}
	name := strings.TrimSpace(unquoteString(args[0]))

	script, err := c.session.GetScript(ctx, name)
	if err != nil {
		c.sessionError(err)
		return
	}
	fmt.Fprintf(c.writer, "{%d}\r\n", len(script))
	c.writer.WriteString(script)
	// RFC 5804 §2.9 / §4: the string literal is terminated by CRLF before the
	// OK response line. Without this, the OK is glued to the last script
	// octet and clients that re-sync on the literal's trailing CRLF desync.
	c.writer.WriteString("\r\n")
	c.writeLine("OK")
}

func (c *Conn) handlePutScript(ctx context.Context, args []string) {
	if len(args) < 2 {
		c.clientError("Syntax: PUTSCRIPT scriptName scriptContent")
		return
	}

	content, ok := c.readScriptArgument(args[1])
	if !ok {
		return
	}

	// Validate script name - non-empty, valid UTF-8, no control characters.
	// An invalid name is a client protocol fault: route it through the
	// clientError choke point so it feeds MaxErrors/ErrorDelay.
	name := strings.TrimSpace(unquoteString(args[0]))
	if err := managesieve.ValidateScriptName(name); err != nil {
		c.lastErr = err
		c.clientError(err.Error())
		return
	}

	// Size bound for the quoted-string path (literals were bounded before
	// their content was read).
	if max := c.server.opts.MaxScriptSize; max > 0 && int64(len(content)) > max {
		c.quotaMaxSize(int64(len(content)))
		return
	}

	var (
		updated  bool
		warnings string
		err      error
	)
	if pw, ok := c.session.(SessionPutScriptWarnings); ok {
		updated, warnings, err = pw.PutScriptWarnings(ctx, name, content)
	} else {
		updated, err = c.session.PutScript(ctx, name, content)
	}
	if err != nil {
		c.sessionError(err)
		return
	}
	switch {
	case warnings != "":
		// RFC 5804 §2.6: stored, but the client should see the warnings.
		c.writeLine("OK (WARNINGS) " + managesieve.Quote(managesieve.SanitizeText(warnings)))
	case updated:
		c.writeLine(`OK "Script updated"`)
	default:
		c.writeLine(`OK "Script stored"`)
	}
}

func (c *Conn) handleCheckScript(ctx context.Context, args []string) {
	if len(args) < 1 {
		c.clientError("Syntax: CHECKSCRIPT scriptContent")
		return
	}

	content, ok := c.readScriptArgument(args[0])
	if !ok {
		return
	}

	if max := c.server.opts.MaxScriptSize; max > 0 && int64(len(content)) > max {
		c.quotaMaxSize(int64(len(content)))
		return
	}

	warnings, err := c.session.CheckScript(ctx, content)
	if err != nil {
		c.sessionError(err)
		return
	}
	if warnings != "" {
		// RFC 5804 §2.12: validation succeeded but the client should be
		// shown warnings.
		c.writeLine("OK (WARNINGS) " + managesieve.Quote(managesieve.SanitizeText(warnings)))
	} else {
		c.writeLine("OK")
	}
}

func (c *Conn) handleHaveSpace(ctx context.Context, args []string) {
	if len(args) < 2 {
		c.clientError("Syntax: HAVESPACE scriptName scriptSize")
		return
	}
	name := strings.TrimSpace(unquoteString(args[0]))
	size, err := parseInt64(args[1])
	if err != nil {
		c.clientError("Invalid script size")
		return
	}
	if max := c.server.opts.MaxScriptSize; max > 0 && size > max {
		c.quotaMaxSize(size)
		return
	}

	if err := c.session.HaveSpace(ctx, name, size); err != nil {
		c.sessionError(err)
		return
	}
	c.writeLine("OK")
}

func (c *Conn) handleRenameScript(ctx context.Context, args []string) {
	if len(args) < 2 {
		c.clientError("Syntax: RENAMESCRIPT oldName newName")
		return
	}
	oldName := strings.TrimSpace(unquoteString(args[0]))
	newName := strings.TrimSpace(unquoteString(args[1]))

	if oldName == "" {
		c.clientError("Script name cannot be empty")
		return
	}
	// The new name is being created; hold it to the same hygiene as PUTSCRIPT.
	if err := managesieve.ValidateScriptName(newName); err != nil {
		c.lastErr = err
		c.clientError(err.Error())
		return
	}

	if err := c.session.RenameScript(ctx, oldName, newName); err != nil {
		c.sessionError(err)
		return
	}
	c.writeLine("OK")
}

func (c *Conn) handleSetActive(ctx context.Context, args []string) {
	if len(args) < 1 {
		c.clientError("Syntax: SETACTIVE scriptName")
		return
	}
	// RFC 5804 §2.8: SETACTIVE "" deactivates all scripts.
	name := strings.TrimSpace(unquoteString(args[0]))

	if err := c.session.SetActive(ctx, name); err != nil {
		c.sessionError(err)
		return
	}
	c.writeLine("OK")
}

func (c *Conn) handleDeleteScript(ctx context.Context, args []string) {
	if len(args) < 1 {
		c.clientError("Syntax: DELETESCRIPT scriptName")
		return
	}
	name := strings.TrimSpace(unquoteString(args[0]))

	if err := c.session.DeleteScript(ctx, name); err != nil {
		c.sessionError(err)
		return
	}
	c.writeLine(`OK "Script deleted"`)
}

// literalDeferred reports whether a literal marker at position idx of cmd's
// argument list is a content-position literal whose reading is deferred to
// the command handler: PUTSCRIPT/CHECKSCRIPT content goes through
// readScriptArgument (MaxScriptSize enforced before the body is read) and the
// AUTHENTICATE initial response through readAuthLiteral (MaxAuthLiteral).
func literalDeferred(cmd string, idx int) bool {
	switch cmd {
	case "PUTSCRIPT", "AUTHENTICATE":
		return idx == 1
	case "CHECKSCRIPT":
		return idx == 0
	}
	return false
}

// resolveLiteralArgs reads literal-framed arguments inline (RFC 5804 §4:
// sieve-name and every other string argument may be a literal, e.g.
// `GETSCRIPT {8+}`): the literal body becomes the argument and parsing
// continues with the rest of the command that follows the body. Bodies are
// bounded by MaxLineLength — they stand in for text that would otherwise be
// part of the command line. Content-position literals (see literalDeferred)
// are left for their handlers. Returns ok=false when a response has already
// been written for a failure.
func (c *Conn) resolveLiteralArgs(cmd string, args []string) ([]string, bool) {
	for {
		// Only the last argument can be a literal marker: the marker is
		// always the final token of its physical line, with the body (and
		// the command's remaining arguments) following it.
		if len(args) == 0 {
			return args, true
		}
		idx := len(args) - 1
		length, nonSync, isLit, litErr := literalLength(args[idx])
		if !isLit || literalDeferred(cmd, idx) {
			return args, true
		}
		if litErr != nil {
			c.clientError("Invalid literal string length")
			// A malformed non-sync marker has committed a body of unknowable
			// size; the sync form has no committed body and may retry.
			if nonSync {
				c.closePending = true
			}
			return nil, false
		}
		if length > int64(c.server.opts.MaxLineLength) {
			c.clientError("Literal argument too large")
			// {N+} commits the body regardless of the rejection; {N} without
			// a continuation does not — unless bytes were wrongly pipelined.
			if nonSync || c.reader.Buffered() > 0 {
				c.closePending = true
			}
			return nil, false
		}

		if !nonSync {
			// Send the continuation for the synchronizing form (library
			// extension, consistent with PUTSCRIPT content literals).
			c.writeLine("+")
			if err := c.writer.Flush(); err != nil {
				c.closePending = true
				return nil, false
			}
		}

		if d := c.nextReadDeadline(); !d.IsZero() {
			c.setReadDeadline(d)
		}
		body := make([]byte, int(length))
		_, err := io.ReadFull(c.reader, body)
		var rest string
		if err == nil {
			// The command continues on the same logical line after the body
			// (possibly just the terminating CRLF), under the same deadline.
			rest, err = c.readLine()
		}
		c.setReadDeadline(time.Time{})
		if err != nil {
			// Partial literal: the stream is desynced and cannot resume.
			c.lastErr = err
			c.no(`"Failed to read literal argument"`)
			c.closePending = true
			return nil, false
		}

		// Re-quote the body so the handlers' per-argument unquoteString
		// round-trips values containing quote characters.
		args[idx] = managesieve.Quote(string(body))

		more, perr := parseTokens(strings.TrimSpace(rest))
		if perr != nil {
			c.lastErr = perr
			c.clientError(fmt.Sprintf("Invalid command syntax: %v", perr))
			return nil, false
		}
		args = append(args, more...)
	}
}

// readScriptArgument resolves a PUTSCRIPT/CHECKSCRIPT content argument: a
// quoted string is unquoted in place, a {N}/{N+} literal is read from the
// stream (after a `+` continuation for the synchronizing form). Returns
// ok=false when a response has already been written for a failure.
func (c *Conn) readScriptArgument(arg string) (string, bool) {
	length, nonSync, isLit, litErr := literalLength(arg)
	if !isLit {
		return unquoteString(arg), true
	}
	if litErr != nil {
		c.clientError("Invalid literal string length")
		// A malformed non-sync marker has committed a body of unknowable
		// size; the stream cannot be trusted. The sync form has no committed
		// body (no continuation was sent), so the client may retry.
		if nonSync {
			c.closePending = true
		}
		return "", false
	}

	// Enforce the size bound BEFORE reading (or allocating for) the literal:
	// rejecting first means a hostile {N} can never force a large allocation.
	if max := c.server.opts.MaxScriptSize; max > 0 && length > max {
		c.quotaMaxSize(length)
		// A non-sync {N+} commits the body regardless of this rejection —
		// whether it is already buffered or arrives in a later segment, the
		// stream is desynced and resuming would misparse the body as commands
		// in this session. Close instead. The synchronizing {N} form has no
		// committed body until the `+` continuation (never sent on this
		// path), so a compliant client keeps the connection for a clean
		// retry — unless it wrongly pipelined bytes behind the marker.
		if nonSync || c.reader.Buffered() > 0 {
			c.closePending = true
		}
		return "", false
	}

	if !nonSync {
		// Send continuation response (ready for literal data) only for
		// synchronizing literals.
		c.writeLine("+")
		if err := c.writer.Flush(); err != nil {
			c.closePending = true
			return "", false
		}
	}

	// Bound the literal read; a client that stalls mid-upload must not hold
	// the connection open indefinitely.
	if d := c.nextReadDeadline(); !d.IsZero() {
		c.setReadDeadline(d)
	}
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, c.reader, length)
	if err == nil {
		// Read the trailing CRLF after the literal (RFC 5804 compliance)
		// under the same deadline: a client that sends exactly the declared
		// octets and then withholds the CRLF must not wedge the connection.
		_, err = c.readLine()
	}
	c.setReadDeadline(time.Time{})
	if err != nil {
		// Partial literal: the stream is desynced and cannot safely resume.
		c.lastErr = err
		c.no(`"Failed to read literal string content"`)
		c.closePending = true
		return "", false
	}

	// Restart the command clock so OnCommand durations exclude the time the
	// client took to upload the script.
	c.cmdStart = time.Now()

	return buf.String(), true
}

// quotaMaxSize writes the NO (QUOTA/MAXSIZE) rejection for an oversized
// script or HAVESPACE size.
func (c *Conn) quotaMaxSize(size int64) {
	err := &Error{
		Code:    "QUOTA/MAXSIZE",
		Message: fmt.Sprintf("Script size %d exceeds maximum allowed size %d", size, c.server.opts.MaxScriptSize),
	}
	c.lastErr = err
	c.no(err.wireMessage())
}

// --- Response helpers ---

// writeLine writes a raw response line (CRLF appended).
func (c *Conn) writeLine(line string) {
	c.writer.WriteString(line)
	c.writer.WriteString("\r\n")
}

func (c *Conn) ok(msg string) {
	if msg == "" {
		c.writeLine("OK")
	} else {
		c.writeLine("OK " + stripCRLF(msg))
	}
}

func (c *Conn) no(msg string) {
	if msg == "" {
		c.writeLine("NO")
	} else {
		c.writeLine("NO " + stripCRLF(msg))
	}
}

// clientError records a client protocol error — bad syntax, an invalid
// argument, a command sent in the wrong state, or an unknown/unsupported
// command — then applies the progressive error delay and writes the NO
// response. It is the single choke point that feeds MaxErrors, so brute-force
// and fuzzing via malformed commands are bounded exactly like failed logins.
//
// The message is passed raw: it is sanitized (parse errors can echo client
// bytes) and emitted as an RFC 5804 §4 quoted string here.
//
// Errors returned by a Session are deliberately NOT routed here (see
// sessionError): the library cannot distinguish a client fault ("no such
// script") from a transient server-side failure, so those must not count
// against the client. A session that wants a specific error to be fatal
// signals it with *Error{Close: true} or ErrCloseConnection.
func (c *Conn) clientError(msg string) {
	c.errorCount++
	// Surface the error to the OnCommand hook (unless the handler already
	// recorded a more specific one) so protocol errors the library detects
	// are not reported as successful commands.
	if c.lastErr == nil {
		c.lastErr = &Error{Message: msg}
	}
	c.applyErrorDelay()
	c.no(managesieve.Quote(managesieve.SanitizeText(msg)))
}

// sessionError maps an error returned by a Session method onto a NO response
// and records whether the connection should be closed afterwards.
//
//   - *Error: its Code/Message are rendered and Close is honoured.
//   - ErrCloseConnection (bare or wrapped): a generic "internal error" is
//     sent and the connection is closed.
//   - any other error: its text is forwarded as-is (the documented Session
//     contract), unless Options.StrictSessionErrors is set, in which case a
//     generic "internal error" is sent and the original error is logged.
func (c *Conn) sessionError(err error) {
	c.lastErr = err

	var merr *Error
	if errors.As(err, &merr) {
		c.no(merr.wireMessage())
		if merr.Close {
			c.closePending = true
		}
		return
	}

	if errors.Is(err, ErrCloseConnection) {
		c.no(`"internal error"`)
		c.closePending = true
		return
	}

	if c.server.opts.StrictSessionErrors {
		c.server.opts.Logger.Warn("ManageSieve: masked plain session error (StrictSessionErrors)",
			"error", err, "remote", c.netConn.RemoteAddr())
		c.no(`"internal error"`)
		return
	}

	c.no(err.Error())
}

// --- Internal helpers ---

func (c *Conn) readLine() (string, error) {
	return readBoundedLine(c.reader, c.server.opts.MaxLineLength)
}

// applyErrorDelay sleeps for a progressive, capped back-off after a client
// error. The sleep is interruptible by connection/server shutdown so it never
// blocks Server.Close.
func (c *Conn) applyErrorDelay() {
	delay := c.server.opts.ErrorDelay
	if delay <= 0 {
		return
	}
	d := time.Duration(c.errorCount) * delay
	if limit := c.server.opts.MaxErrorDelay; limit > 0 && d > limit {
		d = limit
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-c.ctx.Done():
	}
}

// maxErrorsExceeded reports whether the client has hit the MaxErrors limit.
// A non-positive MaxErrors disables the limit.
func (c *Conn) maxErrorsExceeded() bool {
	max := c.server.opts.MaxErrors
	return max > 0 && c.errorCount >= max
}

func (c *Conn) close() {
	if c.session != nil {
		c.session.Close()
	}
	if !c.hijacked {
		c.netConn.Close()
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
