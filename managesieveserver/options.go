package managesieveserver

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	"github.com/migadu/go-managesieve/managesieve"
)

// defaultMaxErrorDelay caps the progressive per-error back-off when
// Options.MaxErrorDelay is left at its zero value.
const defaultMaxErrorDelay = 30 * time.Second

// defaultWriteTimeout is applied when Options.WriteTimeout is left at its
// zero value. Each buffered write must complete within this window, so a
// stalled (non-reading) client cannot wedge a response forever.
const defaultWriteTimeout = 60 * time.Second

// defaultMaxLineLength is the default bound on a client command line.
// ManageSieve commands can be longer than most line protocols (script names,
// SASL initial responses), so the default is generous.
const defaultMaxLineLength = 8192

// defaultMaxAuthLiteral bounds an AUTHENTICATE initial-response literal.
const defaultMaxAuthLiteral = 8192

// Timeout kinds reported to Options.OnTimeout.
const (
	// TimeoutIdle: no client command arrived within IdleTimeout (or
	// AuthIdleTimeout before authentication).
	TimeoutIdle = "idle"
	// TimeoutAbsolute: the session exceeded AbsoluteSessionTimeout.
	TimeoutAbsolute = "absolute"
)

// Options configures a ManageSieve server.
type Options struct {
	// NewSession is called for each new connection. The Conn provides access
	// to the underlying net.Conn (for peer address, TLS state, etc.).
	// Returning an error rejects the connection immediately: the server sends
	// "NO <message>" and closes the connection. The message is
	// Options.RejectMessage by default, or the wire message of an *Error if
	// the returned error is (or wraps) one. Return ErrSilentReject to close
	// without any banner.
	NewSession func(conn *Conn) (Session, error)

	// TLSConfig enables STARTTLS support on plaintext connections. If nil,
	// STARTTLS is not advertised and the STARTTLS command is rejected. For
	// implicit-TLS listeners, leave this nil and mark the connection as TLS
	// via Conn.SetTLS in NewSession (or hand a *tls.Conn to ServeConn, which
	// the library detects itself).
	TLSConfig *tls.Config

	// Implementation is the value of the IMPLEMENTATION capability.
	// Default: "Go ManageSieve server".
	Implementation string

	// Greeting is the raw text sent after "OK " (or "OK (STARTTLS) ") in the
	// greeting line. It is emitted verbatim, so include RFC 5804 quoting
	// yourself (e.g. `"Acme" ManageSieve server ready.`).
	// Default: `"ManageSieve server ready"`.
	Greeting string

	// GreetingStartTLSHint, when true, prefixes the greeting OK with a
	// "(STARTTLS) " response code while STARTTLS is available on the
	// connection (TLSConfig set and the connection not yet TLS).
	GreetingStartTLSHint bool

	// SieveExtensions is the list advertised as the SIEVE capability (joined
	// with spaces). It should match exactly what the host's Sieve validator
	// accepts (see managesieve.GetSieveCapabilities).
	SieveExtensions []string

	// ExtraCapabilities lists additional capability lines to advertise after
	// the built-ins (IMPLEMENTATION, VERSION, SIEVE, STARTTLS, SASL,
	// MAXSCRIPTSIZE).
	ExtraCapabilities []managesieve.Capability

	// MaxScriptSize bounds script content. When > 0 it is advertised as the
	// MAXSCRIPTSIZE capability, and the library rejects PUTSCRIPT/CHECKSCRIPT
	// literals (and HAVESPACE sizes) above it with NO (QUOTA/MAXSIZE) —
	// crucially, an oversized literal is rejected before its content is read,
	// so a hostile size cannot force a large allocation. 0 = no limit and the
	// capability is not advertised.
	MaxScriptSize int64

	// MaxLineLength is the maximum length (in bytes) of a client command
	// line. Default: 8192.
	MaxLineLength int

	// MaxAuthLiteral bounds the AUTHENTICATE initial-response literal size.
	// Default: 8192.
	MaxAuthLiteral int64

	// IdleTimeout is the maximum time the server waits for a command from
	// the client before disconnecting with a BYE (TRYLATER). Default: 30
	// minutes. Set to a negative value to disable.
	IdleTimeout time.Duration

	// AuthIdleTimeout, if non-zero, overrides IdleTimeout before
	// authentication succeeds. It also bounds SASL continuation reads,
	// literal reads and the STARTTLS handshake. Default: 0 (use IdleTimeout
	// for all states).
	AuthIdleTimeout time.Duration

	// AbsoluteSessionTimeout is the maximum total duration of a session
	// regardless of activity. When exceeded, the server sends BYE (TRYLATER)
	// and closes the connection. Default: 0 (no absolute limit).
	AbsoluteSessionTimeout time.Duration

	// CommandTimeout is the maximum time allowed for a single command to
	// execute, enforced via context.WithTimeout on the per-command context.
	// Default: 0 (no per-command timeout).
	CommandTimeout time.Duration

	// WriteTimeout is the maximum time a single write to the client may
	// block, applied per underlying write. Default: 60s. Set to a negative
	// value to disable (e.g. when a connection wrapper already enforces
	// throughput).
	WriteTimeout time.Duration

	// InsecureAuth permits AUTHENTICATE/LOGIN over unencrypted connections.
	// When false (default), authentication is rejected on non-TLS
	// connections with a "use STARTTLS first" message and SASL mechanisms
	// are not advertised pre-TLS.
	InsecureAuth bool

	// MaxErrors is the maximum number of client protocol errors before the
	// server disconnects the client. This mitigates brute-force and fuzzing
	// attacks. Default: 10. Set to a negative value (e.g. -1) to disable the
	// limit entirely.
	//
	// A client protocol error is one the library itself detects: an unknown
	// command, a command in the wrong state, bad syntax, an invalid literal
	// length, a malformed SASL payload, or a failed authentication. Errors
	// returned by a Session for script operations do NOT count: the library
	// cannot distinguish a client fault from a transient server-side failure.
	MaxErrors int

	// AuthFailuresExemptFromMaxErrors, when true, keeps failed
	// Login/AuthenticatePlain attempts from counting toward MaxErrors
	// (malformed AUTH payloads still count). Embedders whose Session already
	// enforces authentication rate limiting can set this so a small
	// MaxErrors budget does not disconnect a legitimate user who mistypes a
	// password a couple of times. Default: false.
	AuthFailuresExemptFromMaxErrors bool

	// ErrorDelay is the base delay applied after a client error. The actual
	// delay is errorCount * ErrorDelay, capped by MaxErrorDelay, and is
	// interruptible by connection shutdown. Default: 0 (no delay).
	ErrorDelay time.Duration

	// MaxErrorDelay caps the progressive per-error delay computed from
	// ErrorDelay. Default: 30s. Ignored when ErrorDelay is 0.
	MaxErrorDelay time.Duration

	// StrictSessionErrors, when true, prevents plain (non-*Error) errors
	// returned by Session methods from reaching the client verbatim: the
	// response is replaced with a generic `NO "internal error"` and the
	// original error is logged. Recommended when session methods may
	// propagate errors from databases whose text must never leak to clients.
	// Default: false.
	StrictSessionErrors bool

	// RejectMessage is the text sent after "NO " when NewSession returns a
	// plain (non-*Error) error. It is emitted verbatim, so include RFC 5804
	// quoting yourself. Default: `"Service not available"`.
	RejectMessage string

	// UnknownCommandHandler, if set, is invoked for any command not handled
	// by the built-in dispatcher before the command is counted against
	// MaxErrors. The handler writes its own response via c.OK / c.No and may
	// inspect the live session via c.Session(). It returns handled=true if
	// it consumed the command, and close=true to tear the connection down
	// after the response is flushed.
	UnknownCommandHandler func(ctx context.Context, c *Conn, cmd string, args []string) (handled, close bool)

	// OnCommand, if set, is called after every command completes with the
	// command verb (upper-cased, without arguments so credentials are never
	// exposed), the wall-clock duration, and the error produced by the
	// command (nil on success). For PUTSCRIPT/CHECKSCRIPT the duration
	// excludes the time spent receiving the script literal from the client.
	// Intended for metrics and tracing.
	OnCommand func(cmd string, dur time.Duration, err error)

	// OnTimeout, if set, is called exactly once when the server disconnects
	// a client because a connection-level timer expired: TimeoutIdle when no
	// command arrived within IdleTimeout (or AuthIdleTimeout pre-auth),
	// TimeoutAbsolute when the session exceeded AbsoluteSessionTimeout. It
	// fires after the BYE notice is written and before the connection
	// closes. Intended for metrics; keep it fast and non-blocking. The
	// library owns these timers, so an embedder that also wraps the
	// net.Conn in its own idle checker should disarm that checker and count
	// disconnects from this hook instead — two owners of the same timer race
	// each other and can send the client a duplicate notice.
	OnTimeout func(kind string)

	// OnPanic, if set, is called when a panic escapes a connection's handler
	// goroutine, with the recovered value and the stack. The library always
	// logs the panic and closes the connection regardless.
	OnPanic func(recovered any, stack []byte)

	// Logger is the structured logger. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// defaults returns a copy of the options with zero-value fields replaced
// by their defaults.
func (o *Options) defaults() Options {
	opts := *o

	if opts.Implementation == "" {
		opts.Implementation = "Go ManageSieve server"
	}
	if opts.Greeting == "" {
		opts.Greeting = `"ManageSieve server ready"`
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	if opts.MaxLineLength == 0 {
		opts.MaxLineLength = defaultMaxLineLength
	}
	if opts.MaxAuthLiteral == 0 {
		opts.MaxAuthLiteral = defaultMaxAuthLiteral
	}
	if opts.MaxErrors == 0 {
		opts.MaxErrors = 10
	}
	if opts.MaxErrorDelay == 0 {
		opts.MaxErrorDelay = defaultMaxErrorDelay
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = defaultWriteTimeout
	}
	if opts.RejectMessage == "" {
		opts.RejectMessage = `"Service not available"`
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	return opts
}
