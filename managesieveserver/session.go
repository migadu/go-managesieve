package managesieveserver

import (
	"context"

	"github.com/migadu/go-managesieve/managesieve"
)

// Session is a ManageSieve session for a single client connection.
//
// Implementations provide the business logic (authentication, script storage,
// Sieve validation, quotas) while the library handles protocol parsing,
// literal handling, response formatting, state machine enforcement, and
// per-command context management.
//
// The context passed to every method is derived from the connection context
// and carries a per-command deadline when command timeouts are configured.
// Implementations should propagate it into blocking work (database queries
// etc.) so in-flight operations are abandoned when the client disconnects or
// a timeout fires.
//
// # ManageSieve state machine
//
// The library enforces the RFC 5804 states:
//
//	NON-AUTHENTICATED  →  AuthenticatePlain / Login succeed  →  AUTHENTICATED
//
// Script methods are only called in the AUTHENTICATED state; the library
// replies NO to out-of-state commands without invoking the session. A second
// AUTHENTICATE/LOGIN on an authenticated connection is rejected with
// "NO Already authenticated" without invoking the session.
//
// # Sieve validation
//
// The library never parses Sieve scripts. PutScript, CheckScript and
// SetActive implementations are expected to validate script content
// themselves (e.g. with a Sieve interpreter library) and return a suitable
// error — conventionally an uncoded *Error whose Message carries the
// validation failure as a quoted string.
type Session interface {
	// Close is called when the connection is torn down (client disconnect,
	// LOGOUT, timeout, or server shutdown). It is always called exactly once,
	// regardless of whether the session was authenticated.
	Close() error

	// --- NON-AUTHENTICATED state ---

	// AuthenticatePlain handles decoded SASL PLAIN credentials. The library
	// owns the wire exchange (quoted-string or literal initial response, the
	// `""` continuation, `*` abort, base64 decoding, and NUL splitting); the
	// session receives the decoded authorization identity, authentication
	// identity, and password.
	//
	// Return nil on success; the library transitions the connection to the
	// AUTHENTICATED state and replies "OK Authenticated". Return an error to
	// reject: a plain error's text is sent verbatim after "NO "; return an
	// *Error to control the response code/message, with Close to drop the
	// connection after the response.
	//
	// A proxy implementation may call Conn.Hijack() from within this method
	// to take over the raw connection instead of entering the AUTHENTICATED
	// state.
	AuthenticatePlain(ctx context.Context, identity, username, password string) error

	// --- AUTHENTICATED state ---
	// All methods below are only called after successful authentication.

	// ListScripts returns all scripts for the account, corresponding to the
	// LISTSCRIPTS command (RFC 5804 §2.7). At most one entry may be Active.
	ListScripts(ctx context.Context) ([]managesieve.ScriptInfo, error)

	// GetScript returns the content of the named script (GETSCRIPT, §2.9).
	// The returned string is emitted verbatim inside a {N} literal. Return
	// &Error{Code: "NONEXISTENT", ...} when the script does not exist.
	GetScript(ctx context.Context, name string) (string, error)

	// PutScript stores a script (PUTSCRIPT, §2.6). The library has already
	// unquoted and validated the name (managesieve.ValidateScriptName) and
	// enforced Options.MaxScriptSize. The session validates the Sieve
	// content itself. Return updated=true when an existing script was
	// replaced ("OK Script updated") and false when a new script was created
	// ("OK Script stored").
	PutScript(ctx context.Context, name, content string) (updated bool, err error)

	// CheckScript validates script content without storing it (CHECKSCRIPT,
	// §2.12). Returning ("", nil) renders a bare "OK"; a non-empty warnings
	// string with a nil error renders `OK (WARNINGS) "<warnings>"`.
	CheckScript(ctx context.Context, content string) (warnings string, err error)

	// SetActive marks the named script active (SETACTIVE, §2.8). An empty
	// name deactivates all scripts. Return &Error{Code: "NONEXISTENT", ...}
	// when the script does not exist.
	SetActive(ctx context.Context, name string) error

	// DeleteScript deletes the named script (DELETESCRIPT, §2.10). Per RFC
	// 5804 the active script must not be deleted: return
	// &Error{Code: "ACTIVE", ...} in that case.
	DeleteScript(ctx context.Context, name string) error

	// RenameScript renames a script (RENAMESCRIPT, §2.11.1). The library has
	// validated newName. Return &Error{Code: "NONEXISTENT", ...} when oldName
	// does not exist and &Error{Code: "ALREADYEXISTS", ...} when newName is
	// taken.
	RenameScript(ctx context.Context, oldName, newName string) error

	// HaveSpace reports whether a script of the given name and size could be
	// stored (HAVESPACE, §2.5). The library has already rejected sizes above
	// Options.MaxScriptSize, so implementations only need to enforce
	// account-level quotas (e.g. a script-count limit; note a HAVESPACE for
	// an existing name is a replacement and does not increase the count).
	// Return nil to reply "OK".
	HaveSpace(ctx context.Context, name string, size int64) error
}

// SessionPutScriptWarnings may be implemented by a Session to surface Sieve
// validation warnings from PUTSCRIPT: RFC 5804 §2.6 allows PUTSCRIPT to
// succeed with warnings, rendered as `OK (WARNINGS) "<warnings>"` exactly
// like CHECKSCRIPT. The library probes for this interface via type assertion;
// when present, PutScriptWarnings is called instead of PutScript. With an
// empty warnings string the usual "Script stored"/"Script updated" response
// is kept.
type SessionPutScriptWarnings interface {
	Session

	// PutScriptWarnings stores a script like PutScript, additionally
	// returning validation warnings to show the client.
	PutScriptWarnings(ctx context.Context, name, content string) (updated bool, warnings string, err error)
}

// SessionLogin may be implemented by a Session to accept the non-standard
// `LOGIN "address" "password"` verb some legacy clients send. The library
// probes for this interface via type assertion; when absent, LOGIN is treated
// as an unknown command. The same TLS/InsecureAuth gate and re-authentication
// guard as AUTHENTICATE apply.
type SessionLogin interface {
	Session

	// Login authenticates with a plain username/password pair. The same
	// return-value contract as AuthenticatePlain applies, including the
	// ability to call Conn.Hijack() from within.
	Login(ctx context.Context, username, password string) error
}
