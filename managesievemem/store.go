// Package managesievemem provides an in-memory ManageSieve session backend
// for tests and development. It implements the full managesieveserver.Session
// contract (plus SessionLogin) over a per-account script map with RFC 5804
// semantics: NONEXISTENT/ALREADYEXISTS/ACTIVE response codes, SETACTIVE ""
// deactivating all scripts, and active-script delete protection.
package managesievemem

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/migadu/go-managesieve/managesieve"
	"github.com/migadu/go-managesieve/managesieveserver"
)

// Store is an in-memory multi-account script store.
type Store struct {
	// MaxScripts caps the number of scripts per account, enforced by
	// PutScript and HaveSpace. 0 = unlimited.
	MaxScripts int

	// Validate, when set, is invoked with script content by PutScript,
	// CheckScript and SetActive, simulating host-side Sieve validation.
	// A returned error rejects the script; a non-empty warnings string from
	// CheckScript renders `OK (WARNINGS) "..."`.
	Validate func(content string) (warnings string, err error)

	mu       sync.RWMutex
	accounts map[string]*account
}

type account struct {
	password [32]byte // SHA-256 of the password, for constant-time comparison
	scripts  []*script
}

type script struct {
	name    string
	content string
	active  bool
}

// New creates an empty Store.
func New() *Store {
	return &Store{accounts: make(map[string]*account)}
}

// AddUser registers an account with the given credentials.
func (s *Store) AddUser(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[username] = &account{password: sha256.Sum256([]byte(password))}
}

// AddScript seeds a script for an account (for tests). An active=true script
// deactivates any previously active one.
func (s *Store) AddScript(username, name, content string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acct, ok := s.accounts[username]
	if !ok {
		return fmt.Errorf("managesievemem: unknown user %q", username)
	}
	if active {
		for _, sc := range acct.scripts {
			sc.active = false
		}
	}
	if sc := acct.find(name); sc != nil {
		sc.content = content
		sc.active = active
		return nil
	}
	acct.scripts = append(acct.scripts, &script{name: name, content: content, active: active})
	return nil
}

func (a *account) find(name string) *script {
	for _, sc := range a.scripts {
		if sc.name == name {
			return sc
		}
	}
	return nil
}

// NewSession creates a Session for a new connection. Assign it to
// managesieveserver.Options.NewSession:
//
//	store := managesievemem.New()
//	server := managesieveserver.New(managesieveserver.Options{
//		NewSession: store.NewSession,
//	})
func (s *Store) NewSession(_ *managesieveserver.Conn) (managesieveserver.Session, error) {
	return &Session{store: s}, nil
}

// Session is one connection's view of the store.
type Session struct {
	store    *Store
	username string
}

var (
	_ managesieveserver.Session                  = (*Session)(nil)
	_ managesieveserver.SessionLogin             = (*Session)(nil)
	_ managesieveserver.SessionPutScriptWarnings = (*Session)(nil)
)

var errAuthFailed = &managesieveserver.Error{Message: managesieve.Quote("Authentication failed")}

// dummyPassword equalizes comparison timing for unknown accounts.
var dummyPassword = sha256.Sum256([]byte("managesievemem-dummy-password"))

// Close implements managesieveserver.Session.
func (sess *Session) Close() error { return nil }

// AuthenticatePlain implements managesieveserver.Session. A non-empty
// authorization identity must match the authentication identity (the store
// has no impersonation support).
func (sess *Session) AuthenticatePlain(_ context.Context, identity, username, password string) error {
	if identity != "" && identity != username {
		return errAuthFailed
	}
	return sess.login(username, password)
}

// Login implements managesieveserver.SessionLogin.
func (sess *Session) Login(_ context.Context, username, password string) error {
	return sess.login(username, password)
}

func (sess *Session) login(username, password string) error {
	sess.store.mu.RLock()
	acct := sess.store.accounts[username]
	sess.store.mu.RUnlock()

	stored := dummyPassword
	if acct != nil {
		stored = acct.password
	}
	given := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(stored[:], given[:]) != 1 || acct == nil {
		return errAuthFailed
	}
	sess.username = username
	return nil
}

// authed returns the session's account. Script methods are only invoked by
// the library after authentication, so a missing account is a programming
// error surfaced as a closed connection.
func (sess *Session) authed() (*account, error) {
	acct := sess.store.accounts[sess.username]
	if acct == nil {
		return nil, managesieveserver.ErrCloseConnection
	}
	return acct, nil
}

// ListScripts implements managesieveserver.Session.
func (sess *Session) ListScripts(_ context.Context) ([]managesieve.ScriptInfo, error) {
	sess.store.mu.RLock()
	defer sess.store.mu.RUnlock()
	acct, err := sess.authed()
	if err != nil {
		return nil, err
	}
	infos := make([]managesieve.ScriptInfo, 0, len(acct.scripts))
	for _, sc := range acct.scripts {
		infos = append(infos, managesieve.ScriptInfo{Name: sc.name, Active: sc.active})
	}
	return infos, nil
}

// GetScript implements managesieveserver.Session.
func (sess *Session) GetScript(_ context.Context, name string) (string, error) {
	sess.store.mu.RLock()
	defer sess.store.mu.RUnlock()
	acct, err := sess.authed()
	if err != nil {
		return "", err
	}
	sc := acct.find(name)
	if sc == nil {
		return "", &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
	}
	return sc.content, nil
}

// PutScript implements managesieveserver.Session.
func (sess *Session) PutScript(ctx context.Context, name, content string) (bool, error) {
	updated, _, err := sess.PutScriptWarnings(ctx, name, content)
	return updated, err
}

// PutScriptWarnings implements managesieveserver.SessionPutScriptWarnings,
// surfacing Validate warnings the way CHECKSCRIPT does.
func (sess *Session) PutScriptWarnings(_ context.Context, name, content string) (bool, string, error) {
	// Validation runs before the store lock is taken: the host hook may be
	// slow and must not stall other sessions.
	var warnings string
	if v := sess.store.Validate; v != nil {
		var err error
		warnings, err = v(content)
		if err != nil {
			return false, "", wrapValidationError(err)
		}
	}

	sess.store.mu.Lock()
	defer sess.store.mu.Unlock()
	acct, err := sess.authed()
	if err != nil {
		return false, "", err
	}
	if sc := acct.find(name); sc != nil {
		sc.content = content
		return true, warnings, nil
	}
	if max := sess.store.MaxScripts; max > 0 && len(acct.scripts) >= max {
		return false, "", &managesieveserver.Error{Code: "QUOTA/MAXSCRIPTS", Message: "Too many scripts for this account"}
	}
	acct.scripts = append(acct.scripts, &script{name: name, content: content})
	return false, warnings, nil
}

// CheckScript implements managesieveserver.Session.
func (sess *Session) CheckScript(_ context.Context, content string) (string, error) {
	v := sess.store.Validate
	if v == nil {
		return "", nil
	}
	warnings, err := v(content)
	if err != nil {
		return "", wrapValidationError(err)
	}
	return warnings, nil
}

// SetActive implements managesieveserver.Session.
func (sess *Session) SetActive(_ context.Context, name string) error {
	// RFC 5804 §2.8: an empty name deactivates all scripts.
	if name == "" {
		sess.store.mu.Lock()
		defer sess.store.mu.Unlock()
		acct, err := sess.authed()
		if err != nil {
			return err
		}
		for _, sc := range acct.scripts {
			sc.active = false
		}
		return nil
	}

	// Snapshot the content, then run the (possibly slow) host Validate hook
	// WITHOUT the store lock so one activation cannot stall every other
	// session. The content may be replaced between validation and
	// activation; PUTSCRIPT validates on store, so the window is benign for
	// this reference store.
	sess.store.mu.RLock()
	acct, err := sess.authed()
	if err != nil {
		sess.store.mu.RUnlock()
		return err
	}
	target := acct.find(name)
	if target == nil {
		sess.store.mu.RUnlock()
		return &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
	}
	content := target.content
	sess.store.mu.RUnlock()

	// Hosts re-validate before activation; mirror that here.
	if err := sess.validate(content); err != nil {
		return err
	}

	sess.store.mu.Lock()
	defer sess.store.mu.Unlock()
	acct, err = sess.authed()
	if err != nil {
		return err
	}
	target = acct.find(name)
	if target == nil {
		return &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
	}
	for _, sc := range acct.scripts {
		sc.active = false
	}
	target.active = true
	return nil
}

// DeleteScript implements managesieveserver.Session.
func (sess *Session) DeleteScript(_ context.Context, name string) error {
	sess.store.mu.Lock()
	defer sess.store.mu.Unlock()
	acct, err := sess.authed()
	if err != nil {
		return err
	}
	for i, sc := range acct.scripts {
		if sc.name != name {
			continue
		}
		// RFC 5804 §2.10: the active script MUST NOT be deleted.
		if sc.active {
			return &managesieveserver.Error{Code: "ACTIVE", Message: "Cannot delete the active script; deactivate it first"}
		}
		acct.scripts = append(acct.scripts[:i], acct.scripts[i+1:]...)
		return nil
	}
	return &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
}

// RenameScript implements managesieveserver.Session.
func (sess *Session) RenameScript(_ context.Context, oldName, newName string) error {
	sess.store.mu.Lock()
	defer sess.store.mu.Unlock()
	acct, err := sess.authed()
	if err != nil {
		return err
	}
	sc := acct.find(oldName)
	if sc == nil {
		return &managesieveserver.Error{Code: "NONEXISTENT", Message: "Script does not exist"}
	}
	if acct.find(newName) != nil {
		return &managesieveserver.Error{Code: "ALREADYEXISTS", Message: "A script with the new name already exists"}
	}
	sc.name = newName
	return nil
}

// HaveSpace implements managesieveserver.Session. A HAVESPACE for an existing
// script name is a replacement, which does not increase the script count.
func (sess *Session) HaveSpace(_ context.Context, name string, _ int64) error {
	sess.store.mu.RLock()
	defer sess.store.mu.RUnlock()
	acct, err := sess.authed()
	if err != nil {
		return err
	}
	if max := sess.store.MaxScripts; max > 0 && acct.find(name) == nil && len(acct.scripts) >= max {
		return &managesieveserver.Error{Code: "QUOTA/MAXSCRIPTS", Message: "Maximum number of scripts reached"}
	}
	return nil
}

// validate runs the store's Validate hook.
func (sess *Session) validate(content string) error {
	v := sess.store.Validate
	if v == nil {
		return nil
	}
	if _, err := v(content); err != nil {
		return wrapValidationError(err)
	}
	return nil
}

// wrapValidationError renders a validation failure the way a host
// conventionally does: an uncoded *Error carrying a quoted message.
func wrapValidationError(err error) error {
	var merr *managesieveserver.Error
	if errors.As(err, &merr) {
		return err
	}
	return &managesieveserver.Error{
		Message: managesieve.Quote("Script validation failed: " + managesieve.SanitizeText(err.Error())),
	}
}
