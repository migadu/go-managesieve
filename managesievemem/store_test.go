package managesievemem_test

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesievemem"
	"github.com/migadu/go-managesieve/managesieveserver"
)

// TestSetActiveValidateDoesNotHoldStoreLock: the host Validate hook can be
// slow (it runs a Sieve interpreter); SETACTIVE must not run it while holding
// the store lock, or every other session blocks behind one activation.
func TestSetActiveValidateDoesNotHoldStoreLock(t *testing.T) {
	store := managesievemem.New()
	store.AddUser("u@example.com", "pw")
	if err := store.AddScript("u@example.com", "s", "keep;", false); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	store.Validate = func(string) (string, error) {
		close(entered)
		<-release
		return "", nil
	}

	newLoggedInSession := func() managesieveserver.Session {
		t.Helper()
		sess, err := store.NewSession(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.(managesieveserver.SessionLogin).Login(context.Background(), "u@example.com", "pw"); err != nil {
			t.Fatal(err)
		}
		return sess
	}

	activating := newLoggedInSession()
	reading := newLoggedInSession()

	done := make(chan error, 1)
	go func() { done <- activating.SetActive(context.Background(), "s") }()
	<-entered

	// While validation runs, reads on the store must not block.
	listDone := make(chan struct{})
	go func() {
		reading.ListScripts(context.Background())
		close(listDone)
	}()
	select {
	case <-listDone:
	case <-time.After(1 * time.Second):
		close(release)
		<-done
		t.Fatal("ListScripts blocked while SetActive ran the Validate hook (validation under store lock)")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("SetActive = %v", err)
	}
}
