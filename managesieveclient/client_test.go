package managesieveclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveclient"
	"github.com/migadu/go-managesieve/managesievemem"
	"github.com/migadu/go-managesieve/managesieveserver"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// startServer runs a managesieveserver backed by a mem store for loopback
// client tests.
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

func newStore() *managesievemem.Store {
	store := managesievemem.New()
	store.AddUser("user@example.com", "secret")
	return store
}

func TestDialCapabilitiesAuth(t *testing.T) {
	addr := startServer(t, managesieveserver.Options{
		NewSession:      newStore().NewSession,
		InsecureAuth:    true,
		IdleTimeout:     5 * time.Second,
		SieveExtensions: []string{"fileinto", "vacation"},
		MaxScriptSize:   4096,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := managesieveclient.Dial(ctx, addr, managesieveclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	caps := c.Capabilities()
	if caps["SIEVE"] != "fileinto vacation" {
		t.Errorf("SIEVE capability = %q", caps["SIEVE"])
	}
	if caps["SASL"] != "PLAIN" {
		t.Errorf("SASL capability = %q", caps["SASL"])
	}
	if caps["MAXSCRIPTSIZE"] != "4096" {
		t.Errorf("MAXSCRIPTSIZE capability = %q", caps["MAXSCRIPTSIZE"])
	}

	if err := c.AuthenticatePlain(ctx, "", "user@example.com", "secret"); err != nil {
		t.Fatalf("AuthenticatePlain: %v", err)
	}

	// Post-auth, plain commands relay fine.
	status, err := c.Cmd(ctx, "LISTSCRIPTS")
	if err != nil || status != "OK" {
		t.Errorf("LISTSCRIPTS = %q, %v", status, err)
	}

	if err := c.Logout(ctx); err != nil {
		t.Errorf("Logout: %v", err)
	}
}

func TestAuthFailure(t *testing.T) {
	addr := startServer(t, managesieveserver.Options{
		NewSession:   newStore().NewSession,
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := managesieveclient.Dial(ctx, addr, managesieveclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.AuthenticatePlain(ctx, "", "user@example.com", "wrong")
	var perr *managesieveclient.ProtocolError
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if !errorsAs(err, &perr) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
	if perr.Response != `NO "Authentication failed"` {
		t.Errorf("failure response = %q", perr.Response)
	}
}

func TestStartTLSUpgrade(t *testing.T) {
	addr := startServer(t, managesieveserver.Options{
		NewSession:      newStore().NewSession,
		TLSConfig:       testTLSConfig(t),
		IdleTimeout:     5 * time.Second,
		SieveExtensions: []string{"fileinto"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := managesieveclient.Dial(ctx, addr, managesieveclient.Options{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		STARTTLS:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Post-TLS capabilities: SASL PLAIN now advertised, STARTTLS gone.
	caps := c.Capabilities()
	if caps["SASL"] != "PLAIN" {
		t.Errorf("post-TLS SASL = %q", caps["SASL"])
	}
	if _, ok := caps["STARTTLS"]; ok {
		t.Error("STARTTLS still advertised after upgrade")
	}

	if err := c.AuthenticatePlain(ctx, "", "user@example.com", "secret"); err != nil {
		t.Fatalf("AuthenticatePlain over TLS: %v", err)
	}
}

func TestCapabilityCommand(t *testing.T) {
	addr := startServer(t, managesieveserver.Options{
		NewSession:      newStore().NewSession,
		InsecureAuth:    true,
		IdleTimeout:     5 * time.Second,
		SieveExtensions: []string{"fileinto"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := managesieveclient.Dial(ctx, addr, managesieveclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	caps, err := c.Capability(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if caps["SIEVE"] != "fileinto" {
		t.Errorf("CAPABILITY SIEVE = %q", caps["SIEVE"])
	}
}

// errorsAs is a tiny local alias to avoid importing errors just for one call.
func errorsAs(err error, target **managesieveclient.ProtocolError) bool {
	for err != nil {
		if pe, ok := err.(*managesieveclient.ProtocolError); ok {
			*target = pe
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
