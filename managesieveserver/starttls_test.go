package managesieveserver_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesievemem"
	"github.com/migadu/go-managesieve/managesieveserver"
)

func serverTLSConfig(t *testing.T) *tls.Config {
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

func startTLSServer(t *testing.T, store *managesievemem.Store) string {
	t.Helper()
	return startServer(t, managesieveserver.Options{
		NewSession:           store.NewSession,
		TLSConfig:            serverTLSConfig(t),
		IdleTimeout:          5 * time.Second,
		Greeting:             `"Test" ManageSieve server ready.`,
		GreetingStartTLSHint: true,
		SieveExtensions:      []string{"fileinto"},
	})
}

func TestStartTLSFullUpgrade(t *testing.T) {
	addr := startTLSServer(t, newTestStore())
	c := dial(t, addr)

	// Pre-TLS: STARTTLS advertised, SASL empty, greeting carries the hint.
	okLine, caps := c.greet()
	if okLine != `OK (STARTTLS) "Test" ManageSieve server ready.` {
		t.Errorf("pre-TLS greeting = %q", okLine)
	}
	joined := strings.Join(caps, "\n")
	if !strings.Contains(joined, `"STARTTLS"`) || !strings.Contains(joined, `"SASL" ""`) {
		t.Errorf("pre-TLS caps missing STARTTLS/SASL \"\":\n%s", joined)
	}
	if strings.Contains(joined, `"SASL" "PLAIN"`) {
		t.Errorf("SASL PLAIN advertised before TLS:\n%s", joined)
	}

	c.send("STARTTLS")
	if line := c.readLine(); line != `OK "Begin TLS negotiation"` {
		t.Fatalf("STARTTLS ack = %q", line)
	}

	tlsConn := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	tr := bufio.NewReader(tlsConn)

	// RFC 5804 §2.2: capabilities are re-issued after the upgrade, now with
	// SASL PLAIN and without STARTTLS, and the greeting hint is gone.
	var postCaps []string
	var postOK string
	for {
		line, err := tr.ReadString('\n')
		if err != nil {
			t.Fatalf("post-TLS read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "OK") {
			postOK = line
			break
		}
		postCaps = append(postCaps, line)
	}
	if postOK != `OK "Test" ManageSieve server ready.` {
		t.Errorf("post-TLS greeting = %q", postOK)
	}
	joined = strings.Join(postCaps, "\n")
	if !strings.Contains(joined, `"SASL" "PLAIN"`) || strings.Contains(joined, `"STARTTLS"`) {
		t.Errorf("post-TLS caps wrong:\n%s", joined)
	}

	// Authentication now works over TLS.
	payload := base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00secret"))
	fmt.Fprintf(tlsConn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", payload)
	line, err := tr.ReadString('\n')
	if err != nil || strings.TrimRight(line, "\r\n") != `OK "Authenticated"` {
		t.Fatalf("post-TLS auth = %q, %v", line, err)
	}

	// A second STARTTLS is rejected.
	fmt.Fprintf(tlsConn, "STARTTLS\r\n")
	line, _ = tr.ReadString('\n')
	if strings.TrimRight(line, "\r\n") != `NO "TLS already active"` {
		t.Errorf("second STARTTLS = %q", line)
	}
}

func TestStartTLSRejectedAfterAuth(t *testing.T) {
	// InsecureAuth lets us authenticate pre-TLS to exercise the state gate.
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:   store.NewSession,
		TLSConfig:    serverTLSConfig(t),
		InsecureAuth: true,
		IdleTimeout:  5 * time.Second,
	})
	c := dial(t, addr)
	c.authenticate("user@example.com", "secret")

	c.send("STARTTLS")
	resp, _ := c.readResponse()
	if resp != `NO "STARTTLS not permitted after authentication"` {
		t.Errorf("post-auth STARTTLS = %q", resp)
	}
}

func TestStartTLSNotSupported(t *testing.T) {
	addr := startDefaultServer(t, newTestStore()) // no TLSConfig
	c := dial(t, addr)
	c.greet()
	c.send("STARTTLS")
	resp, _ := c.readResponse()
	if resp != `NO "STARTTLS not supported"` {
		t.Errorf("STARTTLS without TLS = %q", resp)
	}
}

func TestStartTLSPipelinedDataRejected(t *testing.T) {
	addr := startTLSServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	// Plaintext bytes pipelined behind STARTTLS may be a MITM
	// command-injection attempt; the server must reject and close.
	c.sendRaw("STARTTLS\r\nNOOP\r\n")
	resp, _ := c.readResponse()
	if resp != `NO "Pipelined data after STARTTLS is not allowed"` {
		t.Errorf("pipelined STARTTLS = %q", resp)
	}
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Error("connection still open after pipelined STARTTLS")
	}
}

func TestStartTLSHandshakeFailureCloses(t *testing.T) {
	addr := startTLSServer(t, newTestStore())
	c := dial(t, addr)
	c.greet()

	c.send("STARTTLS")
	if line := c.readLine(); line != `OK "Begin TLS negotiation"` {
		t.Fatalf("STARTTLS ack = %q", line)
	}
	// Send bytes that are not a valid TLS ClientHello: the server must drop
	// the connection rather than answer plaintext onto a TLS-garbled stream.
	c.sendRaw("this is not a tls handshake\r\n")
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.r.ReadByte(); err == nil {
		t.Fatal("expected connection close after failed handshake")
	}
}

func TestStartTLSStallBounded(t *testing.T) {
	store := newTestStore()
	addr := startServer(t, managesieveserver.Options{
		NewSession:      store.NewSession,
		TLSConfig:       serverTLSConfig(t),
		IdleTimeout:     30 * time.Second,
		AuthIdleTimeout: 300 * time.Millisecond,
	})
	c := dial(t, addr)
	c.greet()

	c.send("STARTTLS")
	if line := c.readLine(); line != `OK "Begin TLS negotiation"` {
		t.Fatalf("STARTTLS ack = %q", line)
	}
	// Never start the handshake: the server must give up within the auth
	// idle deadline instead of holding the connection open.
	start := time.Now()
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.r.ReadByte(); err == nil {
		t.Fatal("expected connection close after stalled handshake")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("stalled handshake held the connection for %v", elapsed)
	}
}
