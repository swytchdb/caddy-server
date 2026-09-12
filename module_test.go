// Copyright 2026 Swytch Labs BV
// SPDX-License-Identifier: AGPL-3.0-or-later

package caddyserver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func provision(t *testing.T, a *App) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := a.Provision(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCaddyfile(t *testing.T) {
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	config, warnings, err := adapter.Adapt([]byte(`{
 swytch {
  listen 127.0.0.1:6380
  password {env.REDIS_PASSWORD}
  max_memory 128mb
  read_timeout 30s
  compress true
  cluster_port 7379
 }
}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = warnings // Formatting warnings do not affect adaptation.
	var decoded struct{ Apps map[string]Config }
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	c := decoded.Apps["swytch"]
	if c.Listen != "127.0.0.1:6380" || !c.Compress || c.ReadTimeout != caddy.Duration(30*time.Second) || c.Password != "{env.REDIS_PASSWORD}" {
		t.Fatalf("unexpected adapted config: %s", config)
	}
	for _, body := range []string{
		"swytch extra", "swytch {\n unknown value\n}", "swytch {\n listen a b\n}",
		"swytch {\n compress maybe\n}", "swytch {\n listen a\n listen b\n}",
		"swytch {\n listen a {\n nested b\n }\n}",
	} {
		t.Run(body, func(t *testing.T) {
			if err := new(App).UnmarshalCaddyfile(caddyfile.NewTestDispenser(body)); err == nil {
				t.Fatal("expected parse failure")
			}
		})
	}
}

func TestValidation(t *testing.T) {
	for _, cfg := range []Config{
		{Listen: "missing-port"}, {Listen: "localhost:0"}, {ClusterPort: -1},
		{Join: "peers.example"}, {ConnectionSecret: "secret", ClusterPassphrase: "pass"},
		{MaxMemory: "nonsense"}, {ReadTimeout: -1}, {MaxConnections: -1},
		{TLSKeyFile: "key"}, {TLSCAFile: "ca"}, {TLSMinVersion: "1.0"},
		{ACLFile: filepath.Join(t.TempDir(), "missing")}, {UnixSocketMode: 01000},
		{Listen: "localhost:6379", UnixSocket: "/tmp/conflicting-socket"},
	} {
		a := &App{Config: cfg}
		a.defaults()
		if err := a.Validate(); err == nil {
			t.Fatalf("expected validation failure for %+v", cfg)
		}
		if err := a.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SWYTCH_TEST_PASSWORD", "test-secret")
	a := &App{Config: Config{Password: "{env.SWYTCH_TEST_PASSWORD}"}}
	provision(t, a)
	if a.Password != "test-secret" || a.Listen != "127.0.0.1:6379" {
		t.Fatal("defaults or replacement failed")
	}
	if runtimeState.server != nil {
		t.Fatal("Provision started a server")
	}
}

type wireClient struct {
	net.Conn
	reader *bufio.Reader
}

func connect(t *testing.T, path string) *wireClient {
	t.Helper()
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &wireClient{c, bufio.NewReader(c)}
}
func (c *wireClient) send(t *testing.T, args ...string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var request strings.Builder
	fmt.Fprintf(&request, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&request, "$%d\r\n%s\r\n", len(arg), arg)
	}
	if _, err := c.Write([]byte(request.String())); err != nil {
		t.Fatal(err)
	}
}
func (c *wireClient) receive(t *testing.T, want string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	for n := 0; n < len(got); {
		count, err := c.reader.Read(got[n:])
		n += count
		if err != nil {
			t.Fatalf("read %q: %v", got[:n], err)
		}
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
func (c *wireClient) command(t *testing.T, want string, args ...string) {
	t.Helper()
	c.send(t, args...)
	c.receive(t, want)
}

func TestCaddyLifecycleAndRedis(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redis.sock")
	cfg := Config{UnixSocket: path, Password: "secret", MaxMemory: "16mb", NumAcceptors: 1}
	load := func(cfg Config) error {
		raw, err := json.Marshal(map[string]any{"admin": map[string]any{"disabled": true}, "apps": map[string]any{"swytch": cfg}})
		if err != nil {
			return err
		}
		return caddy.Load(raw, true)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	c := connect(t, path)
	c.command(t, "-NOAUTH Authentication required.\r\n", "GET", "key")
	c.command(t, "+OK\r\n", "AUTH", "secret")
	c.command(t, "+PONG\r\n", "PING")
	c.command(t, "+OK\r\n", "SET", "key", "value")
	c.command(t, ":1\r\n", "HSET", "hash", "field", "value")
	c.command(t, "$5\r\nvalue\r\n", "HGET", "hash", "field")
	c.command(t, ":1\r\n", "LPUSH", "list", "item")
	c.command(t, "$4\r\nitem\r\n", "RPOP", "list")
	c.command(t, ":1\r\n", "SADD", "set", "member")
	c.command(t, ":1\r\n", "ZADD", "sorted", "1", "member")
	c.command(t, "+OK\r\n", "JSON.SET", "json", "$", `{"enabled":true}`)
	c.command(t, ":42\r\n", "EVAL", "return 42", "0")
	c.command(t, "+OK\r\n", "MULTI")
	c.command(t, "+QUEUED\r\n", "SET", "tx", "committed")
	c.command(t, "*1\r\n+OK\r\n", "EXEC")
	subscriber := connect(t, path)
	subscriber.command(t, "+OK\r\n", "AUTH", "secret")
	subscriber.command(t, "*3\r\n$9\r\nsubscribe\r\n$6\r\nevents\r\n:1\r\n", "SUBSCRIBE", "events")
	original := runtimeState.server
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	if runtimeState.server != original || runtimeState.refs != 1 {
		t.Fatal("reload replaced runtime or leaked reference")
	}
	c.command(t, "$5\r\nvalue\r\n", "GET", "key")
	c.command(t, ":1\r\n", "PUBLISH", "events", "hello")
	subscriber.receive(t, "*3\r\n$7\r\nmessage\r\n$6\r\nevents\r\n$5\r\nhello\r\n")
	blocker := connect(t, path)
	blocker.command(t, "+OK\r\n", "AUTH", "secret")
	blocker.send(t, "BRPOP", "queue", "2")
	c.command(t, ":1\r\n", "LPUSH", "queue", "item")
	blocker.receive(t, "*2\r\n$5\r\nqueue\r\n$4\r\nitem\r\n")
	changed := cfg
	changed.Password = "different"
	if err := load(changed); err == nil || !strings.Contains(err.Error(), "restarting") {
		t.Fatalf("expected restart error, got %v", err)
	}
	c.command(t, "$9\r\ncommitted\r\n", "GET", "tx")
	if runtimeState.refs != 1 {
		t.Fatal("failed reload damaged ownership")
	}
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	if runtimeState.server != nil {
		t.Fatal("runtime leaked")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket was not removed: %v", err)
	}
	// A fresh start after teardown must not retain broken global state.
	if err := load(cfg); err != nil {
		t.Fatal(err)
	}
	connect(t, path).command(t, "+OK\r\n", "AUTH", "secret")
}

func TestStartFailureAndUnclaimedCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &App{Config: Config{UnixSocket: path}}
	provision(t, a)
	if err := a.Start(); err == nil {
		t.Fatal("expected occupied path failure")
	}
	if err := a.Cleanup(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "keep" {
		t.Fatal("existing file was modified")
	}
	// A TCP bind failure occurs after engine initialization and must unwind it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	failed := &App{Config: Config{Listen: listener.Addr().String(), NumAcceptors: 1, MaxMemory: "16mb"}}
	provision(t, failed)
	if err := failed.Start(); err == nil {
		failed.Stop()
		t.Fatal("expected bind failure")
	}
	if runtimeState.server != nil {
		t.Fatal("failed start leaked runtime")
	}
	good := &App{Config: Config{UnixSocket: filepath.Join(t.TempDir(), "redis.sock"), MaxMemory: "16mb"}}
	provision(t, good)
	if err := good.Start(); err != nil {
		t.Fatal(err)
	}
	defer good.Stop()
	if err := failed.Cleanup(); err != nil {
		t.Fatal(err)
	}
	connect(t, good.UnixSocket).command(t, "+PONG\r\n", "PING")
}

func TestTLSAndChangedFiles(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	a := &App{Config: Config{UnixSocket: filepath.Join(dir, "redis.sock"), TLSCertFile: certPath, TLSKeyFile: keyPath, TLSMinVersion: "1.3", MaxMemory: "16mb"}}
	provision(t, a)
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "unix", a.UnixSocket, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &wireClient{conn, bufio.NewReader(conn)}
	client.command(t, "+PONG\r\n", "PING")
	// PEM remains valid, but changed bytes must not silently retain old TLS material.
	if err := os.WriteFile(certPath, append(certPEM, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	replacement := &App{Config: a.Config}
	provision(t, replacement)
	if err := replacement.Start(); err == nil || !strings.Contains(err.Error(), "restarting") {
		t.Fatalf("expected restart error: %v", err)
	}
	if err := replacement.Cleanup(); err != nil {
		t.Fatal(err)
	}
	client.command(t, "+PONG\r\n", "PING")
}
