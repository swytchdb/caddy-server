// Copyright 2026 Swytch Labs BV
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package caddyserver embeds Swytch's Redis server as a Caddy app.
package caddyserver

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/swytchdb/engine/beacon"
	"github.com/swytchdb/swytch/redis"
)

func init() {
	caddy.RegisterModule(App{})
	httpcaddyfile.RegisterGlobalOption("swytch", parseGlobalOption)
}

// Config exposes the embedded Redis transport and effects runtime options.
// The Redis command set is supplied directly by Swytch, without a proxy.
// Configuration changes require a process restart; unchanged reloads retain
// the engine, connections, ACL mutations, scripts, and subscriptions.
type Config struct {
	Listen            string         `json:"listen,omitempty"`
	UnixSocket        string         `json:"unix_socket,omitempty"`
	UnixSocketMode    uint32         `json:"unix_socket_mode,omitempty"`
	Password          string         `json:"password,omitempty"`
	ACLFile           string         `json:"acl_file,omitempty"`
	ReadTimeout       caddy.Duration `json:"read_timeout,omitempty"`
	WriteTimeout      caddy.Duration `json:"write_timeout,omitempty"`
	MaxConnections    int            `json:"max_connections,omitempty"`
	DebugLogging      bool           `json:"debug_logging,omitempty"`
	TCPKeepAlive      caddy.Duration `json:"tcp_keepalive,omitempty"`
	ReadBufferSize    int            `json:"read_buffer_size,omitempty"`
	WriteBufferSize   int            `json:"write_buffer_size,omitempty"`
	NumAcceptors      int            `json:"num_acceptors,omitempty"`
	TLSCertFile       string         `json:"tls_cert_file,omitempty"`
	TLSKeyFile        string         `json:"tls_key_file,omitempty"`
	TLSCAFile         string         `json:"tls_ca_file,omitempty"`
	TLSMinVersion     string         `json:"tls_min_version,omitempty"`
	MaxMemory         string         `json:"max_memory,omitempty"`
	Compress          bool           `json:"compress,omitempty"`
	ClusterPassphrase string         `json:"cluster_passphrase,omitempty"`
	ConnectionSecret  string         `json:"connection_secret,omitempty"`
	Join              string         `json:"join,omitempty"`
	ClusterPort       int            `json:"cluster_port,omitempty"`
	ClusterAdvertise  string         `json:"cluster_advertise,omitempty"`
}

// App is the singleton swytch Caddy application.
type App struct {
	Config
	claimed bool
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "swytch", New: func() caddy.Module { return new(App) }}
}

// Provision validates without opening listeners, starting workers, or joining peers.
func (a *App) Provision(_ caddy.Context) error {
	repl := caddy.NewReplacer()
	a.Listen = repl.ReplaceAll(a.Listen, "")
	a.UnixSocket = repl.ReplaceAll(a.UnixSocket, "")
	a.Password = repl.ReplaceAll(a.Password, "")
	a.ACLFile = repl.ReplaceAll(a.ACLFile, "")
	a.TLSCertFile = repl.ReplaceAll(a.TLSCertFile, "")
	a.TLSKeyFile = repl.ReplaceAll(a.TLSKeyFile, "")
	a.TLSCAFile = repl.ReplaceAll(a.TLSCAFile, "")
	a.TLSMinVersion = repl.ReplaceAll(a.TLSMinVersion, "")
	a.MaxMemory = repl.ReplaceAll(a.MaxMemory, "")
	a.ClusterPassphrase = repl.ReplaceAll(a.ClusterPassphrase, "")
	a.ConnectionSecret = repl.ReplaceAll(a.ConnectionSecret, "")
	a.Join = repl.ReplaceAll(a.Join, "")
	a.ClusterAdvertise = repl.ReplaceAll(a.ClusterAdvertise, "")
	a.defaults()
	return a.Validate()
}

func (a *App) defaults() {
	if a.Listen == "" && a.UnixSocket == "" {
		a.Listen = "127.0.0.1:6379"
	}
	if a.UnixSocketMode == 0 {
		a.UnixSocketMode = 0700
	}
	if a.MaxMemory == "" {
		a.MaxMemory = "64mb"
	}
	if a.ClusterPort == 0 {
		a.ClusterPort = 7379
	}
	if a.TLSMinVersion == "" {
		a.TLSMinVersion = "1.2"
	}
}

// Validate checks configuration and authentication/TLS files without network I/O.
func (a *App) Validate() error {
	if a.Listen != "" && a.UnixSocket != "" {
		return fmt.Errorf("swytch: listen and unix_socket are mutually exclusive")
	}
	if a.Listen != "" {
		_, port, err := net.SplitHostPort(a.Listen)
		if err != nil {
			return fmt.Errorf("swytch: invalid listen address: %w", err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("swytch: listen requires a port between 1 and 65535")
		}
	}
	if a.ClusterPort < 1 || a.ClusterPort > 65535 {
		return fmt.Errorf("swytch: cluster_port must be between 1 and 65535")
	}
	if a.UnixSocketMode > 0777 {
		return fmt.Errorf("swytch: unix_socket_mode must contain only permission bits")
	}
	if a.ReadTimeout < 0 || a.WriteTimeout < 0 || a.TCPKeepAlive < 0 || a.MaxConnections < 0 || a.ReadBufferSize < 0 || a.WriteBufferSize < 0 || a.NumAcceptors < 0 {
		return fmt.Errorf("swytch: timeouts, buffer sizes, acceptors, and connection limits must not be negative")
	}
	if a.ConnectionSecret != "" && (a.ClusterPassphrase != "" || a.Join != "") {
		return fmt.Errorf("swytch: connection_secret is mutually exclusive with cluster_passphrase and join")
	}
	if a.Join != "" && a.ClusterPassphrase == "" {
		return fmt.Errorf("swytch: join requires cluster_passphrase")
	}
	if _, _, err := beacon.ParseMemoryLimit(a.MaxMemory); err != nil {
		return fmt.Errorf("swytch: invalid max_memory: %w", err)
	}
	if a.Password != "" && a.ACLFile != "" {
		return fmt.Errorf("swytch: password and acl_file are mutually exclusive")
	}
	// Upstream silently falls back to default ACLs on file errors. Fail closed here.
	if a.ACLFile != "" {
		if err := redis.NewACLManager().LoadFromFile(a.ACLFile); err != nil {
			return fmt.Errorf("swytch: load ACL file: %w", err)
		}
	}
	if (a.TLSCertFile == "") != (a.TLSKeyFile == "") {
		return fmt.Errorf("swytch: tls_cert_file and tls_key_file are required together")
	}
	if a.TLSCAFile != "" && a.TLSCertFile == "" {
		return fmt.Errorf("swytch: tls_ca_file requires a certificate and key")
	}
	if a.TLSMinVersion != "1.2" && a.TLSMinVersion != "1.3" {
		return fmt.Errorf("swytch: tls_min_version must be 1.2 or 1.3")
	}
	if a.TLSCertFile != "" {
		if _, err := tls.LoadX509KeyPair(a.TLSCertFile, a.TLSKeyFile); err != nil {
			return fmt.Errorf("swytch: load TLS certificate: %w", err)
		}
	}
	if a.TLSCAFile != "" {
		pem, err := os.ReadFile(a.TLSCAFile)
		if err != nil {
			return fmt.Errorf("swytch: read TLS CA: %w", err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return fmt.Errorf("swytch: invalid TLS CA certificate")
		}
	}
	return nil
}

func (a *App) serverConfig() redis.ServerConfig {
	return redis.ServerConfig{
		Address: a.Listen, UnixSocket: a.UnixSocket, UnixSocketMode: os.FileMode(a.UnixSocketMode),
		Password: a.Password, ACLFile: a.ACLFile, ReadTimeout: time.Duration(a.ReadTimeout),
		WriteTimeout: time.Duration(a.WriteTimeout), MaxConnections: a.MaxConnections,
		DebugLogging: a.DebugLogging, TCPKeepAlive: time.Duration(a.TCPKeepAlive),
		ReadBufferSize: a.ReadBufferSize, WriteBufferSize: a.WriteBufferSize, NumAcceptors: a.NumAcceptors,
		TLSCertFile: a.TLSCertFile, TLSKeyFile: a.TLSKeyFile, TLSCAFile: a.TLSCAFile, TLSMinVersion: a.TLSMinVersion,
	}
}

var runtimeState struct {
	sync.Mutex
	server      *redis.Server
	fingerprint [32]byte
	refs        int
}

// Start claims the running server or starts it for the first config.
func (a *App) Start() error {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if a.claimed {
		return nil
	}
	a.defaults()
	if err := a.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(a.Config)
	if err != nil {
		return err
	}
	// Hash secrets rather than retaining a second plaintext configuration.
	hash := sha256.New()
	hash.Write(encoded)
	// Changes to files at the same paths also require a restart.
	for _, path := range []string{a.ACLFile, a.TLSCertFile, a.TLSKeyFile, a.TLSCAFile} {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("swytch: read configuration file: %w", err)
		}
		digest := sha256.Sum256(data)
		hash.Write(digest[:])
	}
	var fingerprint [32]byte
	copy(fingerprint[:], hash.Sum(nil))
	if runtimeState.server != nil {
		if runtimeState.fingerprint != fingerprint {
			return fmt.Errorf("swytch: configuration cannot change without restarting the process")
		}
		runtimeState.refs++
		a.claimed = true
		return nil
	}
	// Swytch removes any existing Unix socket path; do not let it unlink a
	// live listener or an unrelated file. Stale sockets must be removed by the operator.
	if a.UnixSocket != "" {
		if _, err := os.Lstat(a.UnixSocket); err == nil {
			return fmt.Errorf("swytch: unix_socket path already exists")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	limit, percent, _ := beacon.ParseMemoryLimit(a.MaxMemory)
	cfg := &redis.EffectsConfig{MemoryLimit: limit, MemoryLimitPercent: percent,
		ClusterPassphrase: a.ClusterPassphrase, Cloud: a.ConnectionSecret,
		JoinAddr: a.Join, ClusterPort: a.ClusterPort, AdvertiseAddr: a.ClusterAdvertise, Compress: a.Compress}
	server, err := redis.NewServer(a.serverConfig())
	if err != nil {
		return fmt.Errorf("swytch: create server: %w", err)
	}
	if err := redis.InitializeEffects(cfg); err != nil {
		server.Handler().Close()
		return fmt.Errorf("swytch: initialize effects: %w", err)
	}
	if err := redis.InitializeCluster(cfg, server.Handler()); err != nil {
		server.Handler().Close()
		redis.StopCluster()
		return fmt.Errorf("swytch: initialize cluster: %w", err)
	}
	if err := server.Start(); err != nil {
		_ = server.Stop()
		redis.StopCluster()
		return fmt.Errorf("swytch: start server: %w", err)
	}
	runtimeState.server = server
	runtimeState.fingerprint = fingerprint
	runtimeState.refs = 1
	a.claimed = true
	return nil
}

// Stop releases only this app's reference, including during reload rollback.
func (a *App) Stop() error {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if !a.claimed {
		return nil
	}
	a.claimed = false
	runtimeState.refs--
	if runtimeState.refs > 0 {
		return nil
	}
	err := runtimeState.server.Stop()
	redis.StopCluster()
	runtimeState.server = nil
	runtimeState.fingerprint = [32]byte{}
	return err
}

// Cleanup also handles a configuration abandoned after Start.
func (a *App) Cleanup() error { return a.Stop() }

func parseGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	if existing != nil {
		return nil, d.Err("swytch may only be configured once")
	}
	a := new(App)
	if err := a.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	return httpcaddyfile.App{Name: "swytch", Value: caddyconfig.JSON(a, nil)}, nil
}

// UnmarshalCaddyfile parses a global swytch block. Names match the JSON fields.
func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected swytch block")
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	seen := make(map[string]bool)
	for d.NextBlock(0) {
		key := d.Val()
		if seen[key] {
			return d.Errf("duplicate swytch option %q", key)
		}
		seen[key] = true
		args := d.RemainingArgs()
		if len(args) != 1 {
			return d.ArgErr()
		}
		value := args[0]
		var err error
		switch key {
		case "listen":
			a.Listen = value
		case "unix_socket":
			a.UnixSocket = value
		case "unix_socket_mode":
			var n uint64
			n, err = strconv.ParseUint(value, 8, 32)
			a.UnixSocketMode = uint32(n)
		case "password":
			a.Password = value
		case "acl_file":
			a.ACLFile = value
		case "read_timeout":
			var duration time.Duration
			duration, err = caddy.ParseDuration(value)
			a.ReadTimeout = caddy.Duration(duration)
		case "write_timeout":
			var duration time.Duration
			duration, err = caddy.ParseDuration(value)
			a.WriteTimeout = caddy.Duration(duration)
		case "max_connections":
			a.MaxConnections, err = strconv.Atoi(value)
		case "debug_logging":
			a.DebugLogging, err = strconv.ParseBool(value)
		case "tcp_keepalive":
			var duration time.Duration
			duration, err = caddy.ParseDuration(value)
			a.TCPKeepAlive = caddy.Duration(duration)
		case "read_buffer_size":
			a.ReadBufferSize, err = strconv.Atoi(value)
		case "write_buffer_size":
			a.WriteBufferSize, err = strconv.Atoi(value)
		case "num_acceptors":
			a.NumAcceptors, err = strconv.Atoi(value)
		case "tls_cert_file":
			a.TLSCertFile = value
		case "tls_key_file":
			a.TLSKeyFile = value
		case "tls_ca_file":
			a.TLSCAFile = value
		case "tls_min_version":
			a.TLSMinVersion = value
		case "max_memory":
			a.MaxMemory = value
		case "compress":
			a.Compress, err = strconv.ParseBool(value)
		case "cluster_passphrase":
			a.ClusterPassphrase = value
		case "connection_secret":
			a.ConnectionSecret = value
		case "join":
			a.Join = value
		case "cluster_port":
			a.ClusterPort, err = strconv.Atoi(value)
		case "cluster_advertise":
			a.ClusterAdvertise = value
		default:
			return d.Errf("unknown swytch option %q", key)
		}
		if err != nil {
			return d.Errf("invalid %s: %v", key, err)
		}
		if d.NextBlock(1) {
			return d.Errf("%s does not accept a block", key)
		}
	}
	return nil
}

var (
	_ caddy.Module          = (*App)(nil)
	_ caddy.App             = (*App)(nil)
	_ caddy.Provisioner     = (*App)(nil)
	_ caddy.Validator       = (*App)(nil)
	_ caddy.CleanerUpper    = (*App)(nil)
	_ caddyfile.Unmarshaler = (*App)(nil)
)
