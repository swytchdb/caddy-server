// Copyright 2026 Swytch Labs BV
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package caddyswytch embeds Swytch's Redis server as a Caddy app.
package caddyswytch

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

// Config configures the Redis listener, authentication, TLS, memory use, and
// optional Swytch peer replication or Cloud storage. Its fields are embedded
// directly in the swytch app's JSON object.
type Config struct {
	// TCP address for Redis clients, in host:port form. The port must be
	// between 1 and 65535. Defaults to "127.0.0.1:6379" when neither listen
	// nor unix_socket is set. Mutually exclusive with unix_socket.
	Listen string `json:"listen,omitempty"`

	// Unix socket path for Redis clients, instead of a TCP listener. The path
	// must not already exist at first start; remove stale sockets beforehand.
	// Mutually exclusive with listen. Disabled by default.
	UnixSocket string `json:"unix_socket,omitempty"`

	// Permission bits for the Unix socket. Zero or omitted uses 0700.
	// Use octal in the Caddyfile (0700) and a decimal JSON number (448).
	// Only permission bits through 0777 (511 in JSON) are accepted.
	UnixSocketMode uint32 `json:"unix_socket_mode,omitempty"`

	// Password required by the default Redis user. Mutually exclusive with
	// acl_file. When both are empty, clients can connect without authentication.
	// Supports placeholders such as {env.REDIS_PASSWORD}.
	Password string `json:"password,omitempty"`

	// Path to an existing Redis ACL file defining users, passwords, and
	// permissions. The file must load successfully during validation.
	// Mutually exclusive with password. Empty disables ACL file loading.
	ACLFile string `json:"acl_file,omitempty"`

	// Timeout for reading Redis commands, for example "30s". Zero or omitted
	// disables the read timeout. Must not be negative.
	ReadTimeout caddy.Duration `json:"read_timeout,omitempty"`

	// Timeout for writing Redis responses, for example "30s". Zero or omitted
	// disables the write timeout. Must not be negative.
	WriteTimeout caddy.Duration `json:"write_timeout,omitempty"`

	// Maximum number of concurrent Redis client connections. Zero or omitted
	// allows unlimited connections. Must not be negative.
	MaxConnections int `json:"max_connections,omitempty"`

	// Enable Swytch's debug-level Redis command logging. Defaults to false.
	DebugLogging bool `json:"debug_logging,omitempty"`

	// TCP keepalive period passed to Swytch, for example "30s". Zero or omitted
	// leaves the listener's keepalive defaults unchanged. Must not be negative.
	TCPKeepAlive caddy.Duration `json:"tcp_keepalive,omitempty"`

	// Read buffer size per Redis client connection, in bytes. Zero or omitted
	// uses Swytch's default. Must not be negative.
	ReadBufferSize int `json:"read_buffer_size,omitempty"`

	// Write buffer size per Redis client connection, in bytes. Zero or omitted
	// uses Swytch's default. Must not be negative.
	WriteBufferSize int `json:"write_buffer_size,omitempty"`

	// Number of parallel TCP accept loops. Zero or omitted uses the CPU count
	// on platforms supporting SO_REUSEPORT; other platforms use one acceptor.
	// Does not apply to Unix sockets. Must not be negative.
	NumAcceptors int `json:"num_acceptors,omitempty"`

	// Path to a PEM server certificate enabling TLS for Redis clients.
	// Requires tls_key_file. Empty disables TLS. Certificates are loaded from
	// files; Caddy's automatic certificate issuance and renewal are not used.
	TLSCertFile string `json:"tls_cert_file,omitempty"`

	// Path to the PEM private key matching tls_cert_file. The certificate and
	// key must be configured together and load successfully during validation.
	TLSKeyFile string `json:"tls_key_file,omitempty"`

	// Path to a PEM CA bundle used to require and verify Redis client
	// certificates (mutual TLS). Requires tls_cert_file and tls_key_file.
	// Empty disables client certificate authentication.
	TLSCAFile string `json:"tls_ca_file,omitempty"`

	// Minimum TLS version for Redis clients: "1.2" or "1.3". Defaults to "1.2".
	// Only takes effect when tls_cert_file and tls_key_file enable TLS.
	TLSMinVersion string `json:"tls_min_version,omitempty"`

	// Swytch memory limit, as a byte count, a size such as "64mb" or "1gb",
	// or a whole-number percentage such as "50%" (1 through 100).
	// Size suffixes are case-insensitive and use powers of 1024.
	// Defaults to "64mb". This configures Swytch, not a process-wide Caddy limit.
	MaxMemory string `json:"max_memory,omitempty"`

	// Store values compressed in Swytch's effects engine, decompressing them
	// on read to trade CPU work for lower memory use. Defaults to false.
	// Peers with different compression settings can interoperate.
	Compress bool `json:"compress,omitempty"`

	// Shared passphrase enabling peer replication and deriving the cluster's
	// mutual TLS identity. Peers must use the same passphrase. Use join for DNS
	// peer discovery. Mutually exclusive with connection_secret.
	// Empty, with no connection_secret, selects standalone operation.
	ClusterPassphrase string `json:"cluster_passphrase,omitempty"`

	// Swytch Cloud connection secret providing cluster identity, membership,
	// and durable storage across restarts and node loss with zero-knowledge
	// encryption. Mutually exclusive with cluster_passphrase and join.
	// Empty disables Cloud. Supports {env.SWYTCH_CONNECTION_SECRET}.
	ConnectionSecret string `json:"connection_secret,omitempty"`

	// DNS name to resolve for peer discovery using Swytch's discovery rules.
	// Requires cluster_passphrase and is mutually exclusive with
	// connection_secret. Empty disables DNS peer discovery.
	Join string `json:"join,omitempty"`

	// QUIC port for cluster traffic when peer replication or Cloud is enabled.
	// Defaults to 7379, independently of the Redis client listen port.
	// Must be between 1 and 65535.
	ClusterPort int `json:"cluster_port,omitempty"`

	// Cluster host:port advertised to peers, for example "10.0.0.5:7379".
	// Empty lets Swytch detect the address automatically. Only used when
	// peer replication or Cloud is enabled.
	ClusterAdvertise string `json:"cluster_advertise,omitempty"`
}

// App runs Swytch's Redis-compatible server inside Caddy. Redis clients connect
// directly to a TCP or Unix socket listener. Swytch supplies command execution,
// transactions, scripting, JSON, streams, ACLs, and pub/sub; this app configures
// the server and manages its lifecycle. Command compatibility follows the
// Swytch release included in the build.
//
// Configure the module at apps.swytch in JSON, or with the swytch global option
// outside HTTP site blocks in a Caddyfile:
//
//	{
//		swytch {
//			listen 127.0.0.1:6379
//			password {env.REDIS_PASSWORD}
//			max_memory 64mb
//		}
//	}
//
// Caddyfile option names match the JSON fields. Each option takes one value;
// booleans use true or false, and durations accept strings such as "30s".
// String fields support Caddy placeholders, including {env.NAME}, which are
// expanded during provisioning.
//
// By default, Swytch runs as an in-memory standalone cache whose data is lost
// on shutdown. Set cluster_passphrase and join for DNS-discovered peer
// replication, or connection_secret for Swytch Cloud membership and durable,
// zero-knowledge encrypted storage. Peer replication alone does not provide
// Cloud's durability across restarts and node loss. Joining peers or Cloud can
// delay Caddy startup.
//
// Only one Swytch server configuration is supported per Caddy process.
// Unchanged reloads preserve data, client connections, runtime ACL changes,
// scripts, and subscriptions. Changes to options or ACL/TLS file contents
// require a process restart; reloads with such changes are rejected while the
// existing server keeps running. Validation checks configuration and files
// without opening listeners or contacting peers.
type App struct {
	Config
	claimed bool
}

// CaddyModule returns the module information for the swytch app.
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

// UnmarshalCaddyfile parses the swytch global option. Subdirective names match
// the JSON fields in Config, and each takes exactly one value. Duplicate
// options and nested blocks are rejected. See App for a Caddyfile example.
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
