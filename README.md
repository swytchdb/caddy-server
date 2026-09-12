# Swytch Redis server for Caddy

A Caddy app that embeds the full [Swytch](https://github.com/swytchdb/swytch)
Redis server. Redis clients connect directly to its TCP or Unix socket listener.
Commands, RESP handling, transactions, scripting, JSON, streams, blocking
operations, ACLs, and pub/sub come from Swytch itself; this module adds Caddy
configuration and lifecycle management. Compatibility is that of the pinned
Swytch release, not a claim that every upstream Redis command is supported.

## Build

Requires Go 1.27 or later. From this checkout:

```sh
xcaddy build --with github.com/swytchdb/caddy-server="$PWD"
```

Once published, omit the local replacement:

```sh
xcaddy build --with github.com/swytchdb/caddy-server
```

The module depends on released Swytch v1.4.0 and Engine v1.0.1; sibling checkouts
are not required. Unlike `caddy-storage`, this app serves application data over
Redis. It does not configure Caddy's certificate storage. The current sibling
`caddy-storage` requires Engine v1.0.4, whose `NewRuntime` signature differs from
Swytch v1.4.0's dependency. Combining those versions in one binary requires an
upstream Swytch compatibility update first.

## Caddyfile

`swytch` is a global option, outside HTTP site blocks:

```caddyfile
{
    swytch {
        listen 127.0.0.1:6379
        password {env.REDIS_PASSWORD}
        max_memory 64mb
    }
}
```

For ACL authentication, replace `password` with `acl_file /etc/swytch/users.acl`.
The file must already exist and parse successfully. For standalone operation,
data is an in-memory cache; stopping the final app reference discards it.

DNS cluster configuration:

```caddyfile
{
    swytch {
        listen 127.0.0.1:6379
        acl_file /etc/swytch/users.acl
        cluster_passphrase {env.SWYTCH_PASSPHRASE}
        join redis-peers.example.net
        cluster_port 7379
        cluster_advertise 10.0.0.5:7379
    }
}
```

Peers must use the same cluster passphrase. `join` follows Swytch's DNS discovery
rules. Cluster startup uses Swytch's synchronous initialization, so joining peers
or Cloud can delay Caddy startup.

For Swytch Cloud durability, use `connection_secret {env.SWYTCH_CONNECTION_SECRET}`
instead of `cluster_passphrase` and `join`. Cloud supplies cluster identity and
membership as well as durable storage across restarts and node loss, with
zero-knowledge encryption. Ordinary peer replication alone does not provide
that durability.

## Options

JSON uses the same names under `apps.swytch`. Every Caddyfile option takes one
value; booleans use `true` or `false`, and durations use strings such as `30s`.
String fields support Caddy placeholders, including `{env.NAME}`.

| Option | Default | Purpose |
| --- | --- | --- |
| `listen` | `127.0.0.1:6379` | TCP address; mutually exclusive with `unix_socket` |
| `unix_socket` | empty | Unix socket path; must not already exist at first start |
| `unix_socket_mode` | `0700` | Octal permissions in Caddyfile; numeric mode in JSON (448 for 0700) |
| `password` | empty | Password for the default user |
| `acl_file` | empty | Existing ACL file; mutually exclusive with `password` |
| `max_memory` | `64mb` | Swytch memory limit; accepts sizes or percentages |
| `compress` | `false` | Compress values in effects |
| `cluster_passphrase` | empty | Enable peer replication |
| `connection_secret` | empty | Cloud identity and durability; excludes passphrase and join |
| `join` | empty | Discovery DNS name; requires passphrase |
| `cluster_port` | `7379` | Cluster QUIC port; independent of Redis listen port |
| `cluster_advertise` | auto | Advertised cluster host and port |
| `max_connections` | `0` | Concurrent client limit; zero is unlimited |
| `read_timeout` | `0` | Swytch read deadline; zero disables it |
| `write_timeout` | `0` | Swytch write deadline; zero disables it |
| `tcp_keepalive` | `0` | Keepalive period passed to Swytch |
| `read_buffer_size` | `0` | Read buffer bytes; zero uses Swytch's default |
| `write_buffer_size` | `0` | Write buffer bytes; zero uses Swytch's default |
| `num_acceptors` | `0` | Accept loops; zero uses Swytch's automatic selection |
| `debug_logging` | `false` | Swytch command logging |
| `tls_cert_file` | empty | PEM server certificate |
| `tls_key_file` | empty | PEM private key; required with certificate |
| `tls_ca_file` | empty | PEM CA bundle to require client certificates (mTLS) |
| `tls_min_version` | `1.2` | `1.2` or `1.3` |

TLS uses Swytch's certificate-file support. Automatic Caddy certificate issuance
and renewal are not wired to the Redis listener. Swytch's CLI entry point is not
called, so CLI signal handling, process-wide thread settings, telemetry clients,
and separate metrics/pprof HTTP listeners are not started.

Example JSON:

```json
{
  "apps": {
    "swytch": {
      "listen": "127.0.0.1:6379",
      "password": "{env.REDIS_PASSWORD}",
      "max_memory": "64mb"
    }
  }
}
```

## Lifecycle

Provisioning and `caddy validate` check options and authentication/TLS files
without starting the Redis server or contacting peers. Caddy's `Start` phase
creates the runtime and listener. An unchanged reload retains the same engine,
connections, scripts, ACL state, and subscriptions. A changed configuration or
changed ACL/TLS file content is rejected with a restart-required error, leaving
the existing server running. Settings cannot be hot-swapped because Swytch owns
process-wide Redis state. Only one server configuration per process is supported.

Final shutdown closes clients before stopping the cluster runtime. Failed starts
release their resources; failed reloads cannot release another app's reference.
An existing Unix socket path is never intentionally replaced; remove stale sockets
before starting the process. Runtime ACL changes follow Swytch semantics; saving
an ACL file changes its content and consequently requires restart on the next
Caddy reload.

## Development

```sh
go test ./...
go vet ./...
```

Tests exercise Caddyfile adaptation, validation, real RESP commands over a Unix
socket, TLS, pub/sub, blocking commands, Caddy reload and rollback,
shutdown/restart, and listener-start failure.
They do not validate a multi-node cluster or Swytch Cloud deployment.

Licensed under AGPL-3.0-or-later, matching Swytch. See [LICENSE](LICENSE).
