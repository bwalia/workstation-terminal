# sshweb

A single-binary SSH-over-Web gateway for macOS. Run it on a Mac, open a browser, sign in by
proving possession of an authorised SSH key, and get:

- a **real interactive terminal on that Mac** (zsh/bash in a PTY: colours, vim, Ctrl+C/D/Z, resize), and
- **SSH sessions to administrator-approved remote hosts**, with strict host-key verification.

Written in Rust (Tokio, Axum, xterm.js). The web UI is embedded in the executable, so there's no
Node.js, Python, Docker, database or separate web server at runtime.

```
browser (xterm.js) ──HTTPS/WSS or loopback HTTP/WS──▶ sshweb ──PTY──▶ /bin/zsh   (local mode)
                                                         └──PTY──▶ /usr/bin/ssh ──▶ remote host (remote mode)
```

## Contents

- [Quick start](#quick-start)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Install](#install)
- [Authentication](#authentication)
- [Key management](#key-management)
- [Local terminal](#local-terminal)
- [Tabs and resuming](#tabs-and-resuming)
- [Remote SSH hosts](#remote-ssh-hosts)
- [Enabling remote (network) access and HTTPS](#enabling-remote-network-access-and-https)
- [Configuration](#configuration)
- [CLI reference](#cli-reference)
- [Operations: health, metrics, logs, shutdown](#operations)
- [Architecture](#architecture)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security limitations](#security-limitations)

## Quick start

```sh
cargo build --release
./target/release/sshweb config init                       # creates ~/.sshweb/
./target/release/sshweb keys add --user "$(id -un | tr A-Z a-z)" --access local ~/.ssh/id_ed25519.pub
./target/release/sshweb serve                             # http://127.0.0.1:7681/
```

Open <http://127.0.0.1:7681/>, enter your user name, pick your key file, type its passphrase (if it has one) and
press **Sign in**. The page opens the key and signs the one-time challenge in the browser; nothing but the
signature is sent. Then pick **This Mac** and press **Open in new tab**.

Prefer your own tools? Open **Sign in with a command instead**, press **Get challenge** and run the command the
page shows in any terminal on your Mac:

```sh
printf '%s' 'sshweb-auth-v1 origin=http://127.0.0.1:7681 user=alice challenge=… nonce=… expires=…' \
  | ssh-keygen -Y sign -n sshweb-auth -f ~/.ssh/id_ed25519 | pbcopy
```

Paste the signature into the page and press **Sign in**.

No key yet? Create one with `ssh-keygen -t ed25519`.

## Prerequisites

| Need | Why |
|---|---|
| macOS 12+ (Apple Silicon or Intel) | Target platform. Linux probably works but isn't tested. |
| Rust stable ≥ 1.88 (`rustup`) | Build only. |
| OpenSSH `ssh-keygen` 8.1+ on the **user's** machine | Signs login challenges (`ssh-keygen -Y sign`). Ships with macOS. |
| OpenSSH `ssh`, `ssh-keyscan` on the gateway | Remote mode only (`/usr/bin/ssh`, ships with macOS). |

**Runtime dependencies** (the binary isn't fully self-contained): the system OpenSSH client in
remote mode, the configured shells (`/bin/zsh` etc.), and the files you configure (config,
`authorized_keys`, `known_hosts`, TLS certificate and key). The web assets (HTML/CSS/JS,
xterm.js 5.5.0) are compiled into the executable.

## Build

```sh
cargo build                      # development build: target/debug/sshweb
cargo build --release            # optimised build for this Mac's architecture: target/release/sshweb
make check                       # fmt --check, clippy -D warnings, tests, release build
scripts/build-universal.sh       # universal arm64 + x86_64 binary: dist/sshweb
```

For an Intel-only binary: `rustup target add x86_64-apple-darwin && cargo build --release --target x86_64-apple-darwin`.
Node.js is **not** needed. xterm.js is vendored in `web/vendor/` (MIT, see `web/vendor/LICENSE.xterm`).

## Install

Run everything as your ordinary user. `sshweb serve` refuses to start as root, because every
terminal it opens runs as the account that runs it.

```sh
cargo build --release
scripts/install.sh                     # → ~/.local/bin/sshweb and ~/.sshweb/ (config, empty key files)
INSTALL_LAUNCHD=1 scripts/install.sh   # also start at login as a launchd user agent
```

To install manually, copy `target/release/sshweb` anywhere on your `PATH` and run `sshweb config init`.

Files (default `~/.sshweb`, override with `SSHWEB_HOME` or `--config`):

| File | Purpose | Mode |
|---|---|---|
| `config.yaml` | Configuration (see `config.example.yaml`) | 0600 |
| `authorized_keys` | Public keys allowed to log in | 0600, not group/world-writable |
| `known_hosts` | Trusted host keys for remote profiles | 0600 |
| `audit.log` | JSON-lines audit trail | 0600 |
| `run/admin.sock` | Local admin socket for `sessions` / `health` | 0600, dir 0700 |

Launch and health check:

```sh
sshweb serve                     # foreground; Ctrl+C or SIGTERM to stop gracefully
sshweb health                    # exit 0 when ready (uses the admin socket)
curl -s http://127.0.0.1:7681/healthz
```

With launchd: `launchctl kickstart -k gui/$(id -u)/com.sshweb.gateway` restarts the agent,
`launchctl bootout gui/$(id -u)/com.sshweb.gateway` stops it, and logs go to `~/Library/Logs/sshweb.log`.

## Authentication

Browsers can't read `~/.ssh` or talk to ssh-agent, and a public key proves nothing. So sshweb
uses an **SSH signature challenge-response** in the standard OpenSSH `SSHSIG` format:

1. The browser asks for a challenge for a user name. The server creates a one-line message
   containing the **origin**, **user**, a random 256-bit **nonce**, a **challenge id** and an **expiry**
   (default 120 s). It sets an HttpOnly cookie that binds the challenge to this browser.
2. The user signs the message locally with `ssh-keygen -Y sign -n sshweb-auth`. This works with plain
   key files, passphrase-protected keys (the prompt is local) and keys in ssh-agent (pass the `.pub`
   file to `-f`). `sshweb sign -f KEY 'MESSAGE'` is an equivalent helper.
3. The server rebuilds the message from its own state, checks the `sshweb-auth` namespace, checks
   the signing key is authorised for *that* user, and verifies the signature. The challenge is
   deleted on the first attempt, so a signature can't be replayed, and the binding cookie must match.
4. On success the browser gets a random 256-bit session cookie (HttpOnly, SameSite=Strict, and
   `Secure` + `__Host-` prefix under TLS). Only its SHA-256 hash is stored server-side. Logins expire
   after `session_ttl_secs` (8 h) or `session_idle_timeout_secs` (30 min) without activity.

**Check the origin in the message before signing.** A signature is only useful for that challenge,
but a phishing page could relay a real challenge to you. See [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)
and the [threat model](docs/SECURITY.md).

The same exchange is also available over the WebSocket (`auth_request` / `auth_response`, see
[docs/PROTOCOL.md](docs/PROTOCOL.md)) for non-browser clients.

## Key management

`authorized_keys` is administrator-managed. It holds public keys only, one per line, with the
gateway identity and the access it grants:

```
user="alice",access="local,remote:web1" ssh-ed25519 AAAAC3Nza... alice@laptop
user="bob",access="remote:*" ssh-rsa AAAAB3Nza... bob@desktop
```

- `access`: `local` (terminal on this Mac), `remote:<profile-id>`, `remote:*` (all profiles).
- A user can have several keys, and each key line belongs to exactly one user.
- Accepted keys: Ed25519, ECDSA (P-256/384/521), and RSA ≥ 2048 bits (`auth.min_rsa_bits`).
- A malformed line makes the whole file invalid. **All logins are then refused** (fail closed)
  until it's fixed; `sshweb config validate` and `sshweb keys list` show the error.

```sh
sshweb keys fingerprint ~/.ssh/id_ed25519.pub              # SHA256:… (same as ssh-keygen -lf)
sshweb keys add --user alice --access local ~/.ssh/id_ed25519.pub
sshweb keys list
sshweb keys revoke SHA256:p5it6OAPZS7qL1xZcTyDn2X8b1FpzIIfAn3KFsKCrPE
```

Revocation and changes take effect without restarting or rebuilding. The file is re-read when it
changes. Logins made with a removed key are revoked within ~5 s and their terminals are closed. If a
key's `access` is narrowed, sessions it no longer covers are closed too. Key additions and revocations
are recorded in the audit log.

Browser users can't add or change keys. The server has no key-upload endpoint and never writes
`authorized_keys`. Only someone who can edit that file (the administrator account) can authorise keys.

## Local terminal

With `local.enabled: true` and a key with `local` access, **This Mac** starts the configured shell
(`$SHELL` if it's in `local.allowed_shells`, otherwise the first allowed shell) as a login shell in a
real PTY, running as the user who runs sshweb. Users can choose any shell listed in both
`local.allowed_shells` and `/etc/shells`.

- Output is streamed as raw bytes, so colours, cursor movement, alternate screen (vim, less, top) and
  mouse modes work. Keyboard input, including Ctrl+C/D/Z, goes to the PTY, and resizes are applied with `TIOCSWINSZ`.
- **Copying:** drag to select. While a program uses the mouse (Claude Code, vim, less, tmux), hold ⌥ Option
  (Shift on Windows and Linux) while you drag. ⌘C or a right-click on the selection copies it.
- When the shell exits the session closes and its exit code is shown. On close, disconnect timeout,
  idle timeout or shutdown, the whole process group gets SIGHUP and then SIGKILL.
- **Reconnects:** if the network drops, the page reconnects automatically with backoff and replays
  recent *output* (bounded scrollback). Input typed while disconnected is discarded and never replayed.
- **Limits:** `sessions.max_total`, `sessions.max_per_user`, `sessions.idle_timeout_secs` (no keyboard input).
- **Tabs:** each tab is its own terminal session. Open one with **+** or **Open in new tab**. Rename it by
  double-clicking the tab or title, or with **Rename**. Close it with **×**, which ends its session. The tab list
  (target, name, session) is saved on the server per user (`<state_dir>/workspaces/<user>.json`, mode 0600).
  Signing in again in any browser restores it; see [Tabs and resuming](#tabs-and-resuming).

Every gateway identity gets a shell as the **same macOS user**: the one running sshweb, or the account
named in `local.run_as`. With `run_as`, sshweb (unprivileged, under its own account) starts shells as that
account through a narrow sudo rule, so what runs in a terminal can't read the gateway's config, secrets,
TLS key or logs: see [Shells as another account](docs/OPSAPI.md#shells-as-another-account). Signals to
those shells also go through that rule. On macOS, `local.sandbox_profile` also keeps them to their folder and the
web: see [Shells locked to their folder](docs/OPSAPI.md#shells-locked-to-their-folder). Each local shell gets
`SSHWEB_USER` (and, for keys issued in OpsAPI, `SSHWEB_USER_EMAIL` and `SSHWEB_USER_NAME`), so the shared
account's start-up files can credit the person, e.g. in git commits: see
[Crediting each person](docs/OPSAPI.md#crediting-each-person).

## OpsAPI task links

OpsAPI can open a task straight into a tab here: a folder under `local.allowed_roots`, an agent from
`opsapi.agents` started with the task as its first message, and a webhook back to OpsAPI when the session
starts and ends. Links are signed, expire, work once and never sign anyone in. Task tabs stay alive while
the agent works (output counts as activity). Setup, the contract and running task terminals under a
separate macOS account: [docs/OPSAPI.md](docs/OPSAPI.md).
An optional work log (off by default) sends OpsAPI each tab's record, Claude Code's prompts and usage,
and a recording of what the screen showed (never keystrokes): [docs/OPSAPI.md](docs/OPSAPI.md#work-log).

## Tabs and resuming

Closing the browser doesn't end your shells. A terminal whose browser went away keeps running,
*detached*, for `sessions.detach_grace_secs` (default 30 min), unless it hits `sessions.idle_timeout_secs`
(1 h without keyboard input) first. When you come back:

1. **If your login cookie is still valid** (8 h absolute, 30 min idle), the page opens straight away.
2. **Otherwise you sign in again with your SSH key**, using the same challenge you always sign. There is no
   separate "resume token", and a detached shell can't be reached without a fresh key-based login.
3. Your saved tabs are restored. Tabs whose shell is still running are re-attached and show recent output.
   Tabs whose shell ended (exit, timeout, restart) start a **new** shell for the same target and name when
   you open them, marked "[previous session had ended — started a new one]".

Rules that keep resuming safe:

- Only the **same user** can re-attach a session, and only with a currently authorised key. On re-attach,
  the session is re-bound to that new login and key.
- **Revoking a key** (`sshweb keys revoke`) ends every session started or resumed with it within about 5 s,
  including detached ones whose browser login has already expired. Narrowing a key's `access` ends the
  sessions it no longer covers.
- **Log out** ends the sessions owned by that login. The tab list is kept, so the next sign-in starts fresh shells.
- `sshweb sessions revoke <id>` ends a session or a login immediately.
- A server restart ends all shells (PTYs can't survive the process); tabs are still restored with fresh shells.

Set `sessions.detach_grace_secs` lower to reduce how long unattended shells live, or higher (e.g. 28800)
for tmux-like persistence. Shells you need to survive a server restart should run `tmux`/`screen` inside sshweb.
## Remote SSH hosts

Remote mode runs the system `ssh` client inside a PTY with a hardened argument list. Arguments
are passed as an argv vector and never go through a shell:

`-F none` (ignores `~/.ssh/config`), `StrictHostKeyChecking=yes`, `UserKnownHostsFile=<managed file>`,
`GlobalKnownHostsFile=/dev/null`, `UpdateHostKeys=no`, publickey auth only, `ConnectTimeout`,
`ServerAliveInterval/CountMax`, no agent/X11/port forwarding, `ProxyCommand=none`, `ProxyJump=none`,
`PermitLocalCommand=no`, `ControlMaster=no`, `EscapeChar=none`, and `--` before the host name.

1. Define profiles in `config.yaml`:
   ```yaml
   remote:
     enabled: true
     profiles:
       - id: web1
         name: "Web server 1"
         host: web1.example.net
         port: 22
         user: deploy
         identity_file: ~/.ssh/id_ed25519   # key on the gateway Mac (mode 0600); optional
   ```
   Without `identity_file`, ssh uses its default identities or the agent (if `use_agent: true`).
   Encrypted identity files prompt for their passphrase **in the browser terminal**. Prefer ssh-agent
   (`use_agent: true`) so passphrases don't pass through the gateway.
2. Trust the host key explicitly. Nothing is ever trusted automatically:
   ```sh
   sshweb hosts scan web1                                   # shows offered fingerprints (unverified)
   # compare with the server's real fingerprint, e.g. on the server:
   #   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   sshweb hosts trust web1 --fingerprint SHA256:abc…        # adds only the matching key
   # or, with the host's public key file obtained out of band:
   sshweb hosts trust web1 --key-file ssh_host_ed25519_key.pub
   sshweb hosts list
   ```
3. Grant users access: `access="remote:web1"` (or `remote:*`).

Unknown or changed host keys make ssh exit with "Host key verification failed" / "REMOTE HOST
IDENTIFICATION HAS CHANGED". The error is shown in the browser and nothing is added to `known_hosts`.
Arbitrary destinations aren't allowed. `remote.allow_adhoc: true` additionally permits `remote:*`
users to reach hosts, ports and users listed in `remote.allowed_hosts`, `allowed_ports` and
`allowed_users` (the server API supports this, but the bundled UI only offers profiles).

## Enabling remote (network) access and HTTPS

By default sshweb listens on **127.0.0.1 only**. To reach it from other machines:

1. Get a certificate for the name clients will use. Options:
   - a real certificate (e.g. ACME/Let's Encrypt via your DNS provider),
   - an internal CA, or
   - for testing only, a self-signed certificate:
   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
     -subj "/CN=mac.example.net" -addext "subjectAltName=DNS:mac.example.net" \
     -keyout ~/.sshweb/tls/key.pem -out ~/.sshweb/tls/cert.pem
   chmod 600 ~/.sshweb/tls/key.pem
   ```
2. Configure it:
   ```yaml
   server:
     bind: 0.0.0.0                 # or a specific interface address (prefer a VPN/Tailscale address)
     port: 7681
     allow_remote_access: true     # explicit opt-in
     allowed_origins: ["https://mac.example.net:7681"]
     tls:
       cert: tls/cert.pem
       key: tls/key.pem            # must be mode 0600
   ```
3. Run `sshweb config validate`, then `sshweb serve`, and open `https://mac.example.net:7681/`.

### Behind a reverse proxy

If browsers reach sshweb through a proxy (e.g. `https://dev.example.net` → `https://10.0.0.5:7681`):

- Add the proxy's public origin to `server.allowed_origins` (e.g. `"https://dev.example.net"`). Otherwise
  logins and other API calls fail with *cross-origin request rejected*, and WebSockets get 403.
- Add the proxy's IP to `server.trusted_proxies`, so rate limits, lockouts and the audit log use the real client
  IP from `X-Forwarded-For` (or `X-Real-IP` when the proxy sends no `X-Forwarded-For`). Both headers are
  ignored from any other peer. `X-Forwarded-For` is read from the right: the first hop that isn't a trusted
  proxy is the client, and whatever the client itself sent to the left of it is ignored. List every proxy in
  the chain.
- The proxy must: pass `Origin` and `Cookie` through **unchanged** (never rewrite `Origin`, which would disable
  CSRF and WebSocket-hijacking protection); support WebSocket upgrades on `/ws`; set `X-Forwarded-For`;
  use long read timeouts (hours) and no response buffering for `/ws`; and pass `Set-Cookie` through unchanged.
  It may keep or rewrite `Host`; both work once the origin is allowed.

sshweb refuses to start with a non-loopback bind unless `allow_remote_access: true` **and** TLS are
configured. A wildcard bind also needs `allowed_origins`. Only plain HTTP over loopback is supported;
there's no HTTP→HTTPS redirect. Put the gateway behind a VPN or firewall where you can. Login rate
limiting and lockout are on by default.

## Configuration

See [`config.example.yaml`](config.example.yaml); every field is documented there. Relative paths
are resolved against the config file's directory, and `~/` is expanded. Unknown fields are errors.
`sshweb config show` prints the effective configuration.

Environment overrides (deployment-specific paths and settings; never put secrets in the YAML):
`SSHWEB_CONFIG`, `SSHWEB_HOME`, `SSHWEB_BIND`, `SSHWEB_PORT`, `SSHWEB_ALLOW_REMOTE_ACCESS`,
`SSHWEB_TLS_CERT`, `SSHWEB_TLS_KEY`, `SSHWEB_STATE_DIR`, `SSHWEB_AUTHORIZED_KEYS`,
`SSHWEB_KNOWN_HOSTS`, `SSHWEB_AUDIT_LOG`, `SSHWEB_LOG_LEVEL`, `RUST_LOG`.

Startup validation fails with an actionable list of problems: unsafe bind, missing TLS, unsafe file
permissions (group/world-writable `authorized_keys`, readable TLS key or identity file), shells not in
`/etc/shells`, a missing `ssh` binary, an admin socket path that's too long, invalid profiles, and so on.

## CLI reference

```
sshweb serve [-c CONFIG]                    run the gateway
sshweb config init [--dir DIR] [--force]    create config dir with sample config and empty key files
sshweb config validate [-c CONFIG]          offline validation (exit 2 on problems)
sshweb config show [-c CONFIG]              effective configuration
sshweb keys list [-c CONFIG]                offline
sshweb keys fingerprint FILE|-              offline
sshweb keys add --user U --access A FILE|-  offline, audited
sshweb keys revoke SHA256:...               offline, audited; running server reacts within seconds
sshweb hosts list | scan PROFILE | trust PROFILE (--fingerprint FP | --key-file FILE)
sshweb sessions list | revoke ID            needs the running server (admin socket)
sshweb health                               needs the running server; exit 0 when ready
sshweb sign [-f KEY] [MESSAGE]              sign a login challenge with ssh-keygen
sshweb version
```

## Operations

- **Health:** `GET /healthz` (liveness) and `GET /readyz` (ready only when the keys file is valid and the
  server isn't shutting down). Both return no sensitive detail. `sshweb health` prints full diagnostics
  from the admin socket.
- **Metrics:** Prometheus text on the admin socket (`curl --unix-socket ~/.sshweb/run/admin.sock http://x/metrics`).
  Set `metrics.enabled: true` to also expose `/metrics` on the HTTP port, to loopback clients only.
  Counters cover logins (success/failure/lockouts), challenges, WebSocket connections, origin
  rejections, protocol errors, sessions opened (local/remote), active sessions, session start
  failures, remote connection failures and terminal bytes in/out.
- **Logs:** structured `tracing` logs on stderr (`logging.format: json` for JSON). Terminal content is
  never logged.
- **Audit log:** JSON lines with challenges, login success/failure/lockout, logout, expiry, session
  open/close/attach/denied (with remote host/port/user), WebSocket connect/disconnect/rejections,
  administrative key/host/session actions, and server start/stop. Tokens, signatures and terminal
  data are never recorded.
- **Sessions:** `sshweb sessions list` and `sshweb sessions revoke <session-or-login-id>`.
- **Shutdown:** SIGINT/SIGTERM sets readiness to false, notifies browsers, terminates every session's
  process group, drains connections (5 s), removes the admin socket and writes `server_stop`.

## Architecture

| Module | Responsibility |
|---|---|
| `src/cli.rs` | clap CLI, offline key/host/config tools, `sign` helper |
| `src/config.rs` | typed YAML config, env overrides, path resolution, validation |
| `src/server.rs` | Axum router, security middleware (Host/Origin/CSP/HSTS), auth API, admin socket, lifecycle |
| `src/assets.rs` | `rust-embed` static assets (`web/`) |
| `src/auth/` | `keys.rs` authorisation file, `challenge.rs` challenges + SSHSIG verify, `sessions.rs` logins, `mod.rs` service with rate limiting/lockout |
| `src/websocket/` | versioned protocol (`protocol.rs`) and connection state machine |
| `src/session/` | terminal session lifecycle, attach/detach, scrollback, limits, reaping |
| `src/terminal/` | PTY processes (`portable-pty`), I/O threads with backpressure, process-group teardown |
| `src/ssh/` | remote target authorisation, hardened OpenSSH argv, managed `known_hosts` |
| `src/security/` | CSPRNG tokens, permission checks, origin/host policy, rate limiters |
| `src/audit.rs`, `src/metrics.rs` | audit trail, counters and Prometheus rendering |
| `web/` | `index.html`, `app.css`, `app.js`, vendored xterm.js |

Data flow: PTY reader thread → bounded channel (32 × 16 KiB) → session pump (scrollback + attached
socket's bounded channel) → WebSocket binary frames. A slow browser stalls the pump, which stalls the
PTY reader, which blocks the program writing output. Memory stays bounded. Input goes through a
per-connection token bucket into a bounded channel to a PTY writer thread.

Design notes and the decision log are in [PLAN.md](PLAN.md). The wire protocol is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Testing

```sh
cargo test                      # unit + integration tests (real PTYs, real ssh/sshd, real ssh-keygen)
cargo clippy --all-targets -- -D warnings
scripts/test-run-as.sh          # local.run_as for real: two accounts + the sudoers rule in a Linux container (Docker)
```

The integration tests use temporary directories and throwaway keys. The remote tests start a
disposable unprivileged `sshd` on a random loopback port (skipped if `/usr/sbin/sshd` is missing).
The manual browser test procedure, including vim, is in [docs/TESTING.md](docs/TESTING.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `authentication failed` | Request a **new** challenge (each one is single-use and expires). Sign with `-n sshweb-auth`. Check `sshweb keys list` shows your key's fingerprint (`ssh-keygen -lf key.pub`) for the user name you typed. |
| `authentication is unavailable` / `/readyz` 503 | `authorized_keys` is missing, has unsafe permissions or a malformed line: run `sshweb config validate`. |
| `locked out` (HTTP 429) | Too many failures from your IP. Wait `rate_limit.lockout_secs`, or restart the server. |
| `ssh-keygen: unknown option -- Y` | OpenSSH older than 8.1 on the client; upgrade it. |
| Signing with an agent key | `ssh-keygen -Y sign -n sshweb-auth -f ~/.ssh/key.pub` (the **.pub** file). |
| Page loads but WebSocket fails / 403 | You're using a host name or port that isn't allowed. Add the exact `https://host:port` to `server.allowed_origins`. |
| `421 unknown host` | Same cause: the Host header must match the bind address or `allowed_origins` (DNS-rebinding protection). |
| `Host key verification failed` | Trust the host key: `sshweb hosts scan <profile>` then `hosts trust --fingerprint`. |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | The host key changed. Verify why out of band before removing the old line from `known_hosts`. |
| `Permission denied (publickey)` | The profile's `identity_file` or agent key isn't authorised on the remote host. |
| `admin socket path … too long` | Set `server.state_dir` / `SSHWEB_STATE_DIR` to a shorter path (macOS socket paths max 103 bytes). |
| `another sshweb instance is running` | Stop it, or use a different `state_dir` and port. |
| `local.run_as: sudo won't start shells …` (or `… stays running …`, `… drops the terminal's variables`) | The sudoers rule is missing or changed: install `packaging/sshweb.sudoers` (names adjusted) with `visudo -cf` first. |
| `the gateway's account can't reach <folder>` | With `run_as`, the gateway still checks and enters tab folders: `chmod +a "user:_sshweb allow search" /Users/<account>`. |
| Remote terminal asks for a passphrase | The identity file is encrypted; prefer `use_agent: true` with the key loaded in ssh-agent. |
| Terminal size wrong after a resize | Press **Reconnect**. Size is re-sent on attach. |

## Security limitations

Read [docs/SECURITY.md](docs/SECURITY.md) for the threat model. In short:

- A browser terminal **is** shell access. Anyone with an authorised key and `local` access gets the
  macOS account that runs sshweb.
- Copy-paste signing can't technically bind the signature to the page the way WebAuthn does. Users
  must check the origin in the challenge before signing.
- All identities share one macOS account, and isolation between gateway users is by policy only.
  `local.run_as` separates that account from the gateway itself, not people from each other.
- Passphrases typed into a remote session (encrypted identity files) pass through the gateway's memory.
  They're never logged, but prefer ssh-agent.
- State (logins, lockouts) is in memory. A restart logs everyone out and clears lockouts.
- Not yet externally reviewed. Treat it as security-sensitive software and keep it on loopback or behind a VPN.

License: MIT. xterm.js is MIT-licensed (`web/vendor/LICENSE.xterm`).
