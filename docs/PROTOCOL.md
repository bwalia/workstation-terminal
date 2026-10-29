# WebSocket protocol, version 1

Endpoint: `GET /ws` (WSS under TLS). The upgrade requires an allowed `Origin` and `Host`
(403/421 otherwise). A valid login cookie, if present, authenticates the socket. Without one, at most
`limits.max_unauthenticated_websockets_per_ip` (8) sockets per client IP may wait to sign in (429 beyond
that), and each must sign in within `limits.ws_auth_timeout_secs` (30 s) of connecting.

## Framing

- **Client → server:** UTF-8 JSON text frames, one message per frame, with a `type` field. Unknown
  types or fields, wrong types and out-of-range values produce a recoverable `error`. Binary frames
  from the client are rejected.
- **Server → client:** JSON text frames for control messages. **Binary frames carry raw terminal output**
  for the socket's bound session. Output may split UTF-8 sequences across frames, and xterm.js decodes them as a stream.
- **Limits:** frames and messages over `limits.ws_max_message_bytes` (64 KiB) close the connection.
  Input is throttled by a per-connection token bucket (`input_bytes_per_sec`, `input_burst_bytes`).
  After 10 protocol errors the socket is closed.
- **Keepalive:** the server sends WebSocket pings every 20 s and closes connections silent for more
  than 65 s. Clients may also send `ping` and receive `pong`.

## State machine

```
connected ──hello(v=1)──▶ greeted ──(cookie or auth_ok)──▶ authenticated ──open/attach──▶ bound
    │ (10 s without hello: closed)        │ any terminal message before auth:              │ session_closed / detach / status:detached
    └─ any other message: fatal error     │   fatal "unauthenticated", socket closed       └──▶ authenticated
                                          └ not authenticated 30 s after connecting: fatal "auth_timeout"
```

Each socket is bound to **one** authenticated identity and at most **one** terminal session at a time.
The login is re-validated (expiry, revocation, key still authorised) on every terminal message and every 5 s.

## Client messages

| type | fields | notes |
|---|---|---|
| `hello` | `version: 1` | Must be first. |
| `auth_request` | `user` | Only when not authenticated. Returns `auth_challenge` or `auth_failed`. |
| `auth_response` | `challenge_id`, `signature` (armored SSHSIG) | Returns `auth_ok` or `auth_failed`. |
| `open` | `target`, `cols` (1–1000), `rows` (1–500) | Optional `name` sets the session label. `target` is `{"kind":"local","shell":"/bin/zsh"?,"cwd":"/abs/folder"?}`, `{"kind":"remote","profile":"web1"}` or `{"kind":"adhoc","host","port"?,"user"}`. `cwd` must be inside `local.allowed_roots`. Optional `launch` (with a local target) opens an OpsAPI task link accepted by `POST /api/launch`; its folder, agent and environment come from the launch, and each launch opens once. |
| `attach` | `session_id`, `cols`, `rows` | Resume your own detached session. Replays scrollback **output** only. |
| `input` | `data`, `binary`? | Keystrokes. With `binary: true`, each char is a byte (0–255). |
| `resize` | `cols`, `rows` | |
| `detach` | | Unbind; the session stays alive for `detach_grace_secs`. |
| `close` | | Terminate the session's processes. |
| `ping` | `ts`? | |

## Server messages

| type | fields |
|---|---|
| `hello` | `version`, `server`, `authenticated`, `user` |
| `auth_challenge` | `challenge_id`, `namespace` (`sshweb-auth`), `message`, `expires_unix` |
| `auth_ok` | `user`, `expires_unix` |
| `auth_failed` | `code` (`auth_failed`, `rate_limited`, `locked_out`, `invalid_user`, `auth_unavailable`), `message` |
| `session_opened` | `session_id`, `kind` (`local`/`remote`), `title`, `name` (user label or null), `resumed` |
| `session_closed` | `session_id`, `reason`, `exit_code` (null if killed) |
| `status` | `state` (`detached`), `message`. Sent, for example, when another window attached the session. |
| `pong` | `ts` |
| `error` | `code`, `message`, `fatal`. Fatal errors are followed by a close. |

Error codes: `bad_message`, `hello_required`, `hello_timeout`, `auth_timeout`, `unsupported_version`,
`unauthenticated`, `session_expired`, `forbidden`, `open_failed`, `no_such_session`, `no_session`, `session_closed`,
`resize_failed`, `server_shutdown`.

## Reconnect semantics

When a socket drops, the server detaches the session (state `detached`) rather than killing it. A
client that reconnects within `sessions.detach_grace_secs` (default 30 min) sends `hello` and then `attach`.
The attaching login must belong to the same user. It may be a newer login than the one that opened the
session; the session is then re-bound to it. It gets
`session_opened{resumed:true}` followed by one binary frame with the recent output (at most
`sessions.scrollback_bytes`). **Input is never buffered or replayed.** The bundled client drops
keystrokes typed while disconnected. Attaching from a second window takes over the session and sends
`status{state:"detached"}` to the first.

## Example

```
→ {"type":"hello","version":1}
← {"type":"hello","version":1,"server":"sshweb/0.1.0","authenticated":true,"user":"alice"}
→ {"type":"open","target":{"kind":"local"},"cols":120,"rows":40}
← {"type":"session_opened","session_id":"9f2c…","kind":"local","title":"alice@mac (/bin/zsh)","resumed":false}
← <binary: "\x1b]0;…\x07alice@mac ~ % ">
→ {"type":"input","data":"ls\r"}
← <binary: "ls\r\nDesktop  Documents …">
→ {"type":"resize","cols":100,"rows":30}
→ {"type":"input","data":"exit\r"}
← {"type":"session_closed","session_id":"9f2c…","reason":"process exited","exit_code":0}
```

## HTTP API (same origin, JSON)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/auth/challenge` `{user}` | Origin | Issue a challenge; sets the binding cookie |
| `POST /api/auth/verify` `{challenge_id, signature}` | Origin + binding cookie | Log in; sets the session cookie |
| `POST /api/auth/logout` | Origin | Revoke the login and close its sessions |
| `GET /api/me` | cookie | Identity, access, permitted profiles and shells |
| `GET /api/sessions` | cookie | Your sessions and their state. With `X-Sshweb-Poll: 1` (the page's background refresh) the request doesn't count as activity for the login's idle timeout |
| `GET /api/workspace` | cookie | Your saved tabs: `{tabs:[{id, target, name, session_id}], active}` |
| `PUT /api/workspace` | cookie + Origin | Save tabs (≤ 16, validated; last writer wins). Local tabs may carry `cwd`. |
| `POST /api/launch` `{ticket}` | cookie + Origin | Accept an OpsAPI task link: `{launch, name, cwd, agent:{id,name}, task:{uuid,number,title,url}, by, workspace, used, session_id}`. See [OPSAPI.md](OPSAPI.md). |
| `DELETE /api/sessions/{id}` | cookie + Origin | Close one of your sessions |
| `PATCH /api/sessions/{id}` `{name}` | cookie + Origin | Rename one of your sessions (≤ 64 chars, no control characters; empty resets) |
| `GET /healthz`, `GET /readyz` | none | Liveness / readiness (no sensitive detail) |
| `GET /metrics` | loopback, only if `metrics.enabled` | Prometheus text |

Admin socket (`<state_dir>/admin.sock`, mode 0600): `GET /healthz`, `GET /metrics`,
`GET /admin/sessions`, `DELETE /admin/sessions/{session-or-login-id}`.
