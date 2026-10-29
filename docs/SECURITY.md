# sshweb threat model and security design

## What sshweb protects

| Asset | Why it matters |
|---|---|
| Shell access to the macOS account running sshweb | Full control of that user's files, keychains (when unlocked), SSH keys and network position. |
| Access to remote SSH hosts via configured profiles | The gateway holds or reaches identities for those hosts. |
| The authorisation file and `known_hosts` | They decide who may log in and which servers are genuine. |
| Login session tokens | Bearer credentials for an authenticated browser. |
| Terminal contents | May contain passwords, tokens and operational data. |

## Trust boundaries

1. **Browser ↔ gateway** (HTTP/WebSocket). Loopback by default; HTTPS/WSS is mandatory off-loopback.
2. **Gateway ↔ local OS.** Child processes run as the gateway's unprivileged user. sshweb refuses to run as root.
3. **Gateway ↔ remote hosts** (OpenSSH). Host identity comes only from the managed `known_hosts`.
4. **Administrator ↔ gateway** (config files, CLI, admin Unix socket). Filesystem permissions are the boundary.

## Adversaries and mitigations

| # | Threat | Mitigations | Tests |
|---|---|---|---|
| T1 | **Unauthenticated network user** gets a shell | No terminal message is processed before authentication. The upgrade is refused for foreign origins. Every terminal op re-validates the login. Default bind is 127.0.0.1. | `unauthenticated_socket_cannot_open_terminal`, `hello_is_required_and_versioned` |
| T2 | **Key impersonation**: attacker knows a public key | Login needs an SSHSIG over a server-generated message. The server rebuilds the message from its own state, checks namespace `sshweb-auth`, checks the signing key belongs to the claimed user, then verifies (RustCrypto `ssh-key`). A bare public key is rejected. | `a_bare_public_key_is_not_proof`, `signature_from_unauthorised_key_or_other_user_rejected` |
| T3 | **Replay** of a captured signature | Challenges are single-use (deleted on first attempt, even a failed one) and expire after 120 s by default. Each carries a 256-bit nonce. | `challenge_single_use`, `full_login_flow_and_replay_prevention` |
| T4 | **Signature theft / login CSRF**: a signature redeemed from another browser | The challenge is bound to a random HttpOnly, SameSite=Strict cookie (or to the WebSocket connection) and verified in constant time. | `challenge_bound_to_requesting_browser`, `challenge_binding` |
| T5 | **Cross-protocol reuse** (e.g. tricking a user into a git-signing operation) | The namespace must equal `sshweb-auth`. The message format `sshweb-auth-v1 …` is not a valid git or file signature target. | `ssh_keygen_signature_interoperates` |
| T6 | **Cross-site WebSocket hijacking / CSRF** | The `Origin` must exactly match an allowed origin (scheme, host and port) for the WebSocket upgrade and for every state-changing `/api` request. Cookies are SameSite=Strict. | `rejects_cross_site_websocket`, `state_changing_requests_require_origin` |
| T7 | **DNS rebinding** against the loopback listener | The `Host` header must be one of the bind addresses or configured origins; otherwise 421. | `rejects_foreign_host_header` |
| T8 | **Online guessing / brute force** | Challenge issuance is rate-limited per IP. After N failures in a window, the IP is locked out temporarily. User names aren't locked: Ed25519 and the other accepted signatures can't be guessed, and a per-user lock-out would let anyone lock a named person out. Errors are generic. Unknown users still receive challenges (no user enumeration). | `challenge_rate_limit`, `lockout_after_repeated_failures` |
| T9 | **Token theft** | 256-bit CSPRNG tokens in HttpOnly cookies, stored server-side only as SHA-256. Absolute and idle expiry (background polls don't count as activity). Logout, admin revocation and key revocation take effect within seconds. TLS cookies use `Secure` and the `__Host-` prefix. HSTS is sent under TLS. | `tokens_are_not_stored_in_clear`, `background_polls_do_not_keep_a_login_alive`, `logout_and_key_revocation_end_access`, `https_mode_sets_secure_cookies_and_hsts` |
| T10 | **XSS / UI injection** | Strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`). The UI uses `textContent`, never `innerHTML`, for server data. Terminal output is rendered by xterm.js, not the DOM. | `serves_embedded_frontend_with_security_headers` |
| T11 | **Resource exhaustion** | Per-message size limit (64 KiB), HTTP body limit, a global WebSocket connection cap, at most 8 sockets per client IP that haven't signed in and 30 s for each to do so (pings don't extend it), per-connection input token bucket, bounded channels with backpressure end to end, bounded scrollback, session limits total and per user, a cap on outstanding challenges, and protocol-error budgets. | `oversized_message_closes_connection`, `too_many_protocol_errors_close_the_socket`, `sockets_must_sign_in_in_time_and_few_may_wait_per_address`, `session_limit_per_user`, `malformed_and_oversized_requests` |
| T12 | **Command injection** into the shell or ssh | No shell is ever used to build commands. ssh/ssh-keyscan/ssh-keygen get argv vectors. Hosts and users are allowlist-validated (no leading `-`, restricted charset). `--` precedes the host. Users can pick only shells from `allowed_shells` ∩ `/etc/shells`. Profile ids are lookups only. | `host_and_user_validation`, `ssh_args_are_hardened`, `local_shell_policy`, `disallowed_shell_and_local_access_refused` |
| T13 | **Open proxy / pivoting** | Remote targets must be configured profiles the user is authorised for. Ad-hoc targets are off by default and, when enabled, constrained by host, port and user allowlists plus `remote:*`. Port, agent and X11 forwarding, ProxyCommand/ProxyJump, LocalCommand, ControlMaster and the escape char are disabled. | `profile_authorisation`, `adhoc_requires_allowlists`, `auth_failure_and_unauthorised_profiles` |
| T14 | **Man-in-the-middle on remote SSH** | `StrictHostKeyChecking=yes` with only the managed `known_hosts` (`GlobalKnownHostsFile=/dev/null`, `UpdateHostKeys=no`, `-F none`). Unknown or changed keys fail. Keys are added only by an admin, after fingerprint confirmation or from an out-of-band key file. | `unknown_host_key_is_rejected`, `changed_host_key_is_rejected` |
| T15 | **Session hijack between users** | Sessions are bound to their owner. Detached sessions can only be re-attached by the same user after a fresh key login, and are tied to the owning key's fingerprint, so key revocation ends them even when no login exists. Attaching or closing another user's session returns the same "not found" error as a nonexistent id. Each socket is bound to at most one session. | `sessions_are_bound_to_their_owner` |
| T16 | **Privilege escalation via files** | Refuses to start if `authorized_keys`, `known_hosts` or config are group/world-writable or owned by another user. TLS keys and identity files must be 0600. State dir 0700, admin socket 0600, audit log 0600. | `admin_file_permissions`, `private_file_permissions`, `validate_reports_unsafe_settings` |
| T17 | **Self-authorisation**: a gateway user adds their own key | The server has no endpoint that writes `authorized_keys`. Keys can only be added by someone who can write the file (the admin account). | by construction |
| T18 | **Sensitive data in logs** | Terminal I/O is never logged (the work log's screen recording, T28, goes to OpsAPI, never to the audit log). Signatures, tokens and challenge nonces aren't written to the audit log. Audit fields are length-limited and stripped of control characters (no log forging). | `full_login_flow_and_replay_prevention`, `writes_json_lines_and_sanitizes` |
| T19 | **Orphaned processes** | Each session's child is a session leader. On close the whole process group gets SIGHUP, then SIGKILL after a grace period. Graceful shutdown closes every session. | `terminate_kills_process_group`, `graceful_shutdown_closes_sessions_and_sockets` |
| T20 | **Accidental exposure** | A non-loopback bind needs `allow_remote_access: true` **and** TLS. A wildcard bind needs explicit `allowed_origins`. Metrics are off on the HTTP port by default and loopback-only when enabled. Admin functions exist only on the private Unix socket. | `remote_exposure_requires_opt_in_tls_and_origins`, `serve_refuses_unsafe_remote_exposure` |

| T21 | **Forged or replayed task links** (OpsAPI) | Links are HMAC-SHA256 signed with a secret shared only with OpsAPI (constant-time check), expire (≤ 1 h), and open once; a link accepted by one user can't be claimed or opened by another. Unless auto sign-in (T25) is on for that person, a link never signs anyone in: they still prove their SSH key. | `tampered_wrong_key_expired_and_long_lived_links_are_refused`, `bad_links_are_refused`, `launches_are_single_use_per_user` |
| T22 | **Folder escape** via a link or a saved tab | The folder is resolved with `realpath` (symlinks followed) and must be an existing directory inside `local.allowed_roots`; without roots, folders and links are refused. Roots choose where a tab starts; they are not a sandbox: the shell can go anywhere the account can (see "A separate macOS account" in OPSAPI.md). | `folders_must_be_real_directories_inside_a_root`, `tabs_may_reopen_in_an_allowed_folder_only` |
| T23 | **Command injection** through task text | A link carries an agent **id**; command lines come only from `opsapi.agents` in the config. Task text (prompt, title) reaches the shell only as environment variables, never as shell syntax; control characters are stripped. A prompt whose first non-blank character is `-` is refused, and the documented run lines put `--` before it, so it can't become an agent option (`--settings=…`). The banner is built with `textContent`. | `task_link_opens_the_folder_starts_the_agent_and_reports_to_opsapi`, `prompts_that_start_with_a_dash_are_refused`, `bad_fields_are_refused` |
| T24 | **Webhook spoofing** towards OpsAPI | Webhooks are HMAC-signed and carry only the launch id (OpsAPI looks the task up from its own record, never from the webhook) and a timestamp OpsAPI checks. | `task_link_opens_the_folder_starts_the_agent_and_reports_to_opsapi` |
| T25 | **Sign-in through OpsAPI** (auto sign-in, `POST /api/launch/login`) | Off by default. Needs a signed link carrying `login`, living ≤ 120 s, whose OpsAPI step-up (emailed code) is no later than the link and no older than `opsapi.autologin.max_stepup_age_secs` (12 h); the email must be listed in this gateway's own config, and only maps to the terminal user listed there. The login is made through that user's key with `local` access (revoking the key ends it). Each link signs in once. Origin-checked, rate-limited per IP and counted towards the SSH sign-in lock-out; audited as `auth_success`/`auth_failure` with `via=opsapi_launch` and the OpsAPI email and user. | `a_link_with_login_signs_in_once_and_then_opens_the_task`, `links_that_may_not_sign_in_are_refused`, `auto_sign_in_is_off_by_default_and_failures_lock_out`, `autologin_needs_config_mapping_short_link_and_fresh_stepup` |
| T26 | **Report token leakage** | The per-launch token reaches only the task shell's environment (`OPSAPI_REPORT_TOKEN`), is never logged, and on the OpsAPI side can only attach pull requests and notes to its own task. | `a_link_with_login_signs_in_once_and_then_opens_the_task`, `env_carries_the_report_link_when_given` |
| T27 | **Keys from OpsAPI** (`opsapi.keys`) | Fetched with a signed request; the list is used only if its HMAC over the body matches, it names this terminal, is < 5 min old and not older than the last one taken (no replay of a list from before a key was blocked). `local` access only; a user or key that is in `authorized_keys` can't be taken over from the list; expired keys are dropped; without a good fetch for `max_stale_secs` all OpsAPI keys stop (file keys keep working). Removal ends sessions like `sshweb keys revoke`. Added/removed keys are audited. | `opsapi_key_list_must_be_signed_for_this_terminal_and_recent`, `opsapi_keys_merge_but_never_take_over_the_file`, `autologin_finds_people_opsapi_issued_keys_to_by_email` |
| T28 | **Work log** (`opsapi.work_log`): forged telemetry, leaked recordings | Off by default. Claude's telemetry is received on a separate listener bound to `127.0.0.1` only (never the public port), JSON only (a web page can't send that without a CORS preflight, which is never answered) and only with a loopback `Host` (no DNS rebinding). Each local tab has its own 256-bit random token, kept hashed and dropped when the tab ends; posts without a live tab's token (Claude outside sshweb tabs, the owner's included, or a forged token) are answered `200 {}` and discarded unread, only counted (`work_log_unattributed_dropped`, at most once a minute). Claude's `user.email`, `user.account_uuid` and `organization.id` are dropped. The screen recording takes PTY **output only, never input**; parts are 0600 in the 0700 state dir until OpsAPI has them, and stop being written (a gap, audited) while `max_pending_mb` waits, so an unreachable OpsAPI can't fill the disk. Activity and recordings are HMAC-signed with the shared secret, sent only over https (or to this machine), without following redirects. | `local_tabs_get_a_token_and_telemetry_settings`, `logs_keep_only_the_five_events_without_personal_attributes`, `parts_rotate_by_size_and_age_with_the_header_only_in_part_0`, `signatures_cover_the_body_and_for_recordings_the_tab_and_part`, `unattributed_posts_are_only_counted_and_audited_once_a_minute`, `parts_are_skipped_while_too_much_waits_for_upload`, `a_local_tab_reports_claude_telemetry_and_its_screen_to_opsapi` |
| T29 | **A terminal reads or changes the gateway's own files** (config with the OpsAPI secret, TLS key, audit log, work-log queue, recordings) to fake task reports or edit the record | `local.run_as`: the gateway runs as its own account (`_sshweb`) and starts shells as another (`workstation`) through a sudoers rule that allows exactly that account and nothing else; the config is `root:_sshweb 640` and the state `_sshweb 700`. sudo hands over to the shell (no root process in between), keeps only the terminal's variables and sets the account's HOME; signals go through the same rule. `config validate` checks the rule at every start and refuses `root` or the gateway's own account. | `sudo_args_keep_the_command_after_the_separator`, `run_as_an_unknown_account_is_refused`, `shells_run_as_the_other_account_and_can_still_be_stopped`, `the_check_names_what_is_wrong_when_sudo_refuses` (the last two: `scripts/test-run-as.sh`) |
| T30 | **A terminal reaches past its folder** (other accounts' files, disks, services on the Mac or the local network) | `local.sandbox_profile`: shells run in a macOS sandbox (packaging/sshweb-shell.sb) that everything they start inherits: under `/Users` only their account's folder; shared set-up read-only (start-up files, PATH folders in the home and the Claude binary, logins, git's identity, and Claude's settings, memory, commands, agents, skills, plugins and hooks), and their parent folders can't be swapped for a link; other tabs' processes and the gateway can't be inspected or signalled; outbound only to ports 443/80 plus the work log receiver and a few dev-server ports on localhost. The profile must be root/gateway-owned and not writable by others; `config validate` starts a test shell in it. Ports 443/80 on the local network stay reachable (the sandbox can't filter by address; use pf). People sharing the account still share projects, `~/.claude.json`, transcripts, history, and can read each other's process environments (tab tokens). | `the_command_line_wraps_the_shell_in_its_sandbox_then_its_account`, `shells_stay_in_their_folder_and_on_the_web`, `job_control_still_works_in_the_sandbox`, `a_broken_profile_is_refused_with_the_reason` |

## Residual risks and limitations

- **Relay phishing.** The copy-paste flow can't bind the signature to the browser's real origin the
  way WebAuthn can. A malicious page could fetch a real challenge and ask the victim to sign it. Mitigations:
  the origin is inside the signed message, so users should check it (`sshweb sign` prints it). Challenges
  expire in 120 s. Keep the gateway on loopback or a VPN. A browser extension or native helper could
  enforce origin binding in future.
- **Shared OS account.** All gateway identities get shells as the one macOS user that runs sshweb.
  Separating users needs separate instances under separate accounts.
- **Terminal = full trust.** Anything the user can do in Terminal.app, they can do here. Programs in
  the session can read data in that account.
- **Passphrases through the gateway.** If a remote profile uses an encrypted identity file without an
  agent, the passphrase is typed in the browser and passes through gateway memory (never logged).
- **Unattended shells.** Detached shells keep running for up to `sessions.detach_grace_secs` (default
  30 min) after the browser goes away. They can't be reached without a fresh key login, but they keep
  running programs and holding resources. Lower the setting if that matters.
- **In-memory state.** Logins, lockouts and challenges don't survive restarts. A restart logs everyone
  out (fail safe) but also clears lockouts.
- **Fail-closed authorisation file.** One malformed line rejects all logins and terminates existing
  sessions until fixed. This is deliberate, but it means an editing mistake causes an outage.
  Use `sshweb keys add/revoke` and `sshweb config validate`.
- **Lockout as DoS.** Lock-outs are per client IP, so people behind the same address (an office NAT)
  lock each other out with repeated failures. Behind a proxy, list it in `server.trusted_proxies`, or
  everyone shares the proxy's address. Lockouts are temporary (`rate_limit.lockout_secs`).
- **Trust in dependencies.** RustCrypto `ssh-key` (signature verification), `rustls` (TLS),
  OpenSSH (remote transport, host keys), `portable-pty` and xterm.js.
- **Task text is untrusted input to agents.** Anyone who can edit a task in OpsAPI can steer the agent
  it starts (prompt injection). Run task terminals under an account with no access to anything the work
  doesn't need (docs/OPSAPI.md, "A separate macOS account").
- **Auto sign-in moves trust to OpsAPI.** For the people listed under `opsapi.autologin.users`, an
  OpsAPI account plus access to its mailbox (for the step-up code) is as good as their SSH key, and
  whoever holds the shared secret can mint such links. List only people you'd give a shell on this
  account, and rotate the secret if OpsAPI may be compromised.
- **Unattended agents.** An agent configured like `claude_auto` (`--dangerously-skip-permissions`) acts
  on task text without asking. That is only acceptable because task terminals run under their own macOS
  account; leave it out of `opsapi.agents` to forbid it.
- **The work log watches people.** With `opsapi.work_log` on, prompts, tool commands and everything a
  tab shows go to OpsAPI; typed text the terminal echoes is on screen too (passwords at a no-echo
  prompt aren't). Tell employees in writing first. Someone in a tab can unset its telemetry settings
  unless Claude's managed settings are installed (docs/OPSAPI.md, "Work log"). Those switch telemetry on
  for every Claude Code on the Mac; outside sshweb tabs it is discarded at the loopback receiver, but
  everyone using Claude there should be told.
- **No external audit yet.**

## Operational guidance

- Keep `bind: 127.0.0.1` unless you need network access. If you do, prefer binding to a VPN interface
  (e.g. a Tailscale address) over `0.0.0.0`, and use a real certificate.
- Use Ed25519 keys. For remote profiles, use dedicated keys with `restrict`/`from=` options on the
  remote side where possible, and prefer ssh-agent over encrypted identity files.
- Review `audit.log` regularly: `auth_failure`, `auth_lockout`, `ws_rejected`, `session_denied`.
- Revoke promptly with `sshweb keys revoke` and `sshweb sessions revoke`.

## Reporting vulnerabilities

See [../SECURITY.md](../SECURITY.md).
