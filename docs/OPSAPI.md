# OpsAPI task links

OpsAPI (the project management platform) can open a task straight into a terminal tab here:
**Start with AI → Work in the web terminal** on a task asks for a folder on this Mac and an agent
(Claude Code, Codex, Cursor or just a terminal). The browser then opens

```
https://<this gateway>/#launch=<ticket>
```

After the person signs in **with their SSH key as usual**, the gateway opens a tab named after the task
in that folder and starts the agent with the task as its first message. When the agent exits they are
left in an ordinary shell in the same folder. OpsAPI shows the session on the task until it ends.

A launch link never carries a command and works once. It signs nobody in, unless this gateway has
turned on [auto sign-in](#auto-sign-in-for-power-users) for that person.

## Setting it up

1. In OpsAPI: **AI Runs → Machines → Web terminals → Add**, with this gateway's public address
   (e.g. `https://dev.workstation.co.uk`). OpsAPI shows a shared secret and an `opsapi:` block **once**.
2. Paste it into this gateway's `config.yaml` and add the folders tasks may open:

   ```yaml
   local:
     allowed_roots: [~/projects]          # tabs and task links may open these folders and below

   opsapi:
     webhook_url: https://int-opsapi.workstation.co.uk/api/v2/ai-runner/public/terminal/webhook
     webhook_secret: "<from OpsAPI>"      # or SSHWEB_OPSAPI_WEBHOOK_SECRET
     agents:                              # ids must match the agents listed in OpsAPI
       # `--` before the prompt, so a prompt starting with `-` is never read as an option.
       - { id: claude, name: Claude Code, run: 'claude -- "$OPSAPI_TASK_PROMPT"' }
       - { id: codex,  name: Codex,       run: 'codex -- "$OPSAPI_TASK_PROMPT"' }
       - { id: cursor, name: Cursor,      run: 'cursor-agent -- "$OPSAPI_TASK_PROMPT"' }
       # Never stops to ask. Only acceptable because this gateway runs under its own macOS
       # account (below); leave it out to forbid unattended agents.
       - { id: claude_auto, name: "Claude Code (unattended)", run: 'claude --dangerously-skip-permissions -- "$OPSAPI_TASK_PROMPT"' }
     idle_timeout_secs: 14400             # task tabs: 4 h with neither input nor output
     detach_grace_secs: 14400             # task tabs keep running 4 h after the browser closes
   ```

3. `sshweb config validate`, then restart the gateway (this ends open terminals; pick a quiet moment).

`shell` (no agent) is always available. Each agent's `run` is one shell command line, run by the user's
own shell with `-i` so PATH and rc files are as in a normal terminal. The task is only available through
environment variables, so its text is never parsed as shell syntax:

| Variable | Value |
|---|---|
| `OPSAPI_TASK_PROMPT` | The prompt the person reviewed in OpsAPI (≤ 8000 characters) |
| `OPSAPI_TASK_TITLE`, `OPSAPI_TASK_NUMBER` | Task title and number |
| `OPSAPI_TASK_URL` | Link back to the task |
| `OPSAPI_TASK`, `OPSAPI_LAUNCH` | Task id and launch id |
| `OPSAPI_REPORT_URL`, `OPSAPI_REPORT_TOKEN` | Where and how the agent tells OpsAPI about its pull request (only when the link has `report`) |

Always quote it and put `--` before it (`claude -- "$OPSAPI_TASK_PROMPT"`), so a prompt that starts with
`-` (say `--settings=…`) is never read as an option. The gateway also refuses such a prompt
(`prompt_starts_with_dash`), for run lines written without the `--`.

## What happens

1. The page reads `#launch=…` (a fragment, so it never reaches proxies or access logs). If the person
   isn't signed in, the sign-in screen says which task is waiting.
2. `POST /api/launch {ticket}` (login cookie and Origin, like every state-changing call). The gateway:
   - verifies the signature (HMAC-SHA256 with the shared secret, constant time), version, expiry and a
     lifetime of at most 1 hour;
   - requires `local` access for the signed-in key;
   - resolves the folder with `realpath` and requires an existing directory inside `local.allowed_roots`
     (symlinks can't escape);
   - looks the agent id up in `opsapi.agents`.
   Errors: `invalid_link`, `expired`, `not_configured`, `prompt_starts_with_dash` (the prompt's first
   non-blank character is `-`), `folder_not_found`, `folder_not_allowed`, `unknown_agent` (400),
   `forbidden` (403), `already_used` (409, another user accepted it).
3. The page opens a tab with `{"type":"open","target":{"kind":"local"},"launch":"<id>"}`. The folder,
   agent and environment come only from the accepted launch. The launch is then used up: re-posting the
   link returns the running session (a page reload re-attaches it); opening it again is refused.
4. The tab is saved with its folder, so restoring it later opens a plain shell there (no agent).
5. A banner shows the task, the agent and folder, who opened it and **Back to task** (plain text).
6. The gateway sends OpsAPI an HMAC-signed webhook when the session starts and ends:

   ```json
   {"event":"session_start","launch":"<id>","session_id":"<hex>","user":"alice","ts":1792600000,
    "exit_code":null,"reason":null}
   ```

   Header `X-Opsapi-Signature: sha256=<hex of HMAC-SHA256(secret, body)>`. Up to three tries.

Ticket format (made by OpsAPI): `base64url(json).hex(hmac_sha256(secret, base64url(json)))`, claims
`v` (1), `id`, `iat`, `exp`, `task`, `num`, `title`, `path`, `agent`, `prompt`, `by`, `return`, `ws`,
and optionally `login` `{email (≤ 254), user (UUID), stepup (unix seconds)}` and `report`
`{url (https, ≤ 512), token ([A-Za-z0-9_-]{32,128})}`. A malformed `login` or `report` makes the whole
link invalid. Claims the gateway doesn't know are ignored, so a newer OpsAPI works with an older gateway.
The OpsAPI side is documented in `docs/AI_RUNNER_WEB_TERMINAL.md` in the OpsAPI repository.

## Reporting the pull request

When the link has `report`, the shell gets `OPSAPI_REPORT_URL` and `OPSAPI_REPORT_TOKEN`. The prompt
OpsAPI writes asks the agent to call it once its pull request is open:

```sh
curl -fsS -X POST "$OPSAPI_REPORT_URL" -H "Authorization: Bearer $OPSAPI_REPORT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"pr_url":"https://github.com/o/r/pull/12"}'
```

The token can only attach pull requests and notes to its own task. The gateway never logs it.

## Keys issued in OpsAPI

Managers can give each person their own key from OpsAPI (AI Runs → Machines → Web terminals → People), so
nobody signs in as someone else and nobody needs to be added on this machine by hand. The key pair is made in
the manager's browser; OpsAPI keeps only the public half. The manager hands the person the key file and its
passphrase; they sign in here with it like any key.

```yaml
opsapi:
  keys:
    url: https://int-opsapi.workstation.co.uk/api/v2/ai-runner/public/terminal/keys
    terminal_id: "<this terminal's id in OpsAPI>"   # OpsAPI's config block has both lines
    interval_secs: 30
    max_stale_secs: 900
```

The gateway fetches the list now and every `interval_secs`. The request is signed with the shared secret
(`X-Opsapi-Signature: sha256=<hex HMAC of "keys\n<terminal id>\n<timestamp>">`, `X-Opsapi-Timestamp`,
`X-Opsapi-Terminal`), and the answer is only trusted when its own `X-Opsapi-Signature` (HMAC of the body)
checks out, it names this terminal, it is less than 5 minutes old and no older than the last list taken.
Then:

- OpsAPI keys get `local` access only, and are dropped at their expiry (90 days after issue).
- They never take over this machine's own `authorized_keys`: a user name or key that is in the file is
  ignored in the list, so the owner's account can't be claimed from OpsAPI.
- A key that leaves the list (blocked, expired, the person left the workspace) stops at once, and its
  sessions close within seconds, as with `sshweb keys revoke`.
- Without a good fetch for `max_stale_secs`, all OpsAPI keys stop working (fail closed); keys in the file
  keep working, so the owner can still sign in.
- Audit events: `opsapi_key_added`, `opsapi_key_removed` (user and fingerprint), `opsapi_keys_stale`;
  sign-ins as before (`auth_success` with the user and key fingerprint).
- Auto sign-in (below) finds these people by the email in the list, so they need no `autologin.users` line.
- Each entry is `{user, public_key, expires_unix, email?, name?}`. `name` (the person's name, one line,
  ≤ 120 characters) is optional; a bad one is left out and the key still works. Their shells get the email
  and name (see [Crediting each person](#crediting-each-person)).

## Auto sign-in for power users

Off by default. When it is on, OpsAPI may sign chosen people in with the task link itself, so a task
opens with one click. All of these must hold:

- OpsAPI: the terminal has auto sign-in turned on there, the person holds `ai_terminal_autologin`, and
  they confirmed an emailed code (a *step-up*) in the last 12 hours. Only then does OpsAPI add the
  `login` claim, and such a link lives 120 seconds.
- This gateway: `opsapi.autologin.enabled`, and the person's OpsAPI email is listed under `users` (or they
  have a key issued in OpsAPI, matched by its email),
  mapped to a terminal user who has an authorized key allowing `local`:

  ```yaml
  opsapi:
    autologin:
      enabled: true
      max_stepup_age_secs: 43200      # the step-up may be at most this old
      users:                          # OpsAPI email (any case) -> terminal user
        "alice@example.com": alice
  ```

The page sees a waiting link with `login` and, if nobody is signed in, calls

```
POST /api/launch/login
{"ticket": "<the #launch= ticket>"}
```

No login cookie is needed; the Origin is checked like every state-changing call, and the call is
rate-limited per IP and counted towards the same lock-out as SSH sign-in. The gateway verifies the
ticket exactly like `/api/launch`, then requires: `login` present; `exp - iat ≤ 120`; auto sign-in on;
the email mapped; the mapped user has a key allowing `local`; `stepup ≤ iat` and
`now - stepup ≤ max_stepup_age_secs`. Each launch id signs someone in **once**.

On success the answer is the same as an SSH sign-in, with the same session cookie:

```json
{"user": "alice", "access": "local", "expires_unix": 1792643200}
```

The login is made **through that user's key** (its fingerprint and access), so revoking or narrowing the
key ends it like any other. The audit log gets `auth_success` with `via=opsapi_launch`, `opsapi_email`,
`opsapi_user` and `opsapi_launch`; refusals are `auth_failure` with the reason. Then the page posts the
same ticket to `/api/launch` as usual.

Errors (`{"error": "<code>", "message": "…"}`):

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_link` | bad signature or fields, lifetime over 120 s, or `stepup` later than `iat` |
| 400 | `expired`, `not_configured`, `prompt_starts_with_dash` | as for `/api/launch` |
| 403 | `autologin_off` | `opsapi.autologin.enabled` is false (or local terminals are off); not counted towards lock-out |
| 403 | `autologin_not_allowed` | the link has no `login`, the email isn't mapped, or the mapped user has no key allowing `local` |
| 403 | `stepup_stale` | the step-up is older than `max_stepup_age_secs` |
| 409 | `already_used` | this link already signed someone in |
| 429 | `rate_limited`, `locked_out` | as for SSH sign-in |
| 503 | `auth_unavailable` | the authorized keys file is missing or invalid |
| 403 | `bad_origin` | the request came from another site |

On any error the page shows the normal SSH sign-in screen with the task still waiting and a one-line
reason.

What this still protects: a stolen OpsAPI password alone isn't a shell (it also needs the emailed code
within 12 hours and an email this gateway lists); a captured link is useless after 120 seconds or once
used; only people the gateway's owner listed can be signed in, and only as the terminal user they were
mapped to. What it gives up: for those people, OpsAPI (and their mailbox) now stands in for their SSH
key. List only people you'd hand a shell on this account to.

## Work log

Off by default. When it is on, this gateway tells OpsAPI what happens in each tab (one terminal
session), so managers can see who worked on what. **Tell employees in writing before turning it on**:
it keeps the text they give Claude and what their screen shows.

| What | Recorded |
|---|---|
| Tab (local and remote) | terminal user and key fingerprint, sign-in (`key` / `opsapi_launch`), IP, the task link if any, folder, agent, opened/closed, how it ended, exit code, active seconds (counted every 10 s when there was input or output in the last 60 s), bytes in/out, when the last keystroke came, whether a browser is connected |
| Claude Code (from its own OpenTelemetry) | each prompt's text (cut to 16 KiB), each model request (model, tokens, cost estimate, duration), tool results and decisions (tool, success, parameters cut to 8 KiB), API errors, lines added/removed, commits, pull requests. Codex, Cursor and plain shells send nothing here. |
| Screen (local tabs) | the tab's **output**, what the screen shows, as an [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/) recording (`o` and `r` events). **Keystrokes are never recorded**, but what the terminal echoes back is on screen (passwords at a no-echo prompt aren't). |

Claude's `user.email`, `user.account_uuid` and `organization.id` are dropped. OpsAPI keeps prompt and
tool text 90 days and recordings 30 days (its side: `docs/AI_RUNNER_WEB_TERMINAL.md` §11).

```yaml
opsapi:
  webhook_secret: "<from OpsAPI>"
  keys:
    terminal_id: "<this terminal's id in OpsAPI>"   # needed even without keys.url
  work_log:
    enabled: true
    url: https://int-opsapi.workstation.co.uk/api/v2/ai-runner/public/terminal
    otlp_port: 7683      # loopback-only receiver for Claude's telemetry
    record: true         # screen recordings of local tabs
    max_pending_mb: 2048 # recordings waiting for upload; over this, new parts are skipped
```

How it works:

- Each local tab's shell gets `SSHWEB_TAB_TOKEN` (32 random bytes, hex) and Claude's telemetry
  settings: `CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_LOGS_EXPORTER=otlp`, `OTEL_METRICS_EXPORTER=otlp`,
  `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`, `OTEL_EXPORTER_OTLP_{LOGS,METRICS}_ENDPOINT=http://127.0.0.1:<otlp_port>/v1/{logs,metrics}`,
  `OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <token>`, `OTEL_LOG_USER_PROMPTS=1`,
  `OTEL_LOG_TOOL_DETAILS=1`, `OTEL_LOGS_EXPORT_INTERVAL=5000`, `OTEL_METRIC_EXPORT_INTERVAL=30000`.
- The receiver listens on `127.0.0.1:<otlp_port>` only (plain HTTP, `POST /v1/logs` and
  `/v1/metrics`, JSON only, 4 MiB per post, loopback `Host` only). The token names the tab. A post
  without a live tab's token (Claude outside an sshweb tab, a forged or old token) is answered
  `200 {}` and discarded unread: nothing of it reaches OpsAPI, only how many there were is audited
  (`work_log_unattributed_dropped` with `count`, at most once a minute). A token stops working when its
  tab ends. Only the `user_prompt`, `api_request`, `api_error`, `tool_result` and `tool_decision` events and
  the `claude_code.{lines_of_code,commit,pull_request}.count` and `claude_code.active_time.total`
  metrics are kept.
- Every 10 s, when something is new, the gateway sends `POST {url}/activity` (`X-Opsapi-Terminal`,
  `X-Opsapi-Signature: sha256=<hex HMAC of the body>`): each tab at open, at close and once a minute while
  it is open, changed or not (a heartbeat: a tab not heard of for a few minutes went away with its
  gateway), and the new events. While OpsAPI can't be reached they wait in memory (up to 20 000 events,
  oldest dropped first) and are retried with backoff up to 5 minutes. A clean shutdown sends the tabs'
  final state.
- A tab's state, which OpsAPI upserts by `id`: `id`, `user`, `key`, `via`, `ip`, `launch`, `kind`, `cwd`,
  `agent`, `opened_at`, `closed_at`, `end_reason`, `exit_code`, `active_secs`, `input_bytes`,
  `output_bytes`, and from this version `last_input_at` (unix seconds of the tab's last keystroke or
  paste; `null` before the first) and `attached` (a browser is connected to the tab now; `false` once
  closed). Older gateways send neither, and later ones may add fields: ignore what you don't know.
- A recording part closes every 60 s or 1 MiB and when its tab ends, is gzipped to
  `<state_dir>/recordings/<tab>-<part>.cast.gz` (0600), sent as `POST {url}/recordings`
  (`X-Opsapi-Tab`, `X-Opsapi-Part`, `X-Opsapi-Final`, signature over `"<tab>\n<part>\n"` + body) and
  deleted once OpsAPI has it. Parts left by an earlier run are sent at start. Recording goes on while no
  browser is attached. While `max_pending_mb` of parts wait for upload, new parts are skipped (a gap in
  the tab's part numbers; a tab's last part is still sent, without its events, so the recording ends)
  until uploads make room.
- Audit events: `work_log_send_failed` (once per outage), `work_log_events_dropped` (with a count),
  `work_log_unattributed_dropped` (with a count), `work_log_recording_skipped` (with the tab, once per
  outage).

### Claude's managed settings

Someone in a tab can change its environment. On the shared account, install Claude Code's managed
settings as an administrator, so telemetry can't be switched off; their `otelHeadersHelper` reads the
tab's token:

```sh
sudo mkdir -p "/Library/Application Support/ClaudeCode" /usr/local/libexec
sudo install -o root -g wheel -m 644 packaging/claude-managed-settings.json \
  "/Library/Application Support/ClaudeCode/managed-settings.json"
sudo install -o root -g wheel -m 755 packaging/sshweb-otel-headers /usr/local/libexec/sshweb-otel-headers
```

If `otlp_port` isn't 7683, change the two endpoints in the file. The settings apply to **every** Claude
Code on this Mac. Outside an sshweb tab the helper sends no token, so that Claude's telemetry goes to
the loopback receiver and is discarded (or nowhere, when no gateway runs): other people's and the
owner's own prompts never reach OpsAPI. Still tell everyone who uses Claude on this Mac that its
telemetry is switched on machine-wide.

## A separate macOS account for task terminals

Every terminal runs as one macOS account. If that is the account `sshweb` itself runs as, anything typed
in a terminal (or run by an agent there) can read the gateway's config with its OpsAPI secret, its TLS key
and its audit log and pending work log, and so could fake task reports or edit the record. So the gateway
that employees use runs with **two accounts**:

- **`_sshweb`**, a hidden service account with no shell and no login: runs the gateway and alone can read
  its config (`root:_sshweb 640`), secret, TLS key and state (`_sshweb 700`: audit log, work-log queue,
  recordings, admin socket).
- **`workstation`**, a standard (non-admin) account: the terminals' shells run as it (`local.run_as:
  workstation`), with its own files, agent logins and GitHub access. It has no sudo and can't read the
  gateway's files.

Neither is an owner's account, so a task terminal can't read the owner's credentials either.

### Shells as another account

With `local.run_as`, sshweb starts each local shell with `sudo -n -H -u <account> -- <shell> …` and sends
signals with `sudo -n -u <account> -- /bin/kill …`. It needs the rule in
[packaging/sshweb.sudoers](../packaging/sshweb.sudoers) (account names adjusted). The rule:

- lets `_sshweb` act as `workstation` and nothing else: not as root, not as any other account. A shell
  can run anything, so listing only shells would not narrow it;
- makes sudo hand over to the shell without staying around as root (`!pam_session, !pam_setcred,
  !use_pty`), so the gateway can still stop it, and sets HOME to the account's (`always_set_home`);
- keeps only the terminal's variables (`env_keep`: `TERM`, locale, `OPSAPI_*`, `SSHWEB_*`, `OTEL_*`,
  `CLAUDE_CODE_*`). Task text and tokens never go on a command line.

`sshweb config validate` (run at every start too) checks all of it by running a test shell through sudo,
and names what's missing. The gateway still checks and enters tab folders itself, so give `_sshweb`
search access to the account's home: `chmod +a "user:_sshweb allow search" /Users/workstation`.

On the Mac, as an administrator (the OpsAPI setup kit does the same, with checks):

```sh
# 1. The shells' account: standard, not admin; nobody needs its password.
sudo sysadminctl -addUser workstation -fullName "Workstation agents" -password "$(openssl rand -base64 30)"
sudo mkdir -p /Users/workstation/projects && sudo chown workstation:staff /Users/workstation/projects

# 2. The gateway's account: hidden, no shell, no home, no password. Pick a free id below 500.
id=$(( $(dscl . -list /Users UniqueID | awk '$2<500 {print $2}' | sort -n | tail -1) + 1 ))
sudo dscl . -create /Groups/_sshweb PrimaryGroupID $id
sudo dscl . -create /Users/_sshweb UniqueID $id
sudo dscl . -create /Users/_sshweb PrimaryGroupID $id
sudo dscl . -create /Users/_sshweb UserShell /usr/bin/false
sudo dscl . -create /Users/_sshweb NFSHomeDirectory /var/empty
sudo dscl . -create /Users/_sshweb IsHidden 1
sudo chmod +a "user:_sshweb allow search" /Users/workstation

# 3. The sudo rule, checked before it goes in.
sudo visudo -cf packaging/sshweb.sudoers && sudo install -o root -g wheel -m 440 packaging/sshweb.sudoers /etc/sudoers.d/sshweb

# 4. Binary, config and state.
sudo install -o root -g wheel -m 755 target/release/sshweb /usr/local/bin/sshweb
sudo install -d -o root -g wheel -m 755 /usr/local/etc/sshweb
sudo install -d -o _sshweb -g _sshweb -m 700 /usr/local/var/sshweb /usr/local/var/sshweb/run
# config.yaml: root:_sshweb 640, with local.run_as: workstation, state_dir/audit under /usr/local/var/sshweb
sudo -u _sshweb /usr/local/bin/sshweb config validate --config /usr/local/etc/sshweb/config.yaml

# 5. Start it at boot without anyone logging in.
sudo cp packaging/com.sshweb.agents.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sshweb.agents.plist
```

Config for this instance: a different port from any other gateway (e.g. `7682`), the same
`server.trusted_proxies` and TLS approach as the existing one, `allowed_origins` = its public address,
`local.allowed_roots: [/Users/workstation/projects]`, `local.run_as: workstation`, and the `opsapi:` block
from OpsAPI. Use absolute paths: `~` means the gateway's home (`/var/empty`).

Then, as the shells' account (`sudo -iu workstation`):

- sign the agents in with accounts meant for this machine. Nobody logs in to this account's desktop,
  so its login keychain stays locked: tools that keep tokens in the keychain fail there. Use token files
  instead — e.g. `claude setup-token`, then put `export CLAUDE_CODE_OAUTH_TOKEN=…` in a file only this
  account can read (`chmod 600`) and source it from `~/.zprofile`; likewise `codex login` /
  `cursor-agent login` where they offer file storage;
- give it its own GitHub access (`gh auth login --insecure-storage` with a machine account or a
  fine-grained token limited to the repositories it works on), and `git config --global user.name/user.email`;
- clone the projects into `~/projects`.

People's keys come from OpsAPI (`opsapi.keys`) or `sudo sshweb keys add --config … --user <name> --access
local <key>.pub`. Admin commands talk to the running gateway as its account:
`sudo -u _sshweb sshweb sessions list --config /usr/local/etc/sshweb/config.yaml`.

Finally route a public name to it (reverse proxy → `https://<mac>:7682`, see "Behind a reverse proxy"
in the README) and enter that address in OpsAPI.

### Crediting each person

Everyone's shells run as `workstation`, so git would put that account's one `user.name`/`user.email` on
every commit. Each local tab's shell also gets who it is for:

| Variable | Value |
|---|---|
| `SSHWEB_USER` | The terminal user they signed in as |
| `SSHWEB_USER_EMAIL` | Their OpsAPI email (keys issued in OpsAPI) |
| `SSHWEB_USER_NAME` | Their name, when OpsAPI sends it with their key |

sudo keeps them (`SSHWEB_*` in `env_keep`). To credit the person in git, add this to the account's
`~/.zshenv`, which every zsh reads (`~/.bash_profile` too if people use bash):

```sh
# Commits made in an sshweb tab are credited to the person signed in there.
if [ -n "$SSHWEB_USER_EMAIL" ]; then
  export GIT_AUTHOR_EMAIL="$SSHWEB_USER_EMAIL" GIT_COMMITTER_EMAIL="$SSHWEB_USER_EMAIL"
fi
if [ -n "$SSHWEB_USER_NAME" ]; then
  export GIT_AUTHOR_NAME="$SSHWEB_USER_NAME" GIT_COMMITTER_NAME="$SSHWEB_USER_NAME"
fi
```

Without them (a key from `authorized_keys`, or an OpsAPI that sends no name) git uses the global
identity. This says who was signed in, not proof: anyone can change the variables in their own tab. Pushes
still go through the account's one GitHub login.

### Shells locked to their folder

`local.sandbox_profile: /usr/local/etc/sshweb/shell.sb` (macOS) runs every local shell inside a
sandbox (`sandbox-exec`) that everything started from it inherits and can't loosen. The profile in
[packaging/sshweb-shell.sb](../packaging/sshweb-shell.sb):

- **files:** under `/Users` only the shells' own account folder (the projects plus the tools'
  settings and caches); no other account's files, no `/Volumes`. What runs in everyone's sessions is
  read-only, so nobody can plant something there that runs when a colleague starts a shell or Claude:
  shell start-up files (`~/.zshrc` and friends, `~/.oh-my-zsh`, `~/.zsh`), the folders on PATH in the
  home (`~/bin`, `~/.local/bin`) and the Claude that `~/.local/bin/claude` points to
  (`~/.local/share/claude`), the agents' Claude and GitHub logins, git's identity, and what Claude loads
  for everyone: its user settings, `CLAUDE.md`, commands, agents, skills, plugins and hooks. Their folders
  (`~/.claude`, `~/.config`, `~/.local`) can't be moved aside and replaced by a link either. Claude keeps
  its own state as usual (`~/.claude.json`, `~/.claude/projects`, todos and the rest). It can't update
  itself from a tab: update it as the account, `sudo -iu workstation claude update`;
- **processes:** a shell can inspect (open files, folder, path) and signal only what was started in its own
  tab, not another person's shell or agent and not the gateway. Job control (Ctrl+Z, `bg`, `kill %1`) and
  Ctrl+C work as usual. `ps` and `top` don't run inside any sandbox (they are setuid); `pgrep` does;
- **network:** out on ports 443 and 80 only (GitHub over https, Claude, OpsAPI, package registries).
  Not the services on this Mac or the local network (databases, AI servers, dashboards, file and
  screen sharing), not ssh. On this Mac only the work log's receiver (`OTLP_PORT`) and a few usual
  dev-server ports (3000, 3001, 4173, 5173, 8000) a person starts in their own terminal.

A sandbox profile can't name address ranges, so hosts on the local network stay reachable on 443 and 80.
Block those with pf, for the shells' account only, e.g. `/etc/pf.anchors/sshweb`:

```
# The shells' account may not reach the local network.
block return out quick proto { tcp, udp } from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7, fe80::/10 } user workstation
```

Add `anchor "sshweb"` and `load anchor "sshweb" from "/etc/pf.anchors/sshweb"` to `/etc/pf.conf`, check
with `sudo pfctl -vnf /etc/pf.conf`, then `sudo pfctl -E -f /etc/pf.conf`. pf isn't on at boot unless a
LaunchDaemon turns it on, and macOS updates can restore `/etc/pf.conf`. Check from a tab:
`nc -z -G 2 <a host on the local network> 443` should fail. (This project's tests don't cover pf.)

sshweb passes `HOME` (the account's folder) and `OTLP_PORT` and starts
`sudo … sandbox-exec -f <profile> -D … <shell>`; each step hands over to the next, so the gateway still
stops the shell. `config validate` starts a test shell in it. Install the profile root-owned (0644).
Administrators set the account up (logins, repos, tools, Claude's commands and skills) outside the
sandbox: `sudo -u workstation -i`.

What this separates and what it doesn't: the gateway, its secret and its records from everything run in a
terminal (real), and the terminals from the owner's account (real). Between the people sharing
`workstation`, much is still shared, and separation there is by policy only:

- the projects: anyone can change anyone's code, including a repository's own agent set-up that runs when
  someone else works in it (`.claude/settings.json` hooks, `.claude/commands`, `.mcp.json`, `CLAUDE.md`,
  git hooks, package scripts);
- `~/.claude.json`, which Claude must be able to write. It also holds per-project MCP servers, which are
  commands Claude starts;
- what the tools keep: everyone's Claude conversations (`~/.claude/projects`) and shell history
  (`~/.zsh_history`);
- other tools installed in the home (nvm, npm's global folder, `~/.cargo/bin`, …): anyone can replace
  them. Install shared tools outside it (Homebrew owned by an administrator), or add their folders to the
  profile;
- command lines and environments: `pgrep -fl` lists everyone's commands (an agent's prompt included), and
  a program can read another process's environment, tab tokens and report tokens included. macOS doesn't
  let a sandbox stop that.

Real separation between people needs an account each. Their shells' terminal device belongs to `_sshweb`,
so the rare program that reopens its terminal by name (rather than `/dev/tty`) can't; ssh, git, editors and
agents don't.
