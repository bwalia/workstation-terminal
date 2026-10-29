# Browser authentication flow

sshweb authenticates browser users by **proof of possession of an SSH private key**, using the
OpenSSH signature format (`SSHSIG`, see OpenSSH `PROTOCOL.sshsig`). Private keys never reach the
browser or the gateway. The gateway stores public keys only.

## Why this design

- Browsers can't read `~/.ssh` or talk to ssh-agent, and WebCrypto can't use OpenSSH keys.
- A public key supplied by the browser proves nothing, so it's never accepted as a credential.
- `ssh-keygen -Y sign` (OpenSSH ≥ 8.1, standard on macOS) can sign arbitrary data with a key file,
  a passphrase-protected key (prompting locally), a FIDO `sk-` key or a key held in ssh-agent. Any of
  these yields a standard, verifiable signature, so no custom helper is required.

## Sequence

```
Browser                         Gateway                               User's terminal
   | POST /api/auth/challenge {user}   |                                      |
   |---------------------------------->| check rate limit / lockout           |
   |                                   | id, nonce ← CSPRNG; store {user,     |
   |                                   |   origin, H(binding), expiry}        |
   |<-- {challenge_id, message} + Set-Cookie: sshweb_pre=<binding> (HttpOnly) |
   |   shows: printf '%s' '<message>' | ssh-keygen -Y sign -n sshweb-auth -f KEY
   |                                   |                       ------------->|
   |                                   |      -----BEGIN SSH SIGNATURE-----  |
   | POST /api/auth/verify {challenge_id, signature} (cookie: binding)        |
   |---------------------------------->| take(challenge_id)  (single use)     |
   |                                   | expiry? binding matches (ct-eq)?     |
   |                                   | lockout? keys file valid?            |
   |                                   | sig.namespace == "sshweb-auth"?      |
   |                                   | sig.pubkey ∈ authorized keys of user?|
   |                                   | verify(sig, message from server state)
   |<-- Set-Cookie: sshweb_session=<256-bit token>; HttpOnly; SameSite=Strict |
```

The message is a single line:

```
sshweb-auth-v1 origin=<scheme://host:port> user=<user> challenge=<id> nonce=<256-bit b64url> expires=<unix>
```

The server never parses the message back from the client; it verifies against the copy it stored.

## Properties

| Property | Mechanism |
|---|---|
| Possession of the private key | SSHSIG verification against the authorised public key |
| Freshness | 256-bit random nonce and a 120 s default expiry (`auth.challenge_ttl_secs`) |
| Single use and no replay | The challenge is removed on the first verification attempt, even a failed one |
| Bound to the intended identity | The user is fixed at issue time, and the key must be listed for that user |
| Bound to the requesting browser/session | HttpOnly binding cookie (HTTP flow) or the socket's binding secret (WebSocket flow) |
| Domain separation | Namespace `sshweb-auth` and the `sshweb-auth-v1` message prefix |
| No user enumeration | Unknown users still get a challenge, and failures return a generic error |
| Brute-force resistance | Per-IP challenge rate limit and per-IP lockouts. User names aren't locked: signatures can't be guessed, and anyone could lock a named person out |
| Audit | `auth_challenge`, `auth_success`, `auth_failure` (with reason), `auth_lockout` |

## WebSocket variant

Non-browser clients can run the same exchange over `/ws` (`auth_request` → `auth_challenge` →
`auth_response` → `auth_ok`). The challenge is bound to that connection's random binding secret, and
the resulting login is used only by that socket (no cookie is issued). See [PROTOCOL.md](PROTOCOL.md).

## Signing options for users

**In the page (the default).** Pick the key file and type its passphrase. `web/keysign.js` opens the
OpenSSH key in the browser (unencrypted, or `bcrypt` + `aes256-ctr` as `ssh-keygen -N` writes it; Ed25519
only) and makes the same SSHSIG signature `ssh-keygen -Y sign` would, over the message the challenge
gave. Only the signature is sent. The trade-off: the key is opened by JavaScript this gateway served, so a
page at another origin that someone is tricked into using could take the key and passphrase. Keep the
manager-issued keys short-lived (OpsAPI: 90 days, blockable at once), and use a command below where that
matters. A link may name the user (`/?user=alice`) so people only pick the file.

**With a command:**

```sh
# Key file (prompts locally if passphrase-protected):
printf '%s' 'MESSAGE' | ssh-keygen -Y sign -n sshweb-auth -f ~/.ssh/id_ed25519 | pbcopy
# Key in ssh-agent / hardware token: point -f at the public key
printf '%s' 'MESSAGE' | ssh-keygen -Y sign -n sshweb-auth -f ~/.ssh/id_ed25519.pub | pbcopy
# Helper bundled in the binary (runs ssh-keygen with separated arguments):
sshweb sign -f ~/.ssh/id_ed25519 'MESSAGE' | pbcopy
```

Supported key types for login: Ed25519, ECDSA P-256/384/521, RSA ≥ 2048 bits (RSA signatures use
`rsa-sha2-256/512`, as produced by `ssh-keygen -Y sign`). FIDO `sk-` key types aren't accepted
in `authorized_keys` yet.

## Limitation: relay phishing

Unlike WebAuthn, the browser doesn't attest the page origin to the signer. A malicious site could
fetch a genuine challenge from the gateway and ask the victim to sign it. The origin is part of the
signed text, so users should check it, and `sshweb sign` prints it before signing. Keeping the
gateway on loopback or a VPN and the short challenge lifetime limit exposure.

## Resuming sessions and restoring tabs

Resuming never bypasses key authentication:

- A browser login is a cookie with an 8 h absolute and 30 min idle lifetime. Typing in a terminal and using
  the page count as activity; the page's own background refresh of the session list (`X-Sshweb-Poll: 1`)
  and terminal output don't, so a page left open still goes idle. While it's valid, reopening
  the page restores your tabs without a new signature.
- Once it has expired, you sign a new challenge exactly as above. There is no long-lived "remember me"
  token, and saved tabs and detached shells are only reachable through a fresh login.
- Shells keep running while detached for `sessions.detach_grace_secs` (default 30 min), independent of the
  browser login. After a new login, the **same user** can re-attach them. Each attach re-binds the session
  to the new login and key, so later revocation of either applies.
- Every session is tied to the fingerprint of the key that owns it. Removing or revoking that key, or
  narrowing its `access`, closes the session within about 5 s, whether or not a browser is attached or a
  login still exists.
- The saved tab list holds only targets, names and session ids. It contains no credentials and is stored
  per user (`<state_dir>/workspaces/<user>.json`, mode 0600, directory 0700).
