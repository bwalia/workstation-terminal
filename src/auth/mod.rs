//! Authentication and authorisation service.

pub mod challenge;
pub mod keys;
pub mod sessions;

use std::sync::Arc;
use std::time::Duration;

use crate::audit::{Audit, AuditEvent};
use crate::config::Config;
use crate::metrics::Metrics;
use crate::security::rate_limit::{FailureTracker, RateLimiter};
use challenge::{Challenge, ChallengeError, ChallengeStore, VerifyError};
use keys::KeyStore;
use sessions::{Login, LoginState, LoginStore};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("too many requests; try again later")]
    RateLimited,
    #[error("temporarily locked out after repeated failures; try again in {0} seconds")]
    LockedOut(u64),
    #[error("invalid user name")]
    InvalidUser,
    #[error("authentication failed")]
    Challenge(#[from] ChallengeError),
    #[error("authentication failed")]
    Verify(#[from] VerifyError),
    #[error("authentication is unavailable: the authorized keys file is missing or invalid")]
    KeysUnavailable,
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::RateLimited => "rate_limited",
            AuthError::LockedOut(_) => "locked_out",
            AuthError::InvalidUser => "invalid_user",
            AuthError::Challenge(_) | AuthError::Verify(_) => "auth_failed",
            AuthError::KeysUnavailable => "auth_unavailable",
        }
    }
}

pub struct AuthService {
    pub keys: KeyStore,
    pub challenges: ChallengeStore,
    pub logins: LoginStore,
    challenge_rl: RateLimiter,
    failures: FailureTracker,
    audit: Arc<Audit>,
    metrics: Arc<Metrics>,
}

impl AuthService {
    pub fn new(cfg: &Config, audit: Arc<Audit>, metrics: Arc<Metrics>) -> Self {
        let rl = &cfg.rate_limit;
        Self {
            keys: KeyStore::new(cfg.auth.authorized_keys.clone(), cfg.auth.min_rsa_bits)
                .with_max_stale(cfg.opsapi.keys.max_stale_secs),
            challenges: ChallengeStore::new(Duration::from_secs(cfg.auth.challenge_ttl_secs)),
            logins: LoginStore::new(
                Duration::from_secs(cfg.auth.session_ttl_secs),
                Duration::from_secs(cfg.auth.session_idle_timeout_secs),
            ),
            challenge_rl: RateLimiter::new(rl.challenges_per_minute, Duration::from_secs(60)),
            failures: FailureTracker::new(
                rl.max_failures,
                Duration::from_secs(rl.failure_window_secs),
                Duration::from_secs(rl.lockout_secs),
            ),
            audit,
            metrics,
        }
    }

    /// Is this IP locked out after repeated failures? Only IPs are: a user name isn't, so nobody
    /// can lock a named person out by sending bad signatures for them (which can't be guessed
    /// anyway).
    pub fn check_lockout(&self, ip: &str) -> Result<(), AuthError> {
        match self.failures.locked(&format!("ip:{ip}")) {
            Some(rem) => Err(AuthError::LockedOut(rem.as_secs().max(1))),
            None => Ok(()),
        }
    }

    /// Issue a challenge. Unknown users get a challenge too, so user names cannot be probed.
    pub fn issue_challenge(
        &self,
        user: &str,
        origin: &str,
        binding: &str,
        ip: &str,
    ) -> Result<Challenge, AuthError> {
        if !keys::valid_user(user) {
            return Err(AuthError::InvalidUser);
        }
        if !self.challenge_rl.check(&format!("ip:{ip}")) {
            self.audit
                .log(AuditEvent::new("auth_rate_limited").ip(ip).user(user));
            return Err(AuthError::RateLimited);
        }
        self.check_lockout(ip)?;
        let ch = self.challenges.issue(user, origin, binding).map_err(|e| {
            if e == ChallengeError::Capacity {
                AuthError::RateLimited
            } else {
                e.into()
            }
        })?;
        self.metrics.inc(&self.metrics.challenges_issued);
        self.audit.log(
            AuditEvent::new("auth_challenge")
                .ip(ip)
                .user(user)
                .field("challenge_id", &ch.id),
        );
        Ok(ch)
    }

    /// Verify a signed challenge and create a login.
    pub fn verify(
        &self,
        challenge_id: &str,
        signature: &str,
        binding: &str,
        ip: &str,
        via: &'static str,
    ) -> Result<(String, Login), AuthError> {
        self.check_lockout(ip)?;
        let result = self.verify_inner(challenge_id, signature, binding, ip, via);
        match &result {
            Ok((_, login)) => self.record_sign_in(login, ip, via, &[]),
            Err((user, e)) => {
                self.record_failed_sign_in(ip, user.as_deref(), &format!("{:?}", e), via, &[])
            }
        }
        result.map_err(|(_, e)| e)
    }

    /// Admit a sign-in attempt that doesn't start with a challenge (an OpsAPI link): the same
    /// per-IP rate limit as challenges, and the IP must not be locked out.
    pub fn admit(&self, ip: &str) -> Result<(), AuthError> {
        if !self.challenge_rl.check(&format!("ip:{ip}")) {
            self.audit.log(AuditEvent::new("auth_rate_limited").ip(ip));
            return Err(AuthError::RateLimited);
        }
        self.check_lockout(ip)
    }

    /// Sign `key`'s user in without a challenge (the caller has proved who they are another
    /// way), recorded exactly like a key sign-in. Revoking the key ends the login.
    pub fn sign_in_with_key(
        &self,
        key: &keys::AuthorizedKey,
        ip: &str,
        via: &'static str,
        extra: &[(&str, &str)],
    ) -> Result<(String, Login), AuthError> {
        self.check_lockout(ip)?;
        let (token, login) =
            self.logins
                .create(&key.user, &key.fingerprint, key.access.clone(), ip, via);
        self.record_sign_in(&login, ip, via, extra);
        Ok((token, login))
    }

    fn record_sign_in(&self, login: &Login, ip: &str, via: &str, extra: &[(&str, &str)]) {
        self.failures.record_success(&format!("ip:{ip}"));
        self.metrics.inc(&self.metrics.auth_success);
        let mut ev = AuditEvent::new("auth_success")
            .ip(ip)
            .user(&login.user)
            .field("key", &login.key_fingerprint)
            .field("login_id", &login.id)
            .field("via", via);
        for (k, v) in extra {
            ev = ev.field(k, v);
        }
        self.audit.log(ev);
    }

    /// Audit a failed sign-in and count it towards the IP's lock-out.
    pub fn record_failed_sign_in(
        &self,
        ip: &str,
        user: Option<&str>,
        reason: &str,
        via: &str,
        extra: &[(&str, &str)],
    ) {
        self.metrics.inc(&self.metrics.auth_failure);
        let mut ev = AuditEvent::new("auth_failure")
            .ip(ip)
            .field("reason", reason)
            .field("via", via);
        if let Some(u) = user {
            ev = ev.user(u);
        }
        for (k, v) in extra {
            ev = ev.field(k, v);
        }
        self.audit.log(ev);
        if self.failures.record_failure(&format!("ip:{ip}")) {
            self.metrics.inc(&self.metrics.auth_lockouts);
            let mut ev = AuditEvent::new("auth_lockout").ip(ip);
            if let Some(u) = user {
                ev = ev.user(u);
            }
            self.audit.log(ev);
        }
    }

    fn verify_inner(
        &self,
        challenge_id: &str,
        signature: &str,
        binding: &str,
        ip: &str,
        via: &'static str,
    ) -> Result<(String, Login), (Option<String>, AuthError)> {
        let ch = self
            .challenges
            .take(challenge_id, binding)
            .map_err(|e| (None, e.into()))?;
        let user = Some(ch.user.clone());
        let keys = self
            .keys
            .current()
            .map_err(|_| (user.clone(), AuthError::KeysUnavailable))?;
        let key = challenge::verify_signature(&keys, &ch.user, &ch.message, signature)
            .map_err(|e| (user.clone(), e.into()))?;
        Ok(self
            .logins
            .create(&ch.user, &key.fingerprint, key.access.clone(), ip, via))
    }

    /// Validate a bearer token: expiry, idle timeout and that the key is still authorised.
    /// Access rights are refreshed from the authorisation file.
    pub fn validate(&self, token: &str) -> Option<Login> {
        self.validate_with(token, true)
    }

    /// Like [`validate`](Self::validate) but without refreshing the idle timer; used for
    /// periodic background checks so an idle open tab does not keep a login alive.
    pub fn check_still_valid(&self, token: &str) -> bool {
        self.validate_quietly(token).is_some()
    }

    /// [`validate`](Self::validate) for a background poll: the login, without counting the
    /// request as activity.
    pub fn validate_quietly(&self, token: &str) -> Option<Login> {
        self.validate_with(token, false)
    }

    fn validate_with(&self, token: &str, touch: bool) -> Option<Login> {
        match self.logins.check(token, touch) {
            LoginState::Valid(mut login) => {
                if self.revalidate(&mut login) {
                    Some(login)
                } else {
                    self.logins.revoke_token(token);
                    self.audit.log(
                        AuditEvent::new("login_revoked")
                            .user(&login.user)
                            .field("login_id", &login.id)
                            .field("reason", "key no longer authorised"),
                    );
                    None
                }
            }
            LoginState::Expired | LoginState::Idle => None,
            LoginState::Unknown => None,
        }
    }

    /// Re-check a login against the current authorisation file; updates access in place.
    pub fn revalidate(&self, login: &mut Login) -> bool {
        match self.keys.current() {
            Ok(keys) => match keys.by_fingerprint(&login.key_fingerprint) {
                Some(k) if k.user == login.user => {
                    if k.access != login.access {
                        login.access = k.access.clone();
                        self.logins.update_access(&login.id, k.access.clone());
                    }
                    true
                }
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// Revoke logins whose key was removed from the authorisation file. Returns revoked ids.
    pub fn sweep_revoked_keys(&self) -> Vec<String> {
        let keys = self.keys.current().ok();
        let gone = self.logins.revoke_where(|l| match &keys {
            Some(k) => !matches!(k.by_fingerprint(&l.key_fingerprint), Some(x) if x.user == l.user),
            None => true,
        });
        for l in &gone {
            self.audit.log(
                AuditEvent::new("login_revoked")
                    .user(&l.user)
                    .field("login_id", &l.id)
                    .field("reason", "key no longer authorised"),
            );
        }
        gone.into_iter().map(|l| l.id).collect()
    }

    pub fn purge(&self) {
        self.challenges.purge();
        self.challenge_rl.purge();
        self.failures.purge();
        for l in self.logins.purge() {
            self.audit.log(
                AuditEvent::new("login_expired")
                    .user(&l.user)
                    .field("login_id", &l.id),
            );
        }
    }
}
