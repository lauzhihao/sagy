//! Typed, deterministic account-health observations and reduction.
//!
//! Health is deliberately represented as a small closed vocabulary.  Probe
//! implementations may have richer diagnostics, but state persistence must
//! never contain arbitrary endpoint/error text or a stale legacy status.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const PROBE_TTL_SECS: i64 = 300;
pub const TRANSIENT_BACKOFF_SECS: i64 = 30;
pub const DEFAULT_RETRY_SECS: i64 = 300;
pub const MIN_RETRY_SECS: i64 = 30;
pub const MAX_RETRY_SECS: i64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    #[default]
    Unverified,
    Ready,
    RefreshRequired,
    RateLimited,
    AuthInvalid,
    PermissionDenied,
    InvalidCredential,
    TransientFailure,
}

impl HealthStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "Unverified",
            Self::Ready => "Ready",
            Self::RefreshRequired => "RefreshRequired",
            Self::RateLimited => "RateLimited",
            Self::AuthInvalid => "AuthInvalid",
            Self::PermissionDenied => "PermissionDenied",
            Self::InvalidCredential => "InvalidCredential",
            Self::TransientFailure => "TransientFailure",
        }
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A closed set of probe failure classes.  It intentionally carries no
/// endpoint response body, token, URL, or arbitrary error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthErrorKind {
    Unauthorized,
    PermissionDenied,
    RateLimited,
    ServerFailure,
    Timeout,
    Network,
    InvalidJwt,
    VertexSigning,
    InvalidCredential,
    Unknown,
}

impl HealthErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "Unauthorized",
            Self::PermissionDenied => "PermissionDenied",
            Self::RateLimited => "RateLimited",
            Self::ServerFailure => "ServerFailure",
            Self::Timeout => "Timeout",
            Self::Network => "Network",
            Self::InvalidJwt => "InvalidJwt",
            Self::VertexSigning => "VertexSigning",
            Self::InvalidCredential => "InvalidCredential",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for HealthErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeSubject {
    RawToken,
    AuthorizedUser,
    ApiKey,
    Vertex,
}

/// Typed result emitted by a probe.  The explicit 200/401 raw-vs-authorized
/// forms make the reducer's auth semantics testable without inspecting a
/// response body.  Generic forms are retained for adapters that determine
/// the subject dynamically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Http200Raw,
    Http200Authorized,
    Http200ApiKey,
    Http200Vertex,
    Http401Raw,
    Http401Authorized,
    Http401ApiKey,
    Http401Vertex,
    Http403 {
        subject: ProbeSubject,
    },
    Http429 {
        subject: ProbeSubject,
        retry_after_secs: Option<i64>,
    },
    Http5xx {
        subject: ProbeSubject,
        status: u16,
    },
    Timeout {
        subject: ProbeSubject,
    },
    Network {
        subject: ProbeSubject,
    },
    InvalidJwt,
    VertexSigning,
    InvalidCredential,
    Http200 {
        subject: ProbeSubject,
    },
    Http401 {
        subject: ProbeSubject,
    },
    Http500 {
        subject: ProbeSubject,
    },
    OtherTransient,
}

pub type ProbeObservation = ProbeOutcome;

impl ProbeOutcome {
    pub const fn http_200_raw() -> Self {
        Self::Http200Raw
    }

    pub const fn http_200_authorized() -> Self {
        Self::Http200Authorized
    }

    pub const fn http_401_raw() -> Self {
        Self::Http401Raw
    }

    pub const fn http_401_authorized() -> Self {
        Self::Http401Authorized
    }

    pub const fn http_200(subject: ProbeSubject) -> Self {
        Self::Http200 { subject }
    }

    pub const fn http_401(subject: ProbeSubject) -> Self {
        Self::Http401 { subject }
    }

    pub const fn http_403(subject: ProbeSubject) -> Self {
        Self::Http403 { subject }
    }

    pub const fn http_429(subject: ProbeSubject, retry_after_secs: Option<i64>) -> Self {
        Self::Http429 {
            subject,
            retry_after_secs,
        }
    }

    pub const fn http_5xx(subject: ProbeSubject, status: u16) -> Self {
        Self::Http5xx { subject, status }
    }

    pub const fn timeout(subject: ProbeSubject) -> Self {
        Self::Timeout { subject }
    }

    pub const fn network(subject: ProbeSubject) -> Self {
        Self::Network { subject }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cooldown {
    pub started_at: i64,
    pub until: i64,
    pub last_evidence_at: i64,
}

impl Cooldown {
    pub fn new(started_at: i64, retry_after_secs: Option<i64>) -> Self {
        let retry = clamp_retry_after(retry_after_secs);
        Self {
            started_at,
            until: started_at.saturating_add(retry),
            last_evidence_at: started_at,
        }
    }

    pub fn is_active(&self, now: i64) -> bool {
        self.until > now
    }

    /// Normalize persisted timestamps at the observation boundary.  A clock
    /// rollback or malformed interval is treated as one fresh bounded window
    /// rather than allowing an unbounded/future cooldown to suppress probes.
    pub fn normalize(self, now: i64) -> Option<Self> {
        if self.until <= now {
            return None;
        }
        if self.started_at > now
            || self.last_evidence_at > now
            || self.until <= self.started_at
            || self.until.saturating_sub(self.started_at) > MAX_RETRY_SECS
        {
            return Some(Self::new(now, None));
        }
        Some(Self {
            started_at: self.started_at,
            until: self.until,
            last_evidence_at: self.last_evidence_at.max(self.started_at).min(now),
        })
    }
}

pub fn clamp_retry_after(retry_after_secs: Option<i64>) -> i64 {
    retry_after_secs
        .unwrap_or(DEFAULT_RETRY_SECS)
        .clamp(MIN_RETRY_SECS, MAX_RETRY_SECS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeDecision {
    UseCached,
    Probe,
    SkipCooldown,
}

impl ProbeDecision {
    pub const fn should_probe(self) -> bool {
        matches!(self, Self::Probe)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsageSnapshot {
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub health: HealthStatus,
    #[serde(default)]
    pub cooldown: Option<Cooldown>,
    #[serde(default)]
    pub remaining_quota_percent: Option<u8>,
    #[serde(default)]
    pub last_probe_at: Option<i64>,
    #[serde(default)]
    pub last_success_at: Option<i64>,
    #[serde(default)]
    pub last_rate_limit_at: Option<i64>,
    #[serde(default)]
    pub last_error: Option<HealthErrorKind>,
}

impl Default for UsageSnapshot {
    fn default() -> Self {
        Self {
            plan: None,
            health: HealthStatus::Unverified,
            cooldown: None,
            remaining_quota_percent: None,
            last_probe_at: None,
            last_success_at: None,
            last_rate_limit_at: None,
            last_error: None,
        }
    }
}

impl UsageSnapshot {
    pub fn is_in_cooldown(&self, now: i64) -> bool {
        self.cooldown
            .as_ref()
            .and_then(|cooldown| cooldown.normalize(now))
            .is_some_and(|cooldown| cooldown.is_active(now))
    }

    pub fn cooldown_until(&self) -> Option<i64> {
        self.cooldown.as_ref().map(|cooldown| cooldown.until)
    }

    pub fn needs_relogin(&self) -> bool {
        matches!(
            self.health,
            HealthStatus::AuthInvalid
                | HealthStatus::PermissionDenied
                | HealthStatus::InvalidCredential
        )
    }

    pub fn is_healthy(&self, now: i64) -> bool {
        if self.is_in_cooldown(now) || self.remaining_quota_percent == Some(0) {
            return false;
        }
        matches!(
            self.health,
            HealthStatus::Ready | HealthStatus::RefreshRequired
        )
    }

    pub fn is_eligible(&self, now: i64) -> bool {
        self.is_healthy(now)
    }

    fn normalized_for(&self, now: i64) -> Self {
        let mut next = self.clone();
        if let Some(quota) = next.remaining_quota_percent.as_mut() {
            *quota = (*quota).min(100);
        }
        let prior_cooldown = next.cooldown.take();
        let had_cooldown = prior_cooldown.is_some();
        next.cooldown = prior_cooldown.and_then(|cooldown| cooldown.normalize(now));
        if had_cooldown
            && next.cooldown.is_none()
            && matches!(next.health, HealthStatus::RateLimited)
        {
            // A rate-limit window is no longer evidence once it expires.  The
            // next decision/probe must establish health again from scratch.
            next.health = HealthStatus::Unverified;
            next.remaining_quota_percent = None;
            next.last_error = None;
        }
        // A future probe/success/rate-limit timestamp is a cache miss.  This
        // also handles a wall-clock rollback without retaining stale success.
        if next.last_probe_at.is_some_and(|value| value > now) {
            next.last_probe_at = None;
        }
        if next.last_success_at.is_some_and(|value| value > now) {
            next.last_success_at = None;
        }
        if next.last_rate_limit_at.is_some_and(|value| value > now) {
            next.last_rate_limit_at = None;
        }
        next
    }
}

/// Decide whether a probe can use the existing cache.  An active cooldown is
/// authoritative: `force` may bypass the normal TTL, but never this guard.
pub fn probe_decision(previous: &UsageSnapshot, now: i64, force: bool) -> ProbeDecision {
    let normalized = previous.normalized_for(now);
    if normalized.is_in_cooldown(now) {
        return ProbeDecision::SkipCooldown;
    }
    if force {
        return ProbeDecision::Probe;
    }
    if matches!(normalized.health, HealthStatus::Unverified) {
        return ProbeDecision::Probe;
    }
    let Some(last_probe) = normalized.last_probe_at else {
        return ProbeDecision::Probe;
    };
    if last_probe > now {
        return ProbeDecision::Probe;
    }
    let age = now.saturating_sub(last_probe);
    let window = if matches!(normalized.health, HealthStatus::TransientFailure) {
        TRANSIENT_BACKOFF_SECS
    } else {
        PROBE_TTL_SECS
    };
    if age < window {
        ProbeDecision::UseCached
    } else {
        ProbeDecision::Probe
    }
}

/// Reduce one typed observation into a durable snapshot.  All wall-clock
/// input is explicit, which makes repeated 429s, rollback, and overflow
/// behavior deterministic in tests.
pub fn reduce_usage<O>(previous: &UsageSnapshot, observation: O, now: i64) -> UsageSnapshot
where
    O: AsRef<ProbeOutcome>,
{
    reduce_usage_observed(previous, observation, now, now)
}

/// Reduce an observation captured earlier and merged at `now` after a CAS
/// retry. Older observations never overwrite a newer probe, and an
/// already-expired delayed 429 cannot start a fresh cooldown window. Equal
/// second-resolution timestamps are applied in exact-CAS order so a fast child
/// failure cannot be discarded merely because the preceding probe completed
/// in the same second.
pub fn reduce_usage_observed<O>(
    previous: &UsageSnapshot,
    observation: O,
    observed_at: i64,
    now: i64,
) -> UsageSnapshot
where
    O: AsRef<ProbeOutcome>,
{
    let mut next = previous.normalized_for(now);
    let observed_at = observed_at.min(now);
    if previous
        .last_probe_at
        .is_some_and(|last_probe| last_probe > observed_at)
    {
        return next;
    }
    next.last_probe_at = Some(observed_at);

    let outcome = observation.as_ref();
    match outcome {
        ProbeOutcome::Http200Raw
        | ProbeOutcome::Http200Authorized
        | ProbeOutcome::Http200ApiKey
        | ProbeOutcome::Http200Vertex
        | ProbeOutcome::Http200 { .. } => {
            next.health = HealthStatus::Ready;
            next.cooldown = None;
            next.last_error = None;
            next.last_success_at = Some(observed_at);
            // 成功的鉴权探测不能证明配额为 100%；只有解析到可信配额字段的适配器
            // 才能单独提供配额观察值。
            next.remaining_quota_percent = None;
        }
        ProbeOutcome::Http401Raw => apply_error(
            &mut next,
            HealthStatus::AuthInvalid,
            HealthErrorKind::Unauthorized,
            observed_at,
            now,
        ),
        ProbeOutcome::Http401Authorized => apply_error(
            &mut next,
            HealthStatus::RefreshRequired,
            HealthErrorKind::Unauthorized,
            observed_at,
            now,
        ),
        ProbeOutcome::Http401ApiKey | ProbeOutcome::Http401Vertex => apply_error(
            &mut next,
            HealthStatus::AuthInvalid,
            HealthErrorKind::Unauthorized,
            observed_at,
            now,
        ),
        ProbeOutcome::Http401 { subject } => {
            let status = if matches!(subject, ProbeSubject::AuthorizedUser) {
                HealthStatus::RefreshRequired
            } else {
                HealthStatus::AuthInvalid
            };
            apply_error(
                &mut next,
                status,
                HealthErrorKind::Unauthorized,
                observed_at,
                now,
            );
        }
        ProbeOutcome::Http403 { .. } => apply_error(
            &mut next,
            HealthStatus::PermissionDenied,
            HealthErrorKind::PermissionDenied,
            observed_at,
            now,
        ),
        ProbeOutcome::Http429 {
            retry_after_secs, ..
        } => {
            next.health = HealthStatus::RateLimited;
            // cooldown 本身已经使账号不可选；把未知配额写成 0 会在 cooldown
            // 结束后继续永久禁用账号。
            next.remaining_quota_percent = None;
            next.last_error = Some(HealthErrorKind::RateLimited);
            next.last_rate_limit_at = Some(observed_at);
            next.cooldown = match next.cooldown.take() {
                Some(mut cooldown) if cooldown.is_active(now) => {
                    cooldown.last_evidence_at = cooldown.last_evidence_at.max(observed_at);
                    Some(cooldown)
                }
                _ => {
                    let cooldown = Cooldown::new(observed_at, *retry_after_secs);
                    (cooldown.until > now).then_some(cooldown)
                }
            };
            if next.cooldown.is_none() {
                next.health = HealthStatus::Unverified;
                next.last_error = None;
            }
        }
        ProbeOutcome::Http5xx { .. }
        | ProbeOutcome::Http500 { .. }
        | ProbeOutcome::OtherTransient => apply_error(
            &mut next,
            HealthStatus::TransientFailure,
            HealthErrorKind::ServerFailure,
            observed_at,
            now,
        ),
        ProbeOutcome::Timeout { .. } => apply_error(
            &mut next,
            HealthStatus::TransientFailure,
            HealthErrorKind::Timeout,
            observed_at,
            now,
        ),
        ProbeOutcome::Network { .. } => apply_error(
            &mut next,
            HealthStatus::TransientFailure,
            HealthErrorKind::Network,
            observed_at,
            now,
        ),
        ProbeOutcome::InvalidJwt => apply_error(
            &mut next,
            HealthStatus::InvalidCredential,
            HealthErrorKind::InvalidJwt,
            observed_at,
            now,
        ),
        ProbeOutcome::VertexSigning => apply_error(
            &mut next,
            HealthStatus::InvalidCredential,
            HealthErrorKind::VertexSigning,
            observed_at,
            now,
        ),
        ProbeOutcome::InvalidCredential => apply_error(
            &mut next,
            HealthStatus::InvalidCredential,
            HealthErrorKind::InvalidCredential,
            observed_at,
            now,
        ),
    }
    next
}

fn apply_error(
    usage: &mut UsageSnapshot,
    health: HealthStatus,
    error: HealthErrorKind,
    _observed_at: i64,
    now: i64,
) {
    usage.health = health;
    usage.cooldown = usage
        .cooldown
        .take()
        .filter(|cooldown| cooldown.is_active(now));
    usage.remaining_quota_percent = None;
    usage.last_error = Some(error);
}

impl AsRef<ProbeOutcome> for ProbeOutcome {
    fn as_ref(&self) -> &ProbeOutcome {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> UsageSnapshot {
        UsageSnapshot {
            health: HealthStatus::Ready,
            remaining_quota_percent: Some(100),
            last_probe_at: Some(100),
            last_success_at: Some(100),
            ..Default::default()
        }
    }

    #[test]
    fn status_matrix_maps_auth_subjects() {
        let raw = reduce_usage(&ready(), ProbeOutcome::Http401Raw, 200);
        assert_eq!(raw.health, HealthStatus::AuthInvalid);
        assert_eq!(raw.last_error, Some(HealthErrorKind::Unauthorized));
        assert_eq!(raw.remaining_quota_percent, None);

        let authorized = reduce_usage(&ready(), ProbeOutcome::Http401Authorized, 200);
        assert_eq!(authorized.health, HealthStatus::RefreshRequired);

        let denied = reduce_usage(
            &ready(),
            ProbeOutcome::Http403 {
                subject: ProbeSubject::AuthorizedUser,
            },
            200,
        );
        assert_eq!(denied.health, HealthStatus::PermissionDenied);
    }

    #[test]
    fn repeated_rate_limit_preserves_original_until() {
        let first = reduce_usage(
            &ready(),
            ProbeOutcome::Http429 {
                subject: ProbeSubject::ApiKey,
                retry_after_secs: Some(60),
            },
            200,
        );
        let second = reduce_usage(
            &first,
            ProbeOutcome::Http429 {
                subject: ProbeSubject::ApiKey,
                retry_after_secs: Some(3600),
            },
            210,
        );
        assert_eq!(second.cooldown.as_ref().unwrap().until, 260);
        assert_eq!(second.cooldown.as_ref().unwrap().last_evidence_at, 210);
    }

    #[test]
    fn delayed_observation_does_not_overwrite_newer_health_or_restart_cooldown() {
        let newer = UsageSnapshot {
            health: HealthStatus::Ready,
            last_probe_at: Some(500),
            last_success_at: Some(500),
            ..Default::default()
        };
        let ignored = reduce_usage_observed(
            &newer,
            ProbeOutcome::Http429 {
                subject: ProbeSubject::ApiKey,
                retry_after_secs: Some(3600),
            },
            400,
            600,
        );
        assert_eq!(ignored.health, HealthStatus::Ready);
        assert_eq!(ignored.cooldown, None);

        let old = UsageSnapshot::default();
        let expired = reduce_usage_observed(
            &old,
            ProbeOutcome::Http429 {
                subject: ProbeSubject::ApiKey,
                retry_after_secs: Some(30),
            },
            100,
            200,
        );
        assert_eq!(expired.health, HealthStatus::Unverified);
        assert_eq!(expired.cooldown, None);
        assert_eq!(expired.last_rate_limit_at, Some(100));
    }

    #[test]
    fn retry_after_is_clamped_and_saturating() {
        let low = reduce_usage(
            &UsageSnapshot::default(),
            ProbeOutcome::Http429 {
                subject: ProbeSubject::ApiKey,
                retry_after_secs: Some(1),
            },
            100,
        );
        assert_eq!(low.cooldown.as_ref().unwrap().until, 130);
        let high = reduce_usage(
            &UsageSnapshot::default(),
            ProbeOutcome::Http429 {
                subject: ProbeSubject::ApiKey,
                retry_after_secs: Some(999_999),
            },
            i64::MAX - 10,
        );
        assert_eq!(high.cooldown.as_ref().unwrap().until, i64::MAX);
    }

    #[test]
    fn cooldown_expiry_and_force_behavior() {
        let limited = reduce_usage(
            &UsageSnapshot::default(),
            ProbeOutcome::Http429 {
                subject: ProbeSubject::ApiKey,
                retry_after_secs: None,
            },
            100,
        );
        assert_eq!(
            probe_decision(&limited, 200, true),
            ProbeDecision::SkipCooldown
        );
        assert_eq!(probe_decision(&limited, 400, false), ProbeDecision::Probe);
        let recovered = reduce_usage(&limited, ProbeOutcome::Http200ApiKey, 400);
        assert_eq!(recovered.cooldown, None);
        assert_eq!(recovered.health, HealthStatus::Ready);

        let expired = UsageSnapshot {
            health: HealthStatus::RateLimited,
            cooldown: Some(Cooldown {
                started_at: 100,
                until: 130,
                last_evidence_at: 100,
            }),
            last_probe_at: Some(110),
            ..Default::default()
        };
        assert_eq!(probe_decision(&expired, 140, false), ProbeDecision::Probe);
    }

    #[test]
    fn future_cache_and_invalid_cooldown_are_cache_misses() {
        let future = UsageSnapshot {
            health: HealthStatus::Ready,
            last_probe_at: Some(10_000),
            cooldown: Some(Cooldown {
                started_at: 10_000,
                until: 20_000,
                last_evidence_at: 10_000,
            }),
            ..Default::default()
        };
        assert_eq!(
            probe_decision(&future, 100, false),
            ProbeDecision::SkipCooldown
        );

        let invalid = UsageSnapshot {
            health: HealthStatus::Ready,
            last_probe_at: Some(10_000),
            cooldown: Some(Cooldown {
                started_at: 50,
                until: 40,
                last_evidence_at: 50,
            }),
            ..Default::default()
        };
        assert_eq!(probe_decision(&invalid, 100, false), ProbeDecision::Probe);
    }
}
