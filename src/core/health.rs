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
    /// The server explicitly rejected the credential itself.  Only a new
    /// successful probe may overturn this verdict: a transport failure is not
    /// evidence about the credential and must never wash it away.
    pub const fn is_credential_rejection(self) -> bool {
        matches!(
            self,
            Self::AuthInvalid | Self::PermissionDenied | Self::InvalidCredential
        )
    }

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
    Gateway,
    Timeout,
    Network,
    InvalidJwt,
    VertexSigning,
    InvalidCredential,
    Unknown,
}

impl HealthErrorKind {
    /// The probe came back without a server verdict about the credential.
    ///
    /// 断网兜底只认 Timeout/Network 是不够的：现实中出网失败最常见的表现是
    /// 公司代理 / 强制门户 / 网关直接应答 407、302、404、502、503。这些应答
    /// 同样没有对凭据下过任何结论，却会让本地校验通过的账号无法启动
    /// (AVAIL-001)。因此"没有拿到凭据结论"的失败一律归入这一类；只有
    /// 400/401/403 这种服务端明确拒绝凭据的结论才不在其中。
    pub const fn is_transport_failure(self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Network | Self::Gateway | Self::ServerFailure
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "Unauthorized",
            Self::PermissionDenied => "PermissionDenied",
            Self::RateLimited => "RateLimited",
            Self::ServerFailure => "ServerFailure",
            Self::Gateway => "Gateway",
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
    Http400 {
        subject: ProbeSubject,
    },
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
    /// 任何"既不是凭据结论也不是 5xx"的非成功应答（3xx/404/407/…）。
    /// 这类应答几乎总是中间层（代理、网关、强制门户）发出的，探测根本没有
    /// 到达 provider。
    HttpUnexpected {
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

    /// Normalize persisted timestamps at the observation boundary.
    ///
    /// 一条 `started_at`/`last_evidence_at` 落在未来的记录只可能来自时钟前跳或
    /// 被改写的 state，它不是限流证据。以前的实现把这种记录重建成一个"从现在
    /// 开始"的新窗口，于是每次读取都重新计时，账号进入永久 cooldown，连
    /// `refresh --force` 也穿不透；现在一律丢弃，让账号立刻可以被重新探测。
    /// 过长的窗口只做**幂等**截断（按 `started_at` 而不是 `now` 计算上界），
    /// 同样是为了避免重复读取不断把到期时间往后推。
    pub fn normalize(self, now: i64) -> Option<Self> {
        if self.started_at > now || self.last_evidence_at > now || self.until <= self.started_at {
            return None;
        }
        let until = self
            .until
            .min(self.started_at.saturating_add(MAX_RETRY_SECS));
        if until <= now {
            return None;
        }
        Some(Self {
            started_at: self.started_at,
            until,
            last_evidence_at: self.last_evidence_at.max(self.started_at),
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

    /// Remaining cooldown seconds under the **normalized** semantics.
    ///
    /// 与 `is_in_cooldown` / `policy::eligibility` 读同一份归一化结果：裸的
    /// `cooldown.until` 会把时钟前跳留下的伪窗口显示成 Cooldown，于是表格说
    /// "冷却中"、选择器却照常把账号选出去，两边永远对不上。
    pub fn cooldown_remaining(&self, now: i64) -> Option<i64> {
        self.cooldown
            .as_ref()
            .and_then(|cooldown| cooldown.normalize(now))
            .filter(|cooldown| cooldown.is_active(now))
            .map(|cooldown| cooldown.until.saturating_sub(now))
    }

    pub fn needs_relogin(&self) -> bool {
        self.health.is_credential_rejection()
    }

    /// The last probe never reached the provider.  This is the single
    /// definition shared by `policy::eligibility` and the account table, so
    /// selection and the message the user reads can never disagree.
    pub fn probe_channel_unreachable(&self) -> bool {
        matches!(self.health, HealthStatus::TransientFailure)
            && self
                .last_error
                .is_some_and(HealthErrorKind::is_transport_failure)
    }

    /// Drop persisted values that are not evidence any more (future
    /// timestamps, a clock-skewed or expired cooldown).  Callers persist the
    /// result so an invalid record is cleared instead of re-derived forever.
    pub fn normalized(&self, now: i64) -> Self {
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
    let normalized = previous.normalized(now);
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
    // 传输失败保留"服务端已拒绝"的结论时，health 仍然是 AuthInvalid 之类，
    // 但 last_probe_at 已经被刷新。只看 health 会把退避窗从 30s 换成 300s TTL,
    // 等于让一次探测失败反过来延长了下一次重探的等待时间。判据必须落在
    // "上一次观察是不是传输失败"上。
    let window = if matches!(normalized.health, HealthStatus::TransientFailure)
        || normalized
            .last_error
            .is_some_and(HealthErrorKind::is_transport_failure)
    {
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
    let mut next = previous.normalized(now);
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
        ProbeOutcome::Http400 { subject } => {
            // Google 对失效/格式错误的 API key 返回 400，这属于服务端明确拒绝
            // 凭据，必须进入"需要用户处理"一类而不是传输故障类。authorized_user
            // 手里还有 refresh_token，正确动作是刷新而不是重新登录。
            let status = if matches!(subject, ProbeSubject::AuthorizedUser) {
                HealthStatus::RefreshRequired
            } else {
                HealthStatus::InvalidCredential
            };
            let error = if matches!(subject, ProbeSubject::AuthorizedUser) {
                HealthErrorKind::Unauthorized
            } else {
                HealthErrorKind::InvalidCredential
            };
            apply_error(&mut next, status, error, observed_at, now);
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
            // ServerFailure 现在同样享受降级兜底，所以它绝不能把一个"服务端
            // 已明确拒绝"的结论洗掉——否则让网关吐 502 就能让已知失效的凭据
            // 重新被调度。
            transport_failure_health(previous.health),
            HealthErrorKind::ServerFailure,
            observed_at,
            now,
        ),
        ProbeOutcome::HttpUnexpected { .. } => apply_error(
            &mut next,
            transport_failure_health(previous.health),
            HealthErrorKind::Gateway,
            observed_at,
            now,
        ),
        ProbeOutcome::Timeout { .. } => apply_error(
            &mut next,
            transport_failure_health(previous.health),
            HealthErrorKind::Timeout,
            observed_at,
            now,
        ),
        ProbeOutcome::Network { .. } => apply_error(
            &mut next,
            transport_failure_health(previous.health),
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

/// 断网期间的降级兜底会让 `TransientFailure` 重新可选，所以传输失败绝不能把
/// 一个"服务端已明确拒绝"的结论覆盖掉——否则拔掉网线就能让已知失效的凭据
/// 重新被调度。只有一次新的成功探测才能翻案。
fn transport_failure_health(previous: HealthStatus) -> HealthStatus {
    if previous.is_credential_rejection() {
        previous
    } else {
        HealthStatus::TransientFailure
    }
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

    /// AC-2.3: the reducer side of the status matrix, including the 400 that
    /// Google returns for an invalidated API key.
    #[test]
    fn reducer_matrix_covers_every_probe_outcome() {
        let cases: [(ProbeOutcome, HealthStatus, Option<HealthErrorKind>); 11] = [
            (ProbeOutcome::Http200ApiKey, HealthStatus::Ready, None),
            (
                ProbeOutcome::Http400 {
                    subject: ProbeSubject::ApiKey,
                },
                HealthStatus::InvalidCredential,
                Some(HealthErrorKind::InvalidCredential),
            ),
            (
                ProbeOutcome::Http400 {
                    subject: ProbeSubject::AuthorizedUser,
                },
                HealthStatus::RefreshRequired,
                Some(HealthErrorKind::Unauthorized),
            ),
            (
                ProbeOutcome::Http401ApiKey,
                HealthStatus::AuthInvalid,
                Some(HealthErrorKind::Unauthorized),
            ),
            (
                ProbeOutcome::Http403 {
                    subject: ProbeSubject::ApiKey,
                },
                HealthStatus::PermissionDenied,
                Some(HealthErrorKind::PermissionDenied),
            ),
            (
                ProbeOutcome::Http429 {
                    subject: ProbeSubject::ApiKey,
                    retry_after_secs: Some(60),
                },
                HealthStatus::RateLimited,
                Some(HealthErrorKind::RateLimited),
            ),
            (
                ProbeOutcome::Http5xx {
                    subject: ProbeSubject::ApiKey,
                    status: 500,
                },
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::ServerFailure),
            ),
            (
                ProbeOutcome::Timeout {
                    subject: ProbeSubject::ApiKey,
                },
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::Timeout),
            ),
            (
                ProbeOutcome::Network {
                    subject: ProbeSubject::ApiKey,
                },
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::Network),
            ),
            (
                ProbeOutcome::HttpUnexpected {
                    subject: ProbeSubject::ApiKey,
                    status: 407,
                },
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::Gateway),
            ),
            (
                ProbeOutcome::HttpUnexpected {
                    subject: ProbeSubject::ApiKey,
                    status: 302,
                },
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::Gateway),
            ),
        ];
        for (outcome, expected_health, expected_error) in cases {
            let next = reduce_usage(&ready(), outcome.clone(), 200);
            assert_eq!(next.health, expected_health, "outcome {outcome:?}");
            assert_eq!(next.last_error, expected_error, "outcome {outcome:?}");
            assert_eq!(
                next.health.is_credential_rejection(),
                matches!(
                    expected_health,
                    HealthStatus::AuthInvalid
                        | HealthStatus::PermissionDenied
                        | HealthStatus::InvalidCredential
                ),
                "outcome {outcome:?}"
            );
            assert_eq!(
                next.probe_channel_unreachable(),
                expected_error.is_some_and(HealthErrorKind::is_transport_failure),
                "outcome {outcome:?}"
            );
        }
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
    fn transport_failure_never_erases_a_server_rejection() {
        for rejected in [
            HealthStatus::AuthInvalid,
            HealthStatus::PermissionDenied,
            HealthStatus::InvalidCredential,
        ] {
            let previous = UsageSnapshot {
                health: rejected,
                last_probe_at: Some(100),
                last_error: Some(HealthErrorKind::Unauthorized),
                ..Default::default()
            };
            // 网关/服务端故障现在同样享受降级兜底，所以它们也必须留住
            // "服务端已拒绝"的结论。
            for outcome in [
                ProbeOutcome::Timeout {
                    subject: ProbeSubject::ApiKey,
                },
                ProbeOutcome::Network {
                    subject: ProbeSubject::ApiKey,
                },
                ProbeOutcome::HttpUnexpected {
                    subject: ProbeSubject::ApiKey,
                    status: 407,
                },
                ProbeOutcome::Http5xx {
                    subject: ProbeSubject::ApiKey,
                    status: 502,
                },
                ProbeOutcome::OtherTransient,
            ] {
                let next = reduce_usage(&previous, outcome, 200);
                assert_eq!(
                    next.health, rejected,
                    "an unreachable probe channel must not clear a server rejection"
                );
            }
        }

        let healthy = reduce_usage(
            &ready(),
            ProbeOutcome::Network {
                subject: ProbeSubject::ApiKey,
            },
            200,
        );
        assert_eq!(healthy.health, HealthStatus::TransientFailure);
        assert_eq!(healthy.last_error, Some(HealthErrorKind::Network));
    }

    #[test]
    fn future_cooldown_is_discarded_and_valid_cooldown_is_kept() {
        let now = 1_000;
        let future = Cooldown {
            started_at: now + 5_000,
            until: now + 6_000,
            last_evidence_at: now + 5_000,
        };
        assert_eq!(future.normalize(now), None);

        let skewed = UsageSnapshot {
            health: HealthStatus::RateLimited,
            cooldown: Some(future),
            last_probe_at: Some(now),
            last_error: Some(HealthErrorKind::RateLimited),
            ..Default::default()
        };
        assert!(!skewed.is_in_cooldown(now));
        assert_eq!(probe_decision(&skewed, now, false), ProbeDecision::Probe);
        assert_eq!(probe_decision(&skewed, now, true), ProbeDecision::Probe);
        assert_eq!(skewed.normalized(now).cooldown, None);

        let valid = Cooldown {
            started_at: now - 10,
            until: now + 100,
            last_evidence_at: now - 10,
        };
        assert_eq!(valid.normalize(now), Some(valid));
        let limited = UsageSnapshot {
            health: HealthStatus::RateLimited,
            cooldown: Some(valid),
            last_probe_at: Some(now - 10),
            ..Default::default()
        };
        assert!(limited.is_in_cooldown(now));
        assert_eq!(
            probe_decision(&limited, now, true),
            ProbeDecision::SkipCooldown
        );
        assert_eq!(limited.normalized(now).cooldown, Some(valid));
    }

    #[test]
    fn oversized_cooldown_is_truncated_idempotently() {
        let now = 1_000;
        let oversized = Cooldown {
            started_at: now - 10,
            until: now + MAX_RETRY_SECS * 10,
            last_evidence_at: now - 10,
        };
        let first = oversized.normalize(now).expect("bounded window");
        assert_eq!(first.until, oversized.started_at + MAX_RETRY_SECS);
        // 截断必须幂等：否则每次读取都会重新计时，账号永远出不了 cooldown。
        assert_eq!(first.normalize(now), Some(first));
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
        // 时钟前跳留下的 cooldown 同样是 cache miss（AC-3.1）：它不是限流证据，
        // 不得压制探测，否则账号会进入永久 cooldown。
        assert_eq!(probe_decision(&future, 100, false), ProbeDecision::Probe);

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

    /// AC-R6-2.1 / AC-R6-2.2：一次探测传输失败绝不能把下一次重探推得更远。
    /// 传输失败保留服务端拒绝结论时 health 还是 AuthInvalid，但退避必须仍然是
    /// 30s 的传输退避窗，而不是 300s 的缓存 TTL。
    #[test]
    fn a_transport_failure_never_lengthens_the_next_reprobe() {
        let rejected_at = 1_000;
        let rejected = reduce_usage(&ready(), ProbeOutcome::Http401Raw, rejected_at);
        // 纯粹的服务端拒绝：正常 TTL 窗口。
        assert_eq!(rejected.health, HealthStatus::AuthInvalid);
        assert_eq!(
            probe_decision(&rejected, rejected_at + PROBE_TTL_SECS - 1, false),
            ProbeDecision::UseCached
        );
        assert_eq!(
            probe_decision(&rejected, rejected_at + PROBE_TTL_SECS, false),
            ProbeDecision::Probe
        );

        let failed_at = rejected_at + PROBE_TTL_SECS;
        for outcome in [
            ProbeOutcome::Timeout {
                subject: ProbeSubject::ApiKey,
            },
            ProbeOutcome::Network {
                subject: ProbeSubject::ApiKey,
            },
            ProbeOutcome::HttpUnexpected {
                subject: ProbeSubject::ApiKey,
                status: 407,
            },
        ] {
            let after = reduce_usage(&rejected, outcome.clone(), failed_at);
            assert!(
                after.health.is_credential_rejection(),
                "outcome {outcome:?} must keep the server rejection"
            );
            assert_eq!(after.last_probe_at, Some(failed_at), "outcome {outcome:?}");
            assert_eq!(
                probe_decision(&after, failed_at + TRANSIENT_BACKOFF_SECS, false),
                ProbeDecision::Probe,
                "a transport failure must not push the next reprobe past the backoff window \
                 (outcome {outcome:?})"
            );
        }

        // 同一次传输失败打在健康账号上时的退避窗，是上面那条断言的参照物。
        let plain = reduce_usage(
            &ready(),
            ProbeOutcome::Network {
                subject: ProbeSubject::ApiKey,
            },
            failed_at,
        );
        assert_eq!(
            probe_decision(&plain, failed_at + TRANSIENT_BACKOFF_SECS - 1, false),
            ProbeDecision::UseCached
        );
        assert_eq!(
            probe_decision(&plain, failed_at + TRANSIENT_BACKOFF_SECS, false),
            ProbeDecision::Probe
        );
    }

    /// AC-R6-5.1：表格读的剩余冷却时间必须与 `is_in_cooldown` 同一份归一化语义。
    #[test]
    fn cooldown_remaining_matches_the_normalized_cooldown_predicate() {
        let now = 1_000;
        let skewed = UsageSnapshot {
            health: HealthStatus::Ready,
            cooldown: Some(Cooldown {
                started_at: now + 5_000,
                until: now + 6_000,
                last_evidence_at: now + 5_000,
            }),
            ..Default::default()
        };
        assert!(!skewed.is_in_cooldown(now));
        assert_eq!(skewed.cooldown_remaining(now), None);

        let active = UsageSnapshot {
            health: HealthStatus::RateLimited,
            cooldown: Some(Cooldown {
                started_at: now - 10,
                until: now + 100,
                last_evidence_at: now - 10,
            }),
            ..Default::default()
        };
        assert!(active.is_in_cooldown(now));
        assert_eq!(active.cooldown_remaining(now), Some(100));
    }
}
