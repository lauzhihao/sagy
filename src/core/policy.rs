use chrono::Utc;
use std::collections::BTreeSet;

use crate::core::health::HealthStatus;
use crate::core::state::{
    AccountRecord, AccountType, CredentialRef, CredentialRefKind, State, UsageSnapshot,
};

/// The only result used by account selection. The ordering is intentional:
/// a successfully probed credential wins over one that needs a refresh, both
/// win over a locally verified but unprobed credential, and all of them win
/// over a credential that could only be verified locally because the probe
/// channel was unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eligibility {
    Primary,
    Secondary,
    Fallback,
    Degraded,
    Ineligible,
}

impl Eligibility {
    fn rank(self) -> Option<i64> {
        match self {
            Self::Primary => Some(4),
            Self::Secondary => Some(3),
            Self::Fallback => Some(2),
            Self::Degraded => Some(1),
            Self::Ineligible => None,
        }
    }
}

/// Decide whether one account can be selected.  This is the single definition
/// of account selectability in the code base.
///
/// `None` is deliberately accepted for the credential reference so callers
/// handling v1 or partially migrated state can fail closed instead of
/// inventing a credential kind. A missing usage snapshot is treated as
/// `Unverified`; that path is selectable only after the caller has validated
/// the local credential.
///
/// 一次探测失败只要没有带回"服务端对凭据的结论"（timeout / DNS / 连接被拒 /
/// 代理 407 / 网关 502、503 / 强制门户的 302、404），就只说明探测通道不可用，
/// 本地校验通过的凭据必须仍然可选，否则 sagy 会在凭据完全有效的情况下拒绝
/// 启动 agy（AVAIL-001）。而服务端明确拒绝（400/401/403、无效凭据）不享受
/// 这个兜底。
pub fn eligibility(
    account: &AccountRecord,
    credential_ref: Option<&CredentialRef>,
    usage: Option<&UsageSnapshot>,
    local_credential_validated: bool,
    now: i64,
) -> Eligibility {
    let Some(credential_ref) = credential_ref else {
        return Eligibility::Ineligible;
    };
    if !compatible_credential(account.account_type, credential_ref.kind) {
        return Eligibility::Ineligible;
    }

    let usage = usage.cloned().unwrap_or_default();
    if usage.remaining_quota_percent == Some(0) || usage.is_in_cooldown(now) {
        return Eligibility::Ineligible;
    }

    match usage.health {
        HealthStatus::Ready => Eligibility::Primary,
        HealthStatus::RefreshRequired
            if credential_ref.kind == CredentialRefKind::OauthAuthorizedUser =>
        {
            Eligibility::Secondary
        }
        HealthStatus::Unverified if local_credential_validated => Eligibility::Fallback,
        HealthStatus::TransientFailure
            if local_credential_validated && usage.probe_channel_unreachable() =>
        {
            Eligibility::Degraded
        }
        HealthStatus::RefreshRequired
        | HealthStatus::Unverified
        | HealthStatus::RateLimited
        | HealthStatus::AuthInvalid
        | HealthStatus::PermissionDenied
        | HealthStatus::InvalidCredential
        | HealthStatus::TransientFailure => Eligibility::Ineligible,
    }
}

fn compatible_credential(account_type: AccountType, kind: CredentialRefKind) -> bool {
    match account_type {
        AccountType::OAuth => matches!(
            kind,
            CredentialRefKind::OauthAccessToken | CredentialRefKind::OauthAuthorizedUser
        ),
        AccountType::ApiKey => kind == CredentialRefKind::ApiKey,
        AccountType::Vertex => kind == CredentialRefKind::VertexServiceAccount,
    }
}

pub fn select_best_account<'a>(
    state: &'a State,
    accounts: &'a [AccountRecord],
) -> Option<(&'a AccountRecord, UsageSnapshot)> {
    select_best_account_with_validation(state, accounts, &BTreeSet::new(), Utc::now().timestamp())
}

/// Select after the caller has validated the listed fixed credential files.
/// A durable ref alone is not proof that its file still exists and matches.
pub fn select_best_account_with_validation<'a>(
    state: &'a State,
    accounts: &'a [AccountRecord],
    locally_validated_ids: &BTreeSet<String>,
    now: i64,
) -> Option<(&'a AccountRecord, UsageSnapshot)> {
    if accounts.is_empty() {
        return None;
    }

    // Stickiness and ordinary candidate selection use the same predicate.
    if let Some(current_id) = &state.current_account_id {
        if let Some(current_account) = accounts.iter().find(|a| &a.id == current_id) {
            let usage = state.usage_cache.get(&current_account.id);
            let reference = state.credential_refs.get(&current_account.id);
            if eligibility(
                current_account,
                reference,
                usage,
                locally_validated_ids.contains(&current_account.id),
                now,
            )
            .rank()
            .is_some()
            {
                return Some((current_account, usage.cloned().unwrap_or_default()));
            }
        }
    }

    let mut candidates: Vec<(&'a AccountRecord, UsageSnapshot, i64)> = accounts
        .iter()
        .filter_map(|account| {
            let usage = state.usage_cache.get(&account.id);
            let reference = state.credential_refs.get(&account.id);
            let tier = eligibility(
                account,
                reference,
                usage,
                locally_validated_ids.contains(&account.id),
                now,
            );
            let rank = tier.rank()?;
            let snapshot = usage.cloned().unwrap_or_default();
            Some((
                account,
                snapshot.clone(),
                score_account(account, &snapshot, now, rank),
            ))
        })
        .collect();

    // 排序必须与账号在 state 中的排列顺序无关：先按分数（等级已计入分数），
    // 同分再按 account id 升序。否则断网时"选哪个账号"会随 state 写入顺序漂移，
    // 无法测试也无法向用户解释。
    candidates.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| left.0.id.cmp(&right.0.id))
    });
    candidates
        .into_iter()
        .next()
        .map(|(account, usage, _)| (account, usage))
}

fn score_account(account: &AccountRecord, usage: &UsageSnapshot, now: i64, tier: i64) -> i64 {
    let mut score = tier * 10_000;

    if let Some(remaining) = usage.remaining_quota_percent {
        score += i64::from(remaining) * 5;
    }

    if account.is_oauth() {
        score += 50;
    }

    if let Some(plan) = &account.plan {
        let plan_lower = plan.to_ascii_lowercase();
        if plan_lower.contains("pro")
            || plan_lower.contains("advanced")
            || plan_lower.contains("ultra")
        {
            score += 100;
        }
    }

    // A future timestamp is clock-skew evidence, never a freshness bonus.
    if let Some(last_used) = account.last_used_at {
        if last_used <= now && now - last_used < 24 * 60 * 60 {
            score += 10;
        }
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::health::{Cooldown, HealthErrorKind};

    const FP: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn account(account_type: AccountType) -> AccountRecord {
        AccountRecord {
            id: "account-1".to_string(),
            email: "user@example.test".to_string(),
            account_type,
            ..Default::default()
        }
    }

    fn reference(kind: CredentialRefKind) -> CredentialRef {
        CredentialRef {
            kind,
            fingerprint: FP.to_string(),
        }
    }

    fn usage(health: HealthStatus) -> UsageSnapshot {
        UsageSnapshot {
            health,
            remaining_quota_percent: Some(50),
            ..Default::default()
        }
    }

    #[test]
    fn eligibility_matrix_rejects_incompatible_and_terminal_states() {
        let now = 1_000;
        let kinds = [
            (AccountType::OAuth, CredentialRefKind::OauthAccessToken),
            (AccountType::OAuth, CredentialRefKind::OauthAuthorizedUser),
            (AccountType::ApiKey, CredentialRefKind::ApiKey),
            (AccountType::Vertex, CredentialRefKind::VertexServiceAccount),
        ];
        for (account_type, kind) in kinds {
            let account = account(account_type);
            let reference = reference(kind);
            assert_eq!(
                eligibility(
                    &account,
                    Some(&reference),
                    Some(&usage(HealthStatus::Ready)),
                    false,
                    now
                ),
                Eligibility::Primary
            );
            assert_eq!(
                eligibility(
                    &account,
                    Some(&reference),
                    Some(&usage(HealthStatus::RefreshRequired)),
                    true,
                    now
                ),
                if kind == CredentialRefKind::OauthAuthorizedUser {
                    Eligibility::Secondary
                } else {
                    Eligibility::Ineligible
                }
            );
            for health in [
                HealthStatus::RateLimited,
                HealthStatus::AuthInvalid,
                HealthStatus::PermissionDenied,
                HealthStatus::InvalidCredential,
                HealthStatus::TransientFailure,
            ] {
                assert_eq!(
                    eligibility(&account, Some(&reference), Some(&usage(health)), true, now),
                    Eligibility::Ineligible
                );
            }
            assert_eq!(
                eligibility(&account, Some(&reference), None, false, now),
                Eligibility::Ineligible
            );
            assert_eq!(
                eligibility(&account, Some(&reference), None, true, now),
                Eligibility::Fallback
            );
        }

        let oauth = account(AccountType::OAuth);
        assert_eq!(
            eligibility(
                &oauth,
                Some(&reference(CredentialRefKind::ApiKey)),
                Some(&usage(HealthStatus::Ready)),
                true,
                now
            ),
            Eligibility::Ineligible
        );
        assert_eq!(
            eligibility(&oauth, None, Some(&usage(HealthStatus::Ready)), true, now),
            Eligibility::Ineligible
        );
    }

    #[test]
    fn zero_quota_and_active_cooldown_are_always_ineligible() {
        let account = account(AccountType::OAuth);
        let reference = reference(CredentialRefKind::OauthAuthorizedUser);
        let zero = UsageSnapshot {
            health: HealthStatus::Ready,
            remaining_quota_percent: Some(0),
            ..Default::default()
        };
        assert_eq!(
            eligibility(&account, Some(&reference), Some(&zero), true, 100),
            Eligibility::Ineligible
        );
        let limited = UsageSnapshot {
            health: HealthStatus::RateLimited,
            cooldown: Some(Cooldown {
                started_at: 100,
                until: 200,
                last_evidence_at: 100,
            }),
            ..Default::default()
        };
        assert_eq!(
            eligibility(&account, Some(&reference), Some(&limited), true, 150),
            Eligibility::Ineligible
        );
    }

    #[test]
    fn stickiness_and_candidates_share_eligibility() {
        let current = account(AccountType::OAuth);
        let candidate = AccountRecord {
            id: "account-2".to_string(),
            email: "two@example.test".to_string(),
            account_type: AccountType::OAuth,
            ..Default::default()
        };
        let mut state = State {
            accounts: vec![current.clone(), candidate.clone()],
            current_account_id: Some(current.id.clone()),
            ..Default::default()
        };
        state.credential_refs.insert(
            current.id.clone(),
            reference(CredentialRefKind::OauthAccessToken),
        );
        state.credential_refs.insert(
            candidate.id.clone(),
            reference(CredentialRefKind::OauthAccessToken),
        );
        state
            .usage_cache
            .insert(current.id.clone(), usage(HealthStatus::AuthInvalid));
        state.usage_cache.insert(
            candidate.id.clone(),
            UsageSnapshot {
                health: HealthStatus::Ready,
                remaining_quota_percent: Some(10),
                ..Default::default()
            },
        );
        assert_eq!(
            select_best_account(&state, &state.accounts).unwrap().0.id,
            candidate.id
        );
    }

    #[test]
    fn future_last_used_does_not_receive_freshness_bonus() {
        let now = Utc::now().timestamp();
        let mut first = account(AccountType::ApiKey);
        first.id = "first".to_string();
        first.last_used_at = Some(now + 86_400);
        let mut second = account(AccountType::ApiKey);
        second.id = "second".to_string();
        let mut state = State {
            accounts: vec![first.clone(), second.clone()],
            ..Default::default()
        };
        for item in [&first, &second] {
            state
                .credential_refs
                .insert(item.id.clone(), reference(CredentialRefKind::ApiKey));
            state
                .usage_cache
                .insert(item.id.clone(), usage(HealthStatus::Ready));
        }
        let selected = select_best_account(&state, &state.accounts).unwrap();
        assert_eq!(selected.0.id, "first");
    }

    #[test]
    fn tier_is_primary_then_secondary_then_fallback() {
        assert!(Eligibility::Primary.rank() > Eligibility::Secondary.rank());
        assert!(Eligibility::Secondary.rank() > Eligibility::Fallback.rank());
        assert_eq!(Eligibility::Ineligible.rank(), None);
    }

    fn transport_failure(kind: HealthErrorKind) -> UsageSnapshot {
        UsageSnapshot {
            health: HealthStatus::TransientFailure,
            last_error: Some(kind),
            last_probe_at: Some(900),
            ..Default::default()
        }
    }

    #[test]
    fn transport_failure_falls_back_to_local_validation_but_rejection_does_not() {
        let now = 1_000;
        let account = account(AccountType::ApiKey);
        let reference = reference(CredentialRefKind::ApiKey);

        // Gateway / ServerFailure 也属于"没拿到凭据结论"：代理 407、网关 502
        // 与断网一样不该让本地校验通过的账号无法启动。
        for kind in [
            HealthErrorKind::Timeout,
            HealthErrorKind::Network,
            HealthErrorKind::Gateway,
            HealthErrorKind::ServerFailure,
        ] {
            assert_eq!(
                eligibility(
                    &account,
                    Some(&reference),
                    Some(&transport_failure(kind)),
                    true,
                    now
                ),
                Eligibility::Degraded
            );
            assert_ne!(
                eligibility(
                    &account,
                    Some(&reference),
                    Some(&transport_failure(kind)),
                    true,
                    now
                ),
                Eligibility::Ineligible,
                "a locally valid credential must survive an unreachable probe channel"
            );
            assert_eq!(
                eligibility(
                    &account,
                    Some(&reference),
                    Some(&transport_failure(kind)),
                    false,
                    now
                ),
                Eligibility::Ineligible,
                "an unvalidated credential must still fail closed"
            );
        }

        // 兜底的默认分类（从未被任何探测产生）仍然 fail closed。
        assert_eq!(
            eligibility(
                &account,
                Some(&reference),
                Some(&transport_failure(HealthErrorKind::Unknown)),
                true,
                now
            ),
            Eligibility::Ineligible
        );

        for health in [
            HealthStatus::AuthInvalid,
            HealthStatus::PermissionDenied,
            HealthStatus::InvalidCredential,
        ] {
            assert_eq!(
                eligibility(&account, Some(&reference), Some(&usage(health)), true, now),
                Eligibility::Ineligible
            );
        }
    }

    #[test]
    fn degraded_never_outranks_a_probed_or_unverified_candidate() {
        let now = 1_000;
        let account = account(AccountType::ApiKey);
        let reference = reference(CredentialRefKind::ApiKey);
        let degraded = eligibility(
            &account,
            Some(&reference),
            Some(&transport_failure(HealthErrorKind::Network)),
            true,
            now,
        );
        let fallback = eligibility(&account, Some(&reference), None, true, now);
        assert_eq!(fallback, Eligibility::Fallback);
        assert!(degraded.rank() < fallback.rank());
        assert!(degraded.rank().is_some());
    }

    #[test]
    fn selection_order_is_independent_of_account_vector_order() {
        let ids = ["b", "a", "c"];
        let mut selected = Vec::new();
        for rotation in 0..ids.len() {
            let mut ordered = ids.to_vec();
            ordered.rotate_left(rotation);
            let mut state = State::default();
            let mut validated = BTreeSet::new();
            for id in ordered {
                state.accounts.push(AccountRecord {
                    id: id.to_string(),
                    email: format!("{id}@example.test"),
                    account_type: AccountType::ApiKey,
                    ..Default::default()
                });
                state
                    .credential_refs
                    .insert(id.to_string(), reference(CredentialRefKind::ApiKey));
                state
                    .usage_cache
                    .insert(id.to_string(), transport_failure(HealthErrorKind::Network));
                validated.insert(id.to_string());
            }
            selected.push(
                select_best_account_with_validation(&state, &state.accounts, &validated, 1_000)
                    .map(|(account, _)| account.id.clone()),
            );
        }
        assert_eq!(
            selected,
            vec![
                Some("a".to_string()),
                Some("a".to_string()),
                Some("a".to_string())
            ]
        );
    }

    #[test]
    fn unverified_selection_requires_live_local_validation_not_only_a_state_ref() {
        let candidate = account(AccountType::Vertex);
        let mut state = State {
            accounts: vec![candidate.clone()],
            ..Default::default()
        };
        state.credential_refs.insert(
            candidate.id.clone(),
            reference(CredentialRefKind::VertexServiceAccount),
        );
        state
            .usage_cache
            .insert(candidate.id.clone(), usage(HealthStatus::Unverified));

        assert!(select_best_account(&state, &state.accounts).is_none());
        let validated = BTreeSet::from([candidate.id.clone()]);
        assert_eq!(
            select_best_account_with_validation(&state, &state.accounts, &validated, 1_000)
                .unwrap()
                .0
                .id,
            candidate.id
        );
    }
}
