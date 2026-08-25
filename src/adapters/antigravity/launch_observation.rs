//! Bounded, evidence-only observation of an `agy` child process.
//!
//! The launcher must not infer an API outcome from an exit code, a terminal
//! colour sequence, or an arbitrary line of stderr.  This module therefore
//! accepts only a complete, duplicate-free Google JSON error document and
//! keeps no diagnostic text in its public result.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Maximum amount of child diagnostic data retained while the child drains.
pub const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
/// Default retry delay when a canonical rate-limit response has no hint.
pub const DEFAULT_RETRY_AFTER_SECONDS: u64 = 300;
/// Lower bound for a retry hint.  A child cannot request a busy-loop retry.
pub const MIN_RETRY_AFTER_SECONDS: u64 = 30;
/// Upper bound for a retry hint.  A child cannot pin the scheduler forever.
pub const MAX_RETRY_AFTER_SECONDS: u64 = 3600;

/// The typed result of trying to run a child process.
///
/// `SpawnFailed` and `WaitFailed` deliberately carry no source error.  The
/// source error can contain a path, command line, or secret supplied by the
/// caller, while the launch outcome is intended to be safe to log and store.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ProcessTermination {
    /// The child returned a conventional process exit code.
    Exited { code: i32 },
    /// The child was terminated by a signal (Unix) or an equivalent native
    /// termination reason.  The numeric value is intentionally opaque.
    Signaled { signal: i32 },
    /// The child could not be spawned.
    SpawnFailed,
    /// Waiting for an already spawned child failed.
    WaitFailed,
}

impl ProcessTermination {
    /// Construct an exited process result.
    pub const fn exited(code: i32) -> Self {
        Self::Exited { code }
    }

    /// Construct a signal termination result.
    pub const fn signaled(signal: i32) -> Self {
        Self::Signaled { signal }
    }

    /// Construct a spawn failure result.
    pub const fn spawn_failed() -> Self {
        Self::SpawnFailed
    }

    /// Construct a wait failure result.
    pub const fn wait_failed() -> Self {
        Self::WaitFailed
    }

    /// Whether the child itself completed successfully.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Exited { code: 0 })
    }

    fn has_child_failure(self) -> bool {
        match self {
            Self::Exited { code } => code != 0,
            Self::Signaled { .. } => true,
            Self::SpawnFailed | Self::WaitFailed => false,
        }
    }
}

impl fmt::Debug for ProcessTermination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited { code } => formatter
                .debug_struct("Exited")
                .field("code", code)
                .finish(),
            Self::Signaled { signal } => formatter
                .debug_struct("Signaled")
                .field("signal", signal)
                .finish(),
            Self::SpawnFailed => formatter.write_str("SpawnFailed"),
            Self::WaitFailed => formatter.write_str("WaitFailed"),
        }
    }
}

/// A bounded, secret-free classification of a child launch.
#[derive(Clone, Eq, PartialEq)]
pub enum LaunchDiagnostic {
    /// No strong, canonical evidence was available.
    None,
    /// A canonical Google `RESOURCE_EXHAUSTED` response was observed.
    RateLimited {
        /// Retry delay after applying the 30..=3600 second safety bounds.
        retry_after_seconds: u64,
    },
    /// A canonical Google `UNAUTHENTICATED` response was observed.
    AuthRejected,
    /// A canonical Google `PERMISSION_DENIED` response was observed.
    PermissionDenied,
}

impl LaunchDiagnostic {
    /// Return the bounded retry delay, if this is a rate-limit diagnostic.
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => Some(*retry_after_seconds),
            Self::None | Self::AuthRejected | Self::PermissionDenied => None,
        }
    }
}

impl fmt::Debug for LaunchDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::AuthRejected => formatter.write_str("AuthRejected"),
            Self::PermissionDenied => formatter.write_str("PermissionDenied"),
            Self::RateLimited {
                retry_after_seconds,
            } => formatter
                .debug_struct("RateLimited")
                .field("retry_after_seconds", retry_after_seconds)
                .finish(),
        }
    }
}

/// The only result exposed after the child has terminated.
#[derive(Clone, Eq, PartialEq)]
pub struct LaunchOutcome {
    pub termination: ProcessTermination,
    pub diagnostic: LaunchDiagnostic,
}

impl fmt::Debug for LaunchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchOutcome")
            .field("termination", &self.termination)
            .field("diagnostic", &self.diagnostic)
            .finish()
    }
}

/// Why a chunk or a final document was rejected.
///
/// This type intentionally does not retain the offending bytes or parser
/// message.  Callers can use it for control flow without risking a secret in
/// a log line or a persisted error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchDiagnosticParseError {
    TooLarge,
    InvalidUtf8,
    InvalidJson,
    IncompleteJson,
    DuplicateKey,
    NonCanonical,
}

/// A parser that can be fed from a stderr drain thread in arbitrary chunks.
///
/// Feeding a chunk never exposes its content.  Once the bound is exceeded the
/// buffered bytes are discarded and later chunks are ignored, which lets a
/// drain thread continue until EOF without retaining unbounded child output.
pub struct LaunchDiagnosticParser {
    buffer: Vec<u8>,
    rejection: Option<LaunchDiagnosticParseError>,
}

impl Default for LaunchDiagnosticParser {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LaunchDiagnosticParser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchDiagnosticParser")
            .field("buffered_len", &self.buffer.len())
            .field("rejection", &self.rejection)
            .finish()
    }
}

impl LaunchDiagnosticParser {
    /// Start an empty parser.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            rejection: None,
        }
    }

    /// Feed one arbitrary stderr chunk.
    ///
    /// A UTF-8 code point or JSON token may be split between chunks.  Such
    /// input is checked only by [`Self::try_finish`], not guessed per chunk.
    pub fn feed_chunk(&mut self, chunk: &[u8]) -> Result<(), LaunchDiagnosticParseError> {
        if let Some(rejection) = self.rejection {
            return Err(rejection);
        }

        if chunk.len() > MAX_DIAGNOSTIC_BYTES.saturating_sub(self.buffer.len()) {
            self.buffer.clear();
            self.rejection = Some(LaunchDiagnosticParseError::TooLarge);
            return Err(LaunchDiagnosticParseError::TooLarge);
        }

        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Alias suitable for a generic byte-stream drain loop.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), LaunchDiagnosticParseError> {
        self.feed_chunk(chunk)
    }

    /// Alias for callers that use a push-style stream abstraction.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), LaunchDiagnosticParseError> {
        self.feed_chunk(chunk)
    }

    /// Number of bytes currently retained, never greater than the bound.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the stream has already been rejected.
    pub const fn is_rejected(&self) -> bool {
        self.rejection.is_some()
    }

    /// Finish and classify.  Rejected, incomplete, plain-text, and
    /// non-canonical streams safely become `LaunchDiagnostic::None`.
    pub fn finish(self, termination: ProcessTermination) -> LaunchOutcome {
        match self.try_finish(termination) {
            Ok(outcome) => outcome,
            Err(_) => LaunchOutcome {
                termination,
                diagnostic: LaunchDiagnostic::None,
            },
        }
    }

    /// Finish and return the exact safe rejection category when evidence is
    /// insufficient.  No bytes are included in the error.
    pub fn try_finish(
        self,
        termination: ProcessTermination,
    ) -> Result<LaunchOutcome, LaunchDiagnosticParseError> {
        if let Some(rejection) = self.rejection {
            return Err(rejection);
        }

        let outcome = LaunchOutcome {
            termination,
            diagnostic: LaunchDiagnostic::None,
        };

        if self.buffer.is_empty() {
            return Ok(outcome);
        }

        if std::str::from_utf8(&self.buffer).is_err() {
            return Err(LaunchDiagnosticParseError::InvalidUtf8);
        }

        let value = parse_without_duplicate_keys(&self.buffer)?;
        // Spawn/wait failures do not prove anything about a child API result,
        // even if a caller accidentally supplied a valid document to this
        // parser.  The document is still parsed above so malformed bytes are
        // rejected consistently.
        if !termination.has_child_failure() {
            return Ok(outcome);
        }

        let diagnostic = classify_google_error(&value)?;
        Ok(LaunchOutcome {
            termination,
            diagnostic,
        })
    }
}

const GOOGLE_ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";
const GOOGLE_RETRY_INFO_TYPE: &str = "type.googleapis.com/google.rpc.RetryInfo";

// This is deliberately finite.  Unknown ErrorInfo reasons are not strong
// evidence, even if the surrounding status happens to look familiar.
const ALLOWED_ERROR_INFO_REASONS: &[&str] = &[
    "ACCESS_DENIED",
    "ACCESS_TOKEN_EXPIRED",
    "ACCESS_TOKEN_INVALID",
    "API_KEY_INVALID",
    "AUTHENTICATION_ERROR",
    "BILLING_DISABLED",
    "CONSUMER_INVALID",
    "CONSUMER_SUSPENDED",
    "INVALID_API_KEY",
    "LOCATION_NOT_SUPPORTED",
    "PERMISSION_DENIED",
    "PROJECT_INVALID",
    "QUOTA_EXCEEDED",
    "RATE_LIMIT_EXCEEDED",
    "RESOURCE_EXHAUSTED",
    "SERVICE_DISABLED",
    "UNAUTHENTICATED",
];

fn classify_google_error(value: &Value) -> Result<LaunchDiagnostic, LaunchDiagnosticParseError> {
    let root = value
        .as_object()
        .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
    let error = root
        .get("error")
        .and_then(Value::as_object)
        .ok_or(LaunchDiagnosticParseError::NonCanonical)?;

    let code = error
        .get("code")
        .and_then(Value::as_i64)
        .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
    let status = error
        .get("status")
        .and_then(Value::as_str)
        .ok_or(LaunchDiagnosticParseError::NonCanonical)?;

    let kind = match (code, status) {
        (429, "RESOURCE_EXHAUSTED") => ErrorKind::RateLimited,
        (401, "UNAUTHENTICATED") => ErrorKind::AuthRejected,
        (403, "PERMISSION_DENIED") => ErrorKind::PermissionDenied,
        _ => return Err(LaunchDiagnosticParseError::NonCanonical),
    };

    let mut retry_after = read_retry_after(root, error)?;
    let mut reasons = Vec::new();
    if let Some(details) = error.get("details") {
        let details = details
            .as_array()
            .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
        let mut retry_info_delay = None;
        for detail in details {
            let object = detail
                .as_object()
                .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
            let Some(type_name) = object.get("@type") else {
                continue;
            };
            let type_name = type_name
                .as_str()
                .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
            match type_name {
                GOOGLE_ERROR_INFO_TYPE => {
                    if let Some(reason) = object.get("reason") {
                        let reason = reason
                            .as_str()
                            .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
                        if !ALLOWED_ERROR_INFO_REASONS.contains(&reason) {
                            return Err(LaunchDiagnosticParseError::NonCanonical);
                        }
                        reasons.push(reason);
                    }
                }
                GOOGLE_RETRY_INFO_TYPE => {
                    if let Some(delay) = object.get("retryDelay") {
                        let delay = delay
                            .as_str()
                            .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
                        let delay = parse_google_duration_seconds(delay)
                            .ok_or(LaunchDiagnosticParseError::NonCanonical)?;
                        if let Some(existing) = retry_info_delay {
                            if existing != delay {
                                return Err(LaunchDiagnosticParseError::NonCanonical);
                            }
                        } else {
                            retry_info_delay = Some(delay);
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(delay) = retry_info_delay {
            if let Some(existing) = retry_after {
                if existing != delay {
                    return Err(LaunchDiagnosticParseError::NonCanonical);
                }
            } else {
                retry_after = Some(delay);
            }
        }
    }

    for reason in reasons {
        if !reason_matches_kind(reason, kind) {
            return Err(LaunchDiagnosticParseError::NonCanonical);
        }
    }

    Ok(match kind {
        ErrorKind::RateLimited => LaunchDiagnostic::RateLimited {
            retry_after_seconds: bound_retry_after(
                retry_after.unwrap_or(DEFAULT_RETRY_AFTER_SECONDS),
            ),
        },
        ErrorKind::AuthRejected => LaunchDiagnostic::AuthRejected,
        ErrorKind::PermissionDenied => LaunchDiagnostic::PermissionDenied,
    })
}

#[derive(Clone, Copy)]
enum ErrorKind {
    RateLimited,
    AuthRejected,
    PermissionDenied,
}

fn reason_matches_kind(reason: &str, kind: ErrorKind) -> bool {
    match kind {
        ErrorKind::RateLimited => matches!(
            reason,
            "QUOTA_EXCEEDED" | "RATE_LIMIT_EXCEEDED" | "RESOURCE_EXHAUSTED"
        ),
        ErrorKind::AuthRejected => matches!(
            reason,
            "ACCESS_TOKEN_EXPIRED"
                | "ACCESS_TOKEN_INVALID"
                | "API_KEY_INVALID"
                | "AUTHENTICATION_ERROR"
                | "INVALID_API_KEY"
                | "UNAUTHENTICATED"
        ),
        ErrorKind::PermissionDenied => matches!(
            reason,
            "ACCESS_DENIED"
                | "BILLING_DISABLED"
                | "CONSUMER_INVALID"
                | "CONSUMER_SUSPENDED"
                | "LOCATION_NOT_SUPPORTED"
                | "PERMISSION_DENIED"
                | "PROJECT_INVALID"
                | "SERVICE_DISABLED"
        ),
    }
}

fn read_retry_after(
    root: &Map<String, Value>,
    error: &Map<String, Value>,
) -> Result<Option<u64>, LaunchDiagnosticParseError> {
    let root_hint = parse_retry_after_field(root.get("Retry-After"))?;
    let error_hint = parse_retry_after_field(error.get("Retry-After"))?;
    if let (Some(root_hint), Some(error_hint)) = (root_hint, error_hint) {
        if root_hint != error_hint {
            return Err(LaunchDiagnosticParseError::NonCanonical);
        }
    }
    Ok(root_hint.or(error_hint))
}

fn parse_retry_after_field(
    value: Option<&Value>,
) -> Result<Option<u64>, LaunchDiagnosticParseError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let seconds = if let Some(value) = value.as_i64() {
        value
    } else if let Some(value) = value.as_u64() {
        value.min(i64::MAX as u64) as i64
    } else {
        return Err(LaunchDiagnosticParseError::NonCanonical);
    };
    Ok(Some(bound_retry_after_i64(seconds)))
}

fn parse_google_duration_seconds(value: &str) -> Option<u64> {
    let number = value.strip_suffix('s')?;
    if number.is_empty() || number.starts_with('+') || number.starts_with('-') {
        return None;
    }
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
    {
        return None;
    }
    whole.parse::<u64>().ok()
}

fn bound_retry_after_i64(value: i64) -> u64 {
    if value < MIN_RETRY_AFTER_SECONDS as i64 {
        MIN_RETRY_AFTER_SECONDS
    } else if value > MAX_RETRY_AFTER_SECONDS as i64 {
        MAX_RETRY_AFTER_SECONDS
    } else {
        value as u64
    }
}

fn bound_retry_after(value: u64) -> u64 {
    value.clamp(MIN_RETRY_AFTER_SECONDS, MAX_RETRY_AFTER_SECONDS)
}

fn parse_without_duplicate_keys(bytes: &[u8]) -> Result<Value, LaunchDiagnosticParseError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = NoDuplicateValue::deserialize(&mut deserializer).map_err(map_json_error)?;
    deserializer.end().map_err(map_json_error)?;
    Ok(value.0)
}

fn map_json_error(error: serde_json::Error) -> LaunchDiagnosticParseError {
    if error.is_eof() {
        LaunchDiagnosticParseError::IncompleteJson
    } else if error.to_string().contains("duplicate object key") {
        LaunchDiagnosticParseError::DuplicateKey
    } else {
        LaunchDiagnosticParseError::InvalidJson
    }
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NoDuplicateVisitor;

        impl<'de> Visitor<'de> for NoDuplicateVisitor {
            type Value = NoDuplicateValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with unique object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| NoDuplicateValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(NoDuplicateValue(Value::Null))
            }

            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<NoDuplicateValue>()? {
                    values.push(value.0);
                }
                Ok(NoDuplicateValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                    let value = access.next_value::<NoDuplicateValue>()?;
                    object.insert(key, value.0);
                }
                Ok(NoDuplicateValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_chunks(chunks: &[&[u8]], termination: ProcessTermination) -> LaunchOutcome {
        let mut parser = LaunchDiagnosticParser::new();
        for chunk in chunks {
            let _ = parser.feed_chunk(chunk);
        }
        parser.finish(termination)
    }

    fn rate_limited(json: &str, termination: ProcessTermination) -> LaunchOutcome {
        parse_chunks(&[json.as_bytes()], termination)
    }

    #[test]
    fn fragmented_canonical_json_is_classified() {
        let json = br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"45s"}]}}"#;
        let parts = json.chunks(3).collect::<Vec<_>>();
        let outcome = parse_chunks(&parts, ProcessTermination::exited(1));
        assert_eq!(
            outcome,
            LaunchOutcome {
                termination: ProcessTermination::exited(1),
                diagnostic: LaunchDiagnostic::RateLimited {
                    retry_after_seconds: 45,
                },
            }
        );
    }

    #[test]
    fn duplicate_keys_are_rejected_at_any_object_depth() {
        let json = br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","status":"RESOURCE_EXHAUSTED"}}"#;
        let outcome = rate_limited(
            std::str::from_utf8(json).expect("fixture is UTF-8"),
            ProcessTermination::exited(1),
        );
        assert_eq!(outcome.diagnostic, LaunchDiagnostic::None);
    }

    #[test]
    fn exit_zero_never_becomes_rate_limited() {
        let json = r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#;
        let outcome = rate_limited(json, ProcessTermination::exited(0));
        assert_eq!(outcome.diagnostic, LaunchDiagnostic::None);
    }

    #[test]
    fn plain_text_and_ansi_are_not_guessed() {
        let outcome = rate_limited(
            "\u{1b}[31m429 RESOURCE_EXHAUSTED\u{1b}[0m",
            ProcessTermination::exited(1),
        );
        assert_eq!(outcome.diagnostic, LaunchDiagnostic::None);
    }

    #[test]
    fn code_status_mismatch_is_not_evidence() {
        let json = r#"{"error":{"code":429,"status":"UNAUTHENTICATED"}}"#;
        let outcome = rate_limited(json, ProcessTermination::exited(1));
        assert_eq!(outcome.diagnostic, LaunchDiagnostic::None);
    }

    #[test]
    fn retry_after_is_clamped_and_defaults() {
        let low = rate_limited(
            r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","Retry-After":1}}"#,
            ProcessTermination::exited(1),
        );
        assert_eq!(
            low.diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: MIN_RETRY_AFTER_SECONDS,
            }
        );

        let high = rate_limited(
            r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","Retry-After":99999}}"#,
            ProcessTermination::exited(1),
        );
        assert_eq!(
            high.diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: MAX_RETRY_AFTER_SECONDS,
            }
        );

        let defaulted = rate_limited(
            r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#,
            ProcessTermination::exited(1),
        );
        assert_eq!(
            defaulted.diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: DEFAULT_RETRY_AFTER_SECONDS,
            }
        );
    }

    #[test]
    fn invalid_utf8_and_incomplete_fragments_are_rejected() {
        let mut parser = LaunchDiagnosticParser::new();
        parser
            .feed_chunk(br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}"#)
            .unwrap();
        let incomplete = parser.try_finish(ProcessTermination::exited(1));
        assert_eq!(incomplete, Err(LaunchDiagnosticParseError::IncompleteJson));

        let mut parser = LaunchDiagnosticParser::new();
        parser.feed_chunk(&[b'{', 0xff]).unwrap();
        assert_eq!(
            parser.try_finish(ProcessTermination::exited(1)),
            Err(LaunchDiagnosticParseError::InvalidUtf8)
        );
    }

    #[test]
    fn oversize_input_is_bounded_and_does_not_leak_data() {
        let mut parser = LaunchDiagnosticParser::new();
        let huge = vec![b'x'; MAX_DIAGNOSTIC_BYTES + 1];
        assert_eq!(
            parser.feed_chunk(&huge),
            Err(LaunchDiagnosticParseError::TooLarge)
        );
        assert_eq!(parser.buffered_len(), 0);
        let debug = format!("{parser:?}");
        assert!(!debug.contains('x'));
        assert_eq!(
            parser.finish(ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None
        );
    }

    #[test]
    fn error_info_reason_must_be_allowlisted() {
        let json = r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"UNKNOWN_SECRET_REASON"}]}}"#;
        let outcome = rate_limited(json, ProcessTermination::exited(1));
        assert_eq!(outcome.diagnostic, LaunchDiagnostic::None);
    }

    #[test]
    fn auth_and_permission_need_canonical_code_and_status() {
        let auth = rate_limited(
            r#"{"error":{"code":401,"status":"UNAUTHENTICATED"}}"#,
            ProcessTermination::exited(1),
        );
        assert_eq!(auth.diagnostic, LaunchDiagnostic::AuthRejected);

        let denied = rate_limited(
            r#"{"error":{"code":403,"status":"PERMISSION_DENIED"}}"#,
            ProcessTermination::exited(1),
        );
        assert_eq!(denied.diagnostic, LaunchDiagnostic::PermissionDenied);
    }

    #[test]
    fn spawn_and_wait_failures_cannot_be_reclassified_from_bytes() {
        let json = r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#;
        for termination in [
            ProcessTermination::spawn_failed(),
            ProcessTermination::wait_failed(),
        ] {
            assert_eq!(
                rate_limited(json, termination).diagnostic,
                LaunchDiagnostic::None
            );
        }
    }
}
