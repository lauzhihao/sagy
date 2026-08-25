//! Bounded, evidence-only observation of an `agy` child process.
//!
//! The launcher must not infer an API outcome from an exit code, a terminal
//! colour sequence, or an arbitrary line of stderr.  This module therefore
//! accepts only a complete, duplicate-free Google JSON error document and
//! keeps no diagnostic text in its public result.
//!
//! Real `agy` interleaves that document with ordinary log lines, so the stream
//! is scanned for complete JSON documents instead of being parsed as one.
//! Surrounding text, chunk boundaries, and a total volume beyond the retention
//! bound therefore cannot hide a document the child actually printed.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Maximum amount of child diagnostic data retained at any moment, and the
/// total child volume beyond which the observation is reported as bounded.
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
/// Feeding a chunk never exposes its content.  Chunks are scanned for complete
/// JSON documents as they arrive and only an unfinished candidate document is
/// retained, so a drain thread can continue until EOF without ever holding
/// more than [`MAX_DIAGNOSTIC_BYTES`] of child output.
pub struct LaunchDiagnosticParser {
    /// 只保留"尚未闭合的候选文档", 不保留整条 stderr。
    /// 这样早期的无关日志无法把后面的限流 JSON 挤出缓冲区。
    pending: Vec<u8>,
    /// 已判定的 canonical 证据。多份同时出现时按固定严重性优先级取一份
    /// (见 [`diagnostic_priority`]), 与出现顺序、chunk 切分都无关,
    /// 子进程无法靠调整输出顺序改变结论。
    found: Option<LaunchDiagnostic>,
    /// 第一个拒绝原因, 只用于 try_finish 的分类, 不含任何子进程字节。
    first_error: Option<LaunchDiagnosticParseError>,
    /// 子进程输出总量是否越过上限。越界只是"证据可能不完整"的告警,
    /// 不再让整条流失效。
    overflowed: bool,
    /// 观测到的总字节数。
    observed: usize,
    /// 增量 UTF-8 校验必须跨 chunk, 否则被切开的多字节字符会被误判为非法。
    utf8: Utf8Tracker,
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
            .field("buffered_len", &self.pending.len())
            .field("rejection", &self.first_error)
            .field("overflowed", &self.overflowed)
            .finish()
    }
}

impl LaunchDiagnosticParser {
    /// Start an empty parser.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            found: None,
            first_error: None,
            overflowed: false,
            observed: 0,
            utf8: Utf8Tracker::default(),
        }
    }

    /// Feed one arbitrary stderr chunk.
    ///
    /// A UTF-8 code point or a JSON token may be split between chunks.  Such
    /// input is never guessed per chunk: the split is resolved by the running
    /// scan once the following bytes arrive.
    ///
    /// `Err(TooLarge)` reports that the child has produced more than
    /// [`MAX_DIAGNOSTIC_BYTES`] in total.  It is advisory: scanning continues,
    /// because a log flood must not be able to hide a later canonical
    /// document.  A drain loop can safely ignore the result.
    pub fn feed_chunk(&mut self, chunk: &[u8]) -> Result<(), LaunchDiagnosticParseError> {
        self.observed = self.observed.saturating_add(chunk.len());
        self.utf8.observe(chunk);
        self.pending.extend_from_slice(chunk);
        self.scan(false);
        if self.observed > MAX_DIAGNOSTIC_BYTES {
            self.overflowed = true;
        }
        if self.overflowed {
            return Err(LaunchDiagnosticParseError::TooLarge);
        }
        Ok(())
    }

    /// Scan the retained bytes for complete JSON documents.
    ///
    /// 逐个候选文档扫描, 而不是对整块 buffer 做一次严格解析: 真实 agy 会在限流
    /// JSON 前后打普通日志, 整块解析会因为尾随内容直接退化成 `None`。
    ///
    /// 定界的取舍是"宁可多跳过, 不可少跳过": 多跳过只会丢失证据(退化成 `None`),
    /// 少跳过会让子进程把一份被拒绝文档的内层对象变成独立证据。
    ///
    /// 但"滞留到 EOF"只允许发生在**真的可能是文档**的候选上。日志正文里的裸
    /// `{` (`agy: applying overrides { model=x`) 一旦也被滞留, 它后面的全部输出
    /// 都会留在缓冲区里, 越过 [`MAX_DIAGNOSTIC_BYTES`] 后连同真实的 429 一起被
    /// 丢掉。因此先用 [`object_start_kind`] 做一次纯语法判定: `{` 后的第一个非
    /// 空白字节只有 `"` 或 `}` 才可能开启一个 JSON 对象, 其余情况这个 `{` 根本
    /// 不是候选文档, 直接前进一个字节, 不产生任何滞留。
    fn scan(&mut self, at_eof: bool) {
        let mut cursor = 0_usize;
        while cursor < self.pending.len() {
            let Some(offset) = self.pending[cursor..].iter().position(|byte| *byte == b'{') else {
                cursor = self.pending.len();
                break;
            };
            let start = cursor + offset;
            match object_start_kind(&self.pending[start..]) {
                // 不是对象开头: 这只是日志正文里的一个字符。但**不能**只前进
                // 1 字节 -- 那样游标会落进这个 `{` 的内部, 于是
                // `{m:1,"r":{"error":{"code":429,...}}}` 的内层对象会被当成
                // 独立证据, 重新打开"被拒绝的外层文档夹带内层文档"这个洞。
                // 跳过范围与下面解析失败的分支保持一致。
                ObjectStart::Impossible => {
                    match candidate_document_extent(&self.pending[start..]) {
                        // 结构上已经闭合: 整块跳过, 内层不再单独成为证据。
                        Some(length) => cursor = start.saturating_add(length),
                        // 未闭合但本行已经结束(或流已结束): agy 的日志按行输出,
                        // 一个不配对的 `{` 只属于它所在的那一行, 跳到行尾即可 --
                        // 既不会落进本行内部, 也不会把后面几行真实的限流 JSON
                        // 挡在缓冲区里。
                        None if at_eof || self.pending[start..].contains(&b'\n') => {
                            cursor = start.saturating_add(rest_of_line(&self.pending[start..]));
                        }
                        // 本行还没收完: 后续字节可能把它闭合, 此刻从任何位置继续
                        // 都可能落进它的内部。等下一个 chunk, 结论只依赖字节内容,
                        // 与 chunk 切分无关。
                        None => {
                            cursor = start;
                            break;
                        }
                    }
                    continue;
                }
                // 只看到 `{` 和空白: 判定所需的字节还没到齐。流已结束就说明它
                // 永远不会是文档, 否则等下一个 chunk (结论只依赖字节内容, 与
                // chunk 切分无关)。
                ObjectStart::Undecided => {
                    if at_eof {
                        cursor = start.saturating_add(1);
                        continue;
                    }
                    cursor = start;
                    break;
                }
                ObjectStart::Possible => {}
            }
            match parse_first_value(&self.pending[start..]) {
                Ok((value, consumed)) => {
                    match classify_google_error(&value) {
                        Ok(diagnostic) => self.merge(diagnostic),
                        Err(error) => self.record(error),
                    }
                    // 文档已完整解析: 从它之后继续, 不把它的嵌套对象重新当成
                    // 独立证据, 否则一份被拒绝的外层文档可以夹带内层文档。
                    cursor = start.saturating_add(consumed.max(1));
                }
                Err(LaunchDiagnosticParseError::IncompleteJson) if !at_eof => {
                    cursor = start;
                    break;
                }
                Err(error) => {
                    self.record(error);
                    // 解析失败的分支必须和成功分支一样整块跳过候选文档。只前进
                    // 1 字节的话, 一份因重复键/非法转义/超深嵌套被拒绝的外层
                    // 文档, 它的内层对象会被当成独立证据重新扫描, 子进程就能
                    // 用 `{"m":1,"m":2,"r":{"error":{"code":429,...}}}` 伪造限流。
                    match candidate_document_extent(&self.pending[start..]) {
                        // 候选文档已经结构闭合: 边界就是配对的那个 `}`, 整体跳过。
                        Some(length) => cursor = start.saturating_add(length),
                        // 尚未闭合且流还没结束: 后续字节可能把它补全, 此刻从任何
                        // 位置继续都可能落进它的内部, 所以等下一个 chunk 再判定。
                        // 这保证结论与 chunk 切分无关。
                        None if !at_eof => {
                            cursor = start;
                            break;
                        }
                        // 流已结束仍未闭合: 这个 `{` 根本不是文档开头, 只是日志
                        // 正文里的字符。agy 的日志是按行输出的, 跳到行尾即可 --
                        // 既不会重新进入本行内部, 也不会吞掉后面几行里真实的
                        // 限流 JSON。
                        None => {
                            cursor = start.saturating_add(rest_of_line(&self.pending[start..]));
                        }
                    }
                }
            }
        }
        let cursor = cursor.min(self.pending.len());
        self.pending.drain(..cursor);
        if self.pending.len() > MAX_DIAGNOSTIC_BYTES {
            // 单个候选文档超过上限: 只丢弃这个候选, 后续输出仍然被扫描。
            self.pending.clear();
            self.overflowed = true;
        }
    }

    fn record(&mut self, error: LaunchDiagnosticParseError) {
        if self.first_error.is_none() {
            self.first_error = Some(error);
        }
    }

    /// 合并一份新的 canonical 证据。
    ///
    /// 判定用固定的严重性优先级而不是出现顺序 (见 [`diagnostic_priority`]),
    /// 所以结论与文档顺序、chunk 切分都无关。同优先级保留先到的那份, 这样
    /// 第一份 429 的 retry 提示是确定的。
    fn merge(&mut self, diagnostic: LaunchDiagnostic) {
        let keep_existing = self.found.as_ref().is_some_and(|existing| {
            diagnostic_priority(existing) >= diagnostic_priority(&diagnostic)
        });
        if !keep_existing {
            self.found = Some(diagnostic);
        }
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
        self.pending.len()
    }

    /// Whether the child crossed the diagnostic byte bound.  Evidence that was
    /// scanned before or after the bound was crossed is still reported.
    pub const fn is_rejected(&self) -> bool {
        self.overflowed
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
        mut self,
        termination: ProcessTermination,
    ) -> Result<LaunchOutcome, LaunchDiagnosticParseError> {
        self.scan(true);
        self.utf8.finish();

        let outcome = LaunchOutcome {
            termination,
            diagnostic: LaunchDiagnostic::None,
        };

        if let Some(diagnostic) = self.found {
            // Spawn/wait failures and a clean child exit do not prove anything
            // about a child API result, even when the stream did contain a
            // canonical document.
            if !termination.has_child_failure() {
                return Ok(outcome);
            }
            return Ok(LaunchOutcome {
                termination,
                diagnostic,
            });
        }

        if self.utf8.invalid {
            return Err(LaunchDiagnosticParseError::InvalidUtf8);
        }
        if let Some(error) = self.first_error {
            return Err(error);
        }
        if self.overflowed {
            return Err(LaunchDiagnosticParseError::TooLarge);
        }
        Ok(outcome)
    }
}

/// Incremental UTF-8 validity over the whole child stream.
///
/// 一个多字节字符可能被切在 chunk 边界上, 逐 chunk 校验会把它误判成非法字节,
/// 所以未完成的尾部序列必须留到下一个 chunk 再判定。
#[derive(Default)]
struct Utf8Tracker {
    tail: Vec<u8>,
    invalid: bool,
}

impl Utf8Tracker {
    fn observe(&mut self, chunk: &[u8]) {
        if self.invalid {
            return;
        }
        let mut buffer = std::mem::take(&mut self.tail);
        buffer.extend_from_slice(chunk);
        if let Err(error) = std::str::from_utf8(&buffer) {
            if error.error_len().is_some() {
                self.invalid = true;
                return;
            }
            self.tail = buffer[error.valid_up_to()..].to_vec();
        }
    }

    fn finish(&mut self) {
        if !self.tail.is_empty() {
            self.invalid = true;
        }
    }
}

/// Fixed severity order used when a stream contains more than one canonical
/// document: `AuthRejected` > `PermissionDenied` > `RateLimited`.
///
/// 判定按"是否需要用户介入"排序, 而不是按出现顺序 —— 顺序由子进程控制, 不能
/// 决定结论。同时出现 401 与 429 时必须偏向 401:
/// * 429 只产生一段有上界的 cooldown, 到期后账号会被重新选中。若真实原因是
///   token 失效, 用户永远看不到"该重新登录", 账号在每个 cooldown 之后继续被
///   选中、继续失败, 失败是**静默且无限重复**的。
/// * 反过来, 把一次真实限流记成认证失效, 代价是一次多余的重新登录提示 ——
///   可见、一次性、且不会丢失任何凭据。
///
/// 因此严重性上让"需要人工介入"的结论优先: 403 同理 (配额/账单/权限问题不会
/// 自愈), 只是比 401 弱一档。
const fn diagnostic_priority(diagnostic: &LaunchDiagnostic) -> u8 {
    match diagnostic {
        LaunchDiagnostic::None => 0,
        LaunchDiagnostic::RateLimited { .. } => 1,
        LaunchDiagnostic::PermissionDenied => 2,
        LaunchDiagnostic::AuthRejected => 3,
    }
}

/// Whether a `{` can still start a JSON object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectStart {
    /// The next non-whitespace byte can open a member or close an empty object.
    Possible,
    /// The next non-whitespace byte is illegal in JSON right after `{`.
    Impossible,
    /// Only `{` and whitespace have been observed so far.
    Undecided,
}

/// Classify the bytes that follow `bytes[0] == b'{'`.
///
/// JSON 只允许 `{` 之后出现 `"` (成员键) 或 `}` (空对象)。这是纯语法事实, 不是
/// 启发式: 其余任何字节都注定让这个候选解析失败, 所以它不值得占用缓冲区。
fn object_start_kind(bytes: &[u8]) -> ObjectStart {
    for byte in bytes.iter().skip(1) {
        if byte.is_ascii_whitespace() {
            continue;
        }
        return if *byte == b'"' || *byte == b'}' {
            ObjectStart::Possible
        } else {
            ObjectStart::Impossible
        };
    }
    ObjectStart::Undecided
}

/// Byte length of the candidate document that starts at `bytes[0] == b'{'`,
/// counted up to and including its matching `}`.
///
/// Returns `None` when the candidate never closes inside `bytes`.
///
/// 只做括号配对 + 字符串/转义状态跟踪, 不复用 serde: 候选文档正是因为解析
/// 失败才需要定界, 而失败的原因可能出现在文档的任何位置, 解析器的错误位置
/// (例如重复键在最外层, 内层对象在它之后) 无法界定文档的右边界。
fn candidate_document_extent(bytes: &[u8]) -> Option<usize> {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index.saturating_add(1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Byte length of the remainder of the log line that starts at `bytes[0]`,
/// including its terminating newline.  Always at least one byte, so a scan
/// that uses it makes progress.
fn rest_of_line(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len().max(1), |index| index.saturating_add(1))
}

/// Parse exactly one JSON value from the front of `bytes`.
///
/// Returns the value and the number of bytes it consumed, so the caller can
/// resume scanning after a complete document instead of guessing its extent
/// from brace counting.
fn parse_first_value(bytes: &[u8]) -> Result<(Value, usize), LaunchDiagnosticParseError> {
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<NoDuplicateValue>();
    match stream.next() {
        Some(Ok(value)) => Ok((value.0, stream.byte_offset())),
        Some(Err(error)) => Err(map_json_error(error)),
        None => Err(LaunchDiagnosticParseError::IncompleteJson),
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

    const NOISY_RATE_LIMIT: &str =
        r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","Retry-After":45}}"#;

    #[test]
    fn rate_limit_document_surrounded_by_plain_logs_is_classified() {
        let stream = format!(
            "agy: loading workspace config\nagy: contacting backend\n{NOISY_RATE_LIMIT}\nagy: shutting down\n"
        );
        let outcome = rate_limited(&stream, ProcessTermination::exited(1));
        assert_eq!(
            outcome.diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );
    }

    #[test]
    fn chunk_split_inside_a_multibyte_character_still_yields_evidence() {
        // 限流 JSON 前后各有一个多字节字符, 且被逐字节切开; 逐 chunk 的 UTF-8
        // 判定会在这里误判, 跨 chunk 的增量判定不会。
        let stream = format!("\u{6e2c}\u{8a66}\n{NOISY_RATE_LIMIT}\n\u{7d50}\u{675f}\n");
        let bytes = stream.as_bytes();
        let parts = bytes.chunks(1).collect::<Vec<_>>();
        let outcome = parse_chunks(&parts, ProcessTermination::exited(1));
        assert_eq!(
            outcome.diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );

        // 同一份输入按 7 字节切开, 边界落在别处, 结论必须一致。
        let parts = bytes.chunks(7).collect::<Vec<_>>();
        assert_eq!(
            parse_chunks(&parts, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );
    }

    #[test]
    fn log_flood_beyond_the_bound_cannot_evict_a_later_rate_limit_document() {
        let mut parser = LaunchDiagnosticParser::new();
        let noise = vec![b'n'; 8 * 1024];
        for _ in 0..16 {
            let _ = parser.feed_chunk(&noise);
        }
        assert!(parser.is_rejected(), "the bound must have been crossed");
        assert_eq!(parser.buffered_len(), 0, "noise must not be retained");
        let _ = parser.feed_chunk(NOISY_RATE_LIMIT.as_bytes());
        let outcome = parser.finish(ProcessTermination::exited(1));
        assert_eq!(
            outcome.diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );
    }

    #[test]
    fn a_single_candidate_larger_than_the_bound_is_dropped_without_stopping_the_scan() {
        let mut parser = LaunchDiagnosticParser::new();
        let mut giant = Vec::with_capacity(MAX_DIAGNOSTIC_BYTES + 64);
        giant.extend_from_slice(br#"{"error":{"note":""#);
        giant.extend(std::iter::repeat_n(b'g', MAX_DIAGNOSTIC_BYTES + 1));
        let _ = parser.feed_chunk(&giant);
        assert_eq!(
            parser.buffered_len(),
            0,
            "oversize candidate must be dropped"
        );
        let _ = parser.feed_chunk(b"\"}}\n");
        let _ = parser.feed_chunk(NOISY_RATE_LIMIT.as_bytes());
        assert_eq!(
            parser.finish(ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );
    }

    #[test]
    fn non_rate_limit_failures_are_never_reported_as_rate_limited() {
        let cases = [
            r#"agy: fatal: {"error":{"code":401,"status":"UNAUTHENTICATED"}} bye"#,
            r#"log line
{"error":{"code":403,"status":"PERMISSION_DENIED"}}
log line"#,
            "thread 'main' panicked at agy.rs:1:1: 429 quota { not json }",
            r#"{"error":{"code":500,"status":"INTERNAL","message":"429 RESOURCE_EXHAUSTED"}}"#,
            r#"{"message":"429 RESOURCE_EXHAUSTED","level":"error"}"#,
        ];
        let expected = [
            LaunchDiagnostic::AuthRejected,
            LaunchDiagnostic::PermissionDenied,
            LaunchDiagnostic::None,
            LaunchDiagnostic::None,
            LaunchDiagnostic::None,
        ];
        for (stream, expected) in cases.into_iter().zip(expected) {
            let outcome = rate_limited(stream, ProcessTermination::exited(1));
            assert_eq!(outcome.diagnostic, expected, "stream: {stream}");
            assert!(outcome.diagnostic.retry_after_seconds().is_none());
        }
    }

    #[test]
    fn a_rejected_outer_document_cannot_smuggle_a_nested_one() {
        // 外层文档解析成功但不 canonical 时, 不再从它内部重新扫描。
        let json = r#"{"outer":{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}}"#;
        let outcome = rate_limited(json, ProcessTermination::exited(1));
        assert_eq!(outcome.diagnostic, LaunchDiagnostic::None);
    }

    /// 外层文档被**拒绝**(不是被接受)时的同一个不变量。这是 R5-1 的 PoC:
    /// 只前进 1 字节会让内层对象变成独立证据。
    const SMUGGLED_RATE_LIMIT: &str =
        r#"{"m":1,"m":2,"r":{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}}"#;

    #[test]
    fn a_rejected_outer_document_cannot_smuggle_a_nested_one_through_the_error_path() {
        let outcome = rate_limited(SMUGGLED_RATE_LIMIT, ProcessTermination::exited(1));
        assert_eq!(
            outcome.diagnostic,
            LaunchDiagnostic::None,
            "a duplicate-key document must not donate its nested object as evidence"
        );

        // 同样的输入夹在普通日志中间, 结论必须一致。
        let framed = format!("agy: contacting backend\n{SMUGGLED_RATE_LIMIT}\nagy: bye\n");
        assert_eq!(
            rate_limited(&framed, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None
        );
    }

    /// `ObjectStart::Impossible` 的 PoC: 外层在**第一个 token** 就非法, 因此
    /// 连 `parse_first_value` 都走不到。只前进 1 字节的话游标会落进它内部,
    /// 内层的 canonical 文档就变成了独立证据。
    const IMPOSSIBLE_OUTER_RATE_LIMIT: &str =
        r#"{m:1,"r":{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}}"#;

    #[test]
    fn an_impossible_object_start_cannot_smuggle_a_nested_document() {
        assert_eq!(
            object_start_kind(IMPOSSIBLE_OUTER_RATE_LIMIT.as_bytes()),
            ObjectStart::Impossible
        );
        assert_eq!(
            rate_limited(IMPOSSIBLE_OUTER_RATE_LIMIT, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None,
            "an unparsable outer brace must not donate its nested object as evidence"
        );

        // 真实日志形态: 内层是 401, 同样不得被采信。
        let logged =
            "agy: ctx { last={\"error\":{\"code\":401,\"status\":\"UNAUTHENTICATED\"}} }\n";
        assert_eq!(
            rate_limited(logged, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None
        );

        // 夹在普通日志中间, 以及逐个 chunk 边界, 结论都必须一致。
        let framed = format!("agy: start\n{IMPOSSIBLE_OUTER_RATE_LIMIT}\nagy: bye\n");
        assert_eq!(
            rate_limited(&framed, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None
        );
        for size in [1_usize, 2, 3, 5, 7, 11, 17, 31] {
            let bytes = framed.as_bytes();
            let parts = bytes.chunks(size).collect::<Vec<_>>();
            assert_eq!(
                parse_chunks(&parts, ProcessTermination::exited(1)).diagnostic,
                LaunchDiagnostic::None,
                "chunk size {size} allowed an impossible-start smuggle"
            );
        }
    }

    #[test]
    fn an_unparsable_log_brace_still_does_not_swallow_a_later_rate_limit() {
        // 反向保证: 修 R11-2.2 不能把 R11-2.1 又弄坏 -- 前一行的裸 `{` 只属于
        // 那一行, 后面几行里真实的限流 JSON 仍须被识别。
        let canonical = r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#;
        let stream = format!("agy: overrides {{ model=x\nagy: still working\n{canonical}\n");
        assert!(matches!(
            rate_limited(&stream, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited { .. }
        ));
    }

    #[test]
    fn smuggling_stays_rejected_at_every_chunk_boundary() {
        // 逐字节以及若干个不同步长: 定界必须与 chunk 切分无关, 否则子进程只要
        // 控制 flush 的位置就能把外层文档切成"先报错再补全"两段。
        for size in [1_usize, 2, 3, 5, 7, 11, 17, 31] {
            let bytes = SMUGGLED_RATE_LIMIT.as_bytes();
            let parts = bytes.chunks(size).collect::<Vec<_>>();
            assert_eq!(
                parse_chunks(&parts, ProcessTermination::exited(1)).diagnostic,
                LaunchDiagnostic::None,
                "chunk size {size} allowed a smuggled document"
            );
        }
    }

    #[test]
    fn an_invalid_escape_in_an_outer_document_cannot_smuggle_a_nested_one() {
        // 非法转义与超深嵌套走的是同一条错误路径。
        let invalid_escape =
            r#"{"note":"\x","r":{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}}"#;
        assert_eq!(
            rate_limited(invalid_escape, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None
        );

        let mut deep = String::new();
        for _ in 0..200 {
            deep.push_str("{\"a\":");
        }
        deep.push_str(r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#);
        for _ in 0..200 {
            deep.push('}');
        }
        assert_eq!(
            rate_limited(&deep, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None
        );
    }

    #[test]
    fn a_stray_brace_in_a_log_line_does_not_hide_a_later_rate_limit_document() {
        // 定界不能退化成"从这个 `{` 一路吞到流末尾": 真实日志里出现一个不配对的
        // `{` 之后, 后面几行里的限流 JSON 仍须被识别。
        let stream = format!("agy: applying overrides {{ model=x\n{NOISY_RATE_LIMIT}\nagy: bye\n");
        assert_eq!(
            rate_limited(&stream, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );
    }

    /// AC-R11-3.1: 同一次运行里同时出现 401 与 429 时, 结论必须是"需要用户
    /// 介入"的那一个。429 会退化成一段 cooldown, 到期后账号被重新选中并继续
    /// 失败, 用户永远收不到"该重新登录"的提示。
    #[test]
    fn a_child_cannot_downgrade_an_authentication_failure_into_a_cooldown() {
        let auth = r#"{"error":{"code":401,"status":"UNAUTHENTICATED"}}"#;
        let denied = r#"{"error":{"code":403,"status":"PERMISSION_DENIED"}}"#;
        // 顺序由子进程控制, 不能决定结论: 两种顺序都必须判成认证失效。
        for stream in [
            format!("{NOISY_RATE_LIMIT}\nagy: retrying\n{auth}\n"),
            format!("{auth}\nagy: retrying\n{NOISY_RATE_LIMIT}\n"),
            format!("{denied}\n{auth}\n{NOISY_RATE_LIMIT}\n"),
        ] {
            let diagnostic = rate_limited(&stream, ProcessTermination::exited(1)).diagnostic;
            assert_eq!(
                diagnostic,
                LaunchDiagnostic::AuthRejected,
                "stream: {stream}"
            );
            assert!(
                diagnostic.retry_after_seconds().is_none(),
                "an authentication failure must not carry a cooldown hint"
            );
        }

        // 403 同样不会自愈, 也必须压过 429。
        for stream in [
            format!("{NOISY_RATE_LIMIT}\n{denied}\n"),
            format!("{denied}\n{NOISY_RATE_LIMIT}\n"),
        ] {
            assert_eq!(
                rate_limited(&stream, ProcessTermination::exited(1)).diagnostic,
                LaunchDiagnostic::PermissionDenied,
                "stream: {stream}"
            );
        }

        // 401 与 403 之间同样按严重性判定, 与顺序无关。
        for stream in [format!("{auth}\n{denied}\n"), format!("{denied}\n{auth}\n")] {
            assert_eq!(
                rate_limited(&stream, ProcessTermination::exited(1)).diagnostic,
                LaunchDiagnostic::AuthRejected,
                "stream: {stream}"
            );
        }
    }

    /// AC-R11-3.2: 只出现 429 时行为不变 —— 仍然是带 retry 提示的限流。
    #[test]
    fn a_lone_rate_limit_document_still_yields_a_cooldown() {
        let stream = format!("agy: contacting backend\n{NOISY_RATE_LIMIT}\nagy: bye\n");
        assert_eq!(
            rate_limited(&stream, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );
    }

    /// AC-R11-2.1: 一行裸 `{` 的日志之后仍然可能跟着真实的限流 JSON。
    ///
    /// 分三块喂: 裸 `{` 日志行 -> 恰好把缓冲区顶到上限边缘的日志 -> 限流 JSON。
    /// 只要裸 `{` 被当成候选文档滞留, 第三块就会把 pending 顶过
    /// [`MAX_DIAGNOSTIC_BYTES`], 缓冲区被整体丢弃, 证据一起消失。
    #[test]
    fn a_stray_brace_cannot_park_the_buffer_until_a_later_rate_limit_is_discarded() {
        let stray = b"agy: applying overrides { model=x\n";
        let document = format!("{NOISY_RATE_LIMIT}\n");
        let filler = MAX_DIAGNOSTIC_BYTES - stray.len() - document.len() / 2;
        let mut parser = LaunchDiagnosticParser::new();
        let _ = parser.feed_chunk(stray);
        let _ = parser.feed_chunk(&vec![b'n'; filler]);
        assert!(
            !parser.is_rejected(),
            "the fixture must stay under the bound until the document arrives"
        );
        let _ = parser.feed_chunk(document.as_bytes());
        assert_eq!(
            parser.finish(ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            },
            "a stray brace hid the rate-limit document that followed it"
        );
    }

    /// 同一个不变量的流式版本: 裸 `{` 之后无论跟多少日志, 缓冲区都不该增长。
    #[test]
    fn a_stray_brace_is_not_retained_in_the_buffer() {
        let mut parser = LaunchDiagnosticParser::new();
        let _ = parser.feed_chunk(b"agy: applying overrides { model=x\n");
        assert_eq!(parser.buffered_len(), 0, "a log brace must not be retained");
        for _ in 0..16 {
            let _ = parser.feed_chunk(&vec![b'n'; 8 * 1024]);
            // 总量越界只是"证据可能不完整"的告警; 关键是没有任何字节被滞留,
            // 所以后面的限流 JSON 不会被那次丢弃带走。
            assert_eq!(parser.buffered_len(), 0, "log noise must not be retained");
        }
        let _ = parser.feed_chunk(NOISY_RATE_LIMIT.as_bytes());
        assert_eq!(
            parser.finish(ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
            }
        );
    }

    /// AC-R11-2.2: 语法预判定不得放松嵌套走私的防线 —— 走私文档以 `{"` 开头,
    /// 仍然走完整的"整块跳过"路径。
    #[test]
    fn the_object_start_check_does_not_reopen_the_smuggling_hole() {
        assert_eq!(
            object_start_kind(SMUGGLED_RATE_LIMIT.as_bytes()),
            ObjectStart::Possible
        );
        assert_eq!(
            object_start_kind(b"{ model=x"),
            ObjectStart::Impossible,
            "a log brace is not a document start"
        );
        assert_eq!(object_start_kind(b"{ \n\t"), ObjectStart::Undecided);
        assert_eq!(object_start_kind(b"{}"), ObjectStart::Possible);

        // 裸 `{` 与走私文档同时出现: 前者被跳过, 后者仍必须被拒绝。
        let stream = format!("agy: overrides {{ model=x\n{SMUGGLED_RATE_LIMIT}\n");
        assert_eq!(
            rate_limited(&stream, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::None
        );
        for size in [1_usize, 2, 3, 5, 7, 11, 17, 31] {
            let parts = stream.as_bytes().chunks(size).collect::<Vec<_>>();
            assert_eq!(
                parse_chunks(&parts, ProcessTermination::exited(1)).diagnostic,
                LaunchDiagnostic::None,
                "chunk size {size} allowed a smuggled document"
            );
        }
    }

    #[test]
    fn the_first_document_of_the_same_kind_keeps_its_retry_hint() {
        let stream = format!(
            "{NOISY_RATE_LIMIT}\nagy: retrying\n{}\n",
            r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","Retry-After":3600}}"#
        );
        assert_eq!(
            rate_limited(&stream, ProcessTermination::exited(1)).diagnostic,
            LaunchDiagnostic::RateLimited {
                retry_after_seconds: 45,
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
