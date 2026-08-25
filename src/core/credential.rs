//! Portable credential values used by state and repository synchronization.
//!
//! The module deliberately keeps credentials separate from filesystem paths and
//! from the legacy `AccountRecord`.  It is a small, versioned domain value that
//! can be validated before it is persisted or transported.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// The only credential schema currently understood by this binary.
pub const CREDENTIAL_SCHEMA_VERSION: u32 = 1;

/// Maximum encoded size accepted for a portable credential.
pub const MAX_CREDENTIAL_SERIALIZED_BYTES: usize = 256 * 1024;

/// Maximum UTF-8 byte length of one string field or object key.
pub const MAX_CREDENTIAL_FIELD_BYTES: usize = 16 * 1024;

/// Maximum nesting depth of a credential JSON value.
pub const MAX_CREDENTIAL_NESTING_DEPTH: usize = 16;

/// Maximum number of members in one object or items in one array.
pub const MAX_CREDENTIAL_CONTAINER_ITEMS: usize = 256;

const MAX_CREDENTIAL_VALUES: usize = 4096;
const FINGERPRINT_DOMAIN: &[u8] = b"sagy-portable-credential\0v1\0";

/// Every Google authentication variable a launched child must never inherit.
///
/// 收口策略是 deny-by-default：子进程环境先清空这张表里的**全部**变量，之后再由
/// 启动方按当前账号显式写回需要的那几个。旧实现只清 3 个变量的 allowlist，
/// 父进程里的 `GOOGLE_API_KEY` / `GOOGLE_GENAI_USE_VERTEXAI` /
/// `GOOGLE_CLOUD_LOCATION` 会原样继承下去，从而用与当前账号无关的凭据发请求。
/// 保持 ASCII、去重且按字典序排列，方便调用方直接遍历。
pub const GOOGLE_AUTH_ENV_VARS: &[&str] = &[
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "CLOUDSDK_CORE_PROJECT",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_ACCESS_TOKEN",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "GOOGLE_GENAI_USE_GCA",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
];

/// Report whether a variable name belongs to the Google authentication surface
/// that a launched child must not inherit.
pub fn is_google_auth_env_var(name: &str) -> bool {
    GOOGLE_AUTH_ENV_VARS.contains(&name)
}

/// The four credential payloads that can be transported by the portable schema.
///
/// JSON documents are kept as complete maps for the two document variants.  In
/// particular, fields unknown to sagy survive a deserialize/serialize cycle.
/// The fields are private so values cannot be constructed without validation.
#[derive(Clone, PartialEq)]
pub enum CredentialPayload {
    OAuthAccessToken(String),
    OAuthAuthorizedUser(Map<String, Value>),
    ApiKey(Map<String, Value>),
    VertexServiceAccount(Map<String, Value>),
}

impl CredentialPayload {
    /// Return the stable schema tag for this payload.
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::OAuthAccessToken(_) => CredentialKind::OAuthAccessToken,
            Self::OAuthAuthorizedUser(_) => CredentialKind::OAuthAuthorizedUser,
            Self::ApiKey(_) => CredentialKind::ApiKey,
            Self::VertexServiceAccount(_) => CredentialKind::VertexServiceAccount,
        }
    }

    /// Return the raw OAuth access token, if this is the raw-token variant.
    pub fn oauth_access_token(&self) -> Option<&str> {
        match self {
            Self::OAuthAccessToken(token) => Some(token),
            _ => None,
        }
    }

    /// Return the complete authorized-user JSON object, if present.
    pub fn oauth_authorized_user(&self) -> Option<&Map<String, Value>> {
        match self {
            Self::OAuthAuthorizedUser(document) => Some(document),
            _ => None,
        }
    }

    /// Return the complete API-key JSON object, if present.
    pub fn api_key_document(&self) -> Option<&Map<String, Value>> {
        match self {
            Self::ApiKey(document) => Some(document),
            _ => None,
        }
    }

    /// Return the complete service-account JSON object, if present.
    pub fn vertex_service_account(&self) -> Option<&Map<String, Value>> {
        match self {
            Self::VertexServiceAccount(document) => Some(document),
            _ => None,
        }
    }
}

impl fmt::Debug for CredentialPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = self.kind();
        match self {
            Self::OAuthAccessToken(_) => formatter
                .debug_struct("CredentialPayload")
                .field("kind", &kind)
                .field("access_token", &"<redacted>")
                .finish(),
            Self::OAuthAuthorizedUser(document)
            | Self::ApiKey(document)
            | Self::VertexServiceAccount(document) => formatter
                .debug_struct("CredentialPayload")
                .field("kind", &kind)
                .field("fields", &document.keys().collect::<Vec<_>>())
                .finish(),
        }
    }
}

/// Stable wire tags for [`CredentialPayload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialKind {
    OAuthAccessToken,
    OAuthAuthorizedUser,
    ApiKey,
    VertexServiceAccount,
}

impl CredentialKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OAuthAccessToken => "oauth_access_token",
            Self::OAuthAuthorizedUser => "oauth_authorized_user",
            Self::ApiKey => "api_key",
            Self::VertexServiceAccount => "vertex_service_account",
        }
    }

    fn parse(value: &str) -> Result<Self, CredentialError> {
        match value {
            "oauth_access_token" => Ok(Self::OAuthAccessToken),
            "oauth_authorized_user" => Ok(Self::OAuthAuthorizedUser),
            "api_key" => Ok(Self::ApiKey),
            "vertex_service_account" => Ok(Self::VertexServiceAccount),
            _ => Err(CredentialError::InvalidKind),
        }
    }
}

/// Versioned, path-free portable credential.
#[derive(Clone, PartialEq)]
pub struct PortableCredential {
    schema_version: u32,
    payload: CredentialPayload,
}

impl PortableCredential {
    /// Construct a raw OAuth access-token credential.
    pub fn oauth_access_token(access_token: impl Into<String>) -> Result<Self, CredentialError> {
        let token = access_token.into();
        let payload = CredentialPayload::OAuthAccessToken(token);
        Self::new(payload)
    }

    /// Construct an authorized-user credential from its complete JSON object.
    pub fn oauth_authorized_user(document: Value) -> Result<Self, CredentialError> {
        Self::new(CredentialPayload::OAuthAuthorizedUser(object(document)?))
    }

    /// Construct an API-key credential from its complete JSON object.
    pub fn api_key(api_key: impl Into<String>) -> Result<Self, CredentialError> {
        let mut document = Map::new();
        document.insert("api_key".to_string(), Value::String(api_key.into()));
        Self::new(CredentialPayload::ApiKey(document))
    }

    /// Construct an API-key credential while retaining non-secret metadata.
    pub fn api_key_document(document: Value) -> Result<Self, CredentialError> {
        Self::new(CredentialPayload::ApiKey(object(document)?))
    }

    /// Construct a Vertex service-account credential from its complete JSON object.
    pub fn vertex_service_account(document: Value) -> Result<Self, CredentialError> {
        Self::new(CredentialPayload::VertexServiceAccount(object(document)?))
    }

    /// Parse a raw authorized-user JSON document.
    pub fn parse_oauth_authorized_user_json(input: &str) -> Result<Self, CredentialError> {
        let value = parse_strict_json(input)?;
        Self::oauth_authorized_user(value)
    }

    /// Parse a raw Vertex service-account JSON document.
    pub fn parse_vertex_service_account_json(input: &str) -> Result<Self, CredentialError> {
        let value = parse_strict_json(input)?;
        Self::vertex_service_account(value)
    }

    /// Parse a provider-native credential document.
    ///
    /// The portable envelope and provider-native documents intentionally use
    /// different entry points.  This method accepts an envelope as a
    /// convenience for import callers, but always validates the resulting
    /// payload with the same strict rules (duplicate keys, bounded values and
    /// the minimum fields for the selected provider type).
    pub fn from_native_json_str(input: &str) -> Result<Self, CredentialError> {
        let value = parse_strict_json(input)?;
        if let Value::Object(object) = &value {
            if object.contains_key("schema_version")
                || object.contains_key("kind")
                || object.contains_key("payload")
            {
                return Self::from_value(value);
            }

            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "authorized_user")
            {
                return Self::oauth_authorized_user(value);
            }
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind == "service_account")
            {
                return Self::vertex_service_account(value);
            }
            if object.get("api_key").is_some() {
                return Self::api_key_document(value);
            }
        }
        Err(CredentialError::InvalidEnvelope)
    }

    /// Return this credential as the provider-native JSON document.
    ///
    /// Raw OAuth access tokens have no JSON representation in the fixed
    /// credential layout and therefore return `InvalidEnvelope`.
    pub fn to_native_json_string(&self) -> Result<String, CredentialError> {
        let value = match &self.payload {
            CredentialPayload::OAuthAccessToken(_) => return Err(CredentialError::InvalidEnvelope),
            CredentialPayload::OAuthAuthorizedUser(document)
            | CredentialPayload::ApiKey(document)
            | CredentialPayload::VertexServiceAccount(document) => Value::Object(document.clone()),
        };
        let bytes = serde_json::to_vec(&value).map_err(|_| CredentialError::SerializationFailed)?;
        if bytes.len() > MAX_CREDENTIAL_SERIALIZED_BYTES {
            return Err(CredentialError::SerializedTooLarge);
        }
        String::from_utf8(bytes).map_err(|_| CredentialError::SerializationFailed)
    }

    /// Return the access token carried by either OAuth payload.
    pub fn access_token(&self) -> Option<&str> {
        match &self.payload {
            CredentialPayload::OAuthAccessToken(token) => Some(token),
            CredentialPayload::OAuthAuthorizedUser(document) => document
                .get("access_token")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty()),
            _ => None,
        }
    }

    /// Return the refresh token carried by an authorized-user payload.
    pub fn refresh_token(&self) -> Option<&str> {
        match &self.payload {
            CredentialPayload::OAuthAuthorizedUser(document) => document
                .get("refresh_token")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty()),
            _ => None,
        }
    }

    /// Return an API key payload's secret, if this is an API credential.
    pub fn api_key_value(&self) -> Option<&str> {
        match &self.payload {
            CredentialPayload::ApiKey(document) => document
                .get("api_key")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty()),
            _ => None,
        }
    }

    /// Return a copy of this authorized-user credential with a new access
    /// token while retaining refresh/client/unknown provider fields.
    pub fn with_access_token(
        &self,
        access_token: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let access_token = access_token.into();
        if access_token.trim().is_empty() {
            return Err(CredentialError::EmptyField("access_token"));
        }
        let CredentialPayload::OAuthAuthorizedUser(document) = &self.payload else {
            return Err(CredentialError::InvalidKind);
        };
        let mut updated = document.clone();
        updated.insert("access_token".to_string(), Value::String(access_token));
        Self::oauth_authorized_user(Value::Object(updated))
    }

    /// Borrow a provider-native object for callers that need to retain its
    /// complete unknown-field set.
    pub fn native_document(&self) -> Option<&Map<String, Value>> {
        match &self.payload {
            CredentialPayload::OAuthAuthorizedUser(document)
            | CredentialPayload::ApiKey(document)
            | CredentialPayload::VertexServiceAccount(document) => Some(document),
            CredentialPayload::OAuthAccessToken(_) => None,
        }
    }

    /// Parse a versioned portable credential document.
    pub fn from_json_str(input: &str) -> Result<Self, CredentialError> {
        if input.len() > MAX_CREDENTIAL_SERIALIZED_BYTES {
            return Err(CredentialError::SerializedTooLarge);
        }
        parse_strict_json(input).and_then(Self::from_value)
    }

    /// Return the independent schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return the tagged payload kind.
    pub const fn kind(&self) -> CredentialKind {
        self.payload.kind()
    }

    /// Borrow the validated payload.
    pub fn payload(&self) -> &CredentialPayload {
        &self.payload
    }

    /// Return a canonical JSON representation and enforce its size bound.
    pub fn to_json_string(&self) -> Result<String, CredentialError> {
        let value = self.to_value()?;
        let bytes = serde_json::to_vec(&value).map_err(|_| CredentialError::SerializationFailed)?;
        if bytes.len() > MAX_CREDENTIAL_SERIALIZED_BYTES {
            return Err(CredentialError::SerializedTooLarge);
        }
        String::from_utf8(bytes).map_err(|_| CredentialError::SerializationFailed)
    }

    /// Return a stable SHA-256 fingerprint without including the secret in output.
    pub fn fingerprint(&self) -> String {
        let value = self
            .to_value()
            .expect("validated portable credential must serialize");
        let bytes = serde_json::to_vec(&value).expect("JSON value serialization is infallible");
        let mut digest = Sha256::new();
        digest.update(FINGERPRINT_DOMAIN);
        digest.update(bytes);
        format!("sha256:{:x}", digest.finalize())
    }

    fn new(payload: CredentialPayload) -> Result<Self, CredentialError> {
        let credential = Self {
            schema_version: CREDENTIAL_SCHEMA_VERSION,
            payload,
        };
        credential.validate()
    }

    fn from_value(value: Value) -> Result<Self, CredentialError> {
        let envelope = object(value)?;
        let schema_version = required_u32(&envelope, "schema_version")?;
        if schema_version > CREDENTIAL_SCHEMA_VERSION {
            return Err(CredentialError::FutureSchemaVersion);
        }
        if schema_version != CREDENTIAL_SCHEMA_VERSION {
            return Err(CredentialError::UnsupportedSchemaVersion);
        }

        let kind = required_string(&envelope, "kind")?;
        let kind = CredentialKind::parse(kind)?;
        let payload_value = envelope
            .get("payload")
            .ok_or(CredentialError::MissingField("payload"))?;
        let payload_object = object(payload_value.clone())?;

        if envelope.len() != 3 {
            return Err(CredentialError::UnexpectedEnvelopeField);
        }

        let payload = match kind {
            CredentialKind::OAuthAccessToken => {
                validate_exact_keys(&payload_object, &["access_token"])?;
                CredentialPayload::OAuthAccessToken(
                    required_string(&payload_object, "access_token")?.to_string(),
                )
            }
            CredentialKind::OAuthAuthorizedUser => {
                CredentialPayload::OAuthAuthorizedUser(payload_object)
            }
            CredentialKind::ApiKey => CredentialPayload::ApiKey(payload_object),
            CredentialKind::VertexServiceAccount => {
                CredentialPayload::VertexServiceAccount(payload_object)
            }
        };

        Self::new_with_version(schema_version, payload)
    }

    fn new_with_version(
        schema_version: u32,
        payload: CredentialPayload,
    ) -> Result<Self, CredentialError> {
        let credential = Self {
            schema_version,
            payload,
        };
        credential.validate()
    }

    fn validate(&self) -> Result<Self, CredentialError> {
        if self.schema_version > CREDENTIAL_SCHEMA_VERSION {
            return Err(CredentialError::FutureSchemaVersion);
        }
        if self.schema_version != CREDENTIAL_SCHEMA_VERSION {
            return Err(CredentialError::UnsupportedSchemaVersion);
        }

        let mut budget = MAX_CREDENTIAL_VALUES;
        validate_payload(&self.payload, 0, &mut budget)?;
        let value = self.to_value_unchecked();
        validate_value(&value, 0, &mut budget)?;
        let encoded =
            serde_json::to_vec(&value).map_err(|_| CredentialError::SerializationFailed)?;
        if encoded.len() > MAX_CREDENTIAL_SERIALIZED_BYTES {
            return Err(CredentialError::SerializedTooLarge);
        }
        Ok(self.clone())
    }

    fn to_value(&self) -> Result<Value, CredentialError> {
        self.validate()?;
        Ok(self.to_value_unchecked())
    }

    fn to_value_unchecked(&self) -> Value {
        let mut envelope = Map::new();
        envelope.insert(
            "schema_version".to_string(),
            Value::Number(Number::from(self.schema_version)),
        );
        envelope.insert(
            "kind".to_string(),
            Value::String(self.kind().as_str().to_string()),
        );
        envelope.insert("payload".to_string(), self.payload_value());
        Value::Object(envelope)
    }

    fn payload_value(&self) -> Value {
        match &self.payload {
            CredentialPayload::OAuthAccessToken(access_token) => {
                let mut payload = Map::new();
                payload.insert(
                    "access_token".to_string(),
                    Value::String(access_token.clone()),
                );
                Value::Object(payload)
            }
            CredentialPayload::OAuthAuthorizedUser(document)
            | CredentialPayload::ApiKey(document)
            | CredentialPayload::VertexServiceAccount(document) => Value::Object(document.clone()),
        }
    }
}

impl fmt::Debug for PortableCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableCredential")
            .field("schema_version", &self.schema_version)
            .field("kind", &self.kind())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl Serialize for PortableCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PortableCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let StrictValue(value) = StrictValue::deserialize(deserializer)?;
        Self::from_value(value).map_err(de::Error::custom)
    }
}

/// Errors intentionally contain field names and limits only; secret values are
/// never copied into an error or its formatted representation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    InvalidJson,
    InvalidEnvelope,
    UnexpectedEnvelopeField,
    InvalidKind,
    FutureSchemaVersion,
    UnsupportedSchemaVersion,
    MissingField(&'static str),
    EmptyField(&'static str),
    InvalidFieldType(&'static str),
    AmbiguousSecret,
    AbsolutePath,
    FieldTooLarge,
    SerializedTooLarge,
    TooDeep,
    TooManyContainerItems,
    TooManyValues,
    SerializationFailed,
}

impl fmt::Debug for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for CredentialError {}

impl CredentialError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid credential JSON",
            Self::InvalidEnvelope => "invalid credential envelope",
            Self::UnexpectedEnvelopeField => "unexpected credential envelope field",
            Self::InvalidKind => "invalid credential kind",
            Self::FutureSchemaVersion => "credential schema version is newer than this binary",
            Self::UnsupportedSchemaVersion => "unsupported credential schema version",
            Self::MissingField(_) => "required credential field is missing",
            Self::EmptyField(_) => "required credential field is empty",
            Self::InvalidFieldType(_) => "credential field has an invalid type",
            Self::AmbiguousSecret => "credential contains ambiguous secret fields",
            Self::AbsolutePath => "absolute paths are not portable credential data",
            Self::FieldTooLarge => "credential field is too large",
            Self::SerializedTooLarge => "serialized credential is too large",
            Self::TooDeep => "credential JSON is nested too deeply",
            Self::TooManyContainerItems => "credential JSON container is too large",
            Self::TooManyValues => "credential JSON contains too many values",
            Self::SerializationFailed => "credential serialization failed",
        }
    }
}

fn object(value: Value) -> Result<Map<String, Value>, CredentialError> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(CredentialError::InvalidEnvelope),
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, CredentialError> {
    let value = object
        .get(field)
        .ok_or(CredentialError::MissingField(field))?;
    let value = value
        .as_str()
        .ok_or(CredentialError::InvalidFieldType(field))?;
    if value.trim().is_empty() {
        return Err(CredentialError::EmptyField(field));
    }
    Ok(value)
}

fn required_u32(object: &Map<String, Value>, field: &'static str) -> Result<u32, CredentialError> {
    let value = object
        .get(field)
        .ok_or(CredentialError::MissingField(field))?;
    let value = value
        .as_u64()
        .ok_or(CredentialError::InvalidFieldType(field))?;
    u32::try_from(value).map_err(|_| CredentialError::InvalidFieldType(field))
}

fn validate_exact_keys(
    object: &Map<String, Value>,
    expected: &[&str],
) -> Result<(), CredentialError> {
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(CredentialError::AmbiguousSecret);
    }
    Ok(())
}

fn validate_payload(
    payload: &CredentialPayload,
    depth: usize,
    budget: &mut usize,
) -> Result<(), CredentialError> {
    match payload {
        CredentialPayload::OAuthAccessToken(access_token) => {
            validate_nonempty_string(access_token, "access_token")?;
        }
        CredentialPayload::OAuthAuthorizedUser(document) => {
            validate_authorized_user(document, depth, budget)?;
        }
        CredentialPayload::ApiKey(document) => {
            validate_api_key(document, depth, budget)?;
        }
        CredentialPayload::VertexServiceAccount(document) => {
            validate_service_account(document, depth, budget)?;
        }
    }
    Ok(())
}

fn validate_authorized_user(
    document: &Map<String, Value>,
    depth: usize,
    budget: &mut usize,
) -> Result<(), CredentialError> {
    validate_document(document, depth, budget)?;
    let type_name = required_string(document, "type")?;
    if type_name != "authorized_user" {
        return Err(CredentialError::InvalidFieldType("type"));
    }
    for field in ["client_id", "client_secret", "refresh_token", "token_uri"] {
        required_string(document, field)?;
    }
    reject_secret_fields(document, &["api_key", "private_key"])
}

fn validate_api_key(
    document: &Map<String, Value>,
    depth: usize,
    budget: &mut usize,
) -> Result<(), CredentialError> {
    validate_document(document, depth, budget)?;
    required_string(document, "api_key")?;
    reject_secret_fields(
        document,
        &[
            "access_token",
            "token",
            "refresh_token",
            "private_key",
            "client_secret",
        ],
    )
}

fn validate_service_account(
    document: &Map<String, Value>,
    depth: usize,
    budget: &mut usize,
) -> Result<(), CredentialError> {
    validate_document(document, depth, budget)?;
    let type_name = required_string(document, "type")?;
    if type_name != "service_account" {
        return Err(CredentialError::InvalidFieldType("type"));
    }
    for field in ["project_id", "private_key", "client_email", "token_uri"] {
        required_string(document, field)?;
    }
    reject_secret_fields(
        document,
        &[
            "access_token",
            "token",
            "refresh_token",
            "api_key",
            "client_secret",
        ],
    )
}

fn reject_secret_fields(
    document: &Map<String, Value>,
    fields: &[&str],
) -> Result<(), CredentialError> {
    if fields.iter().any(|field| document.contains_key(*field)) {
        return Err(CredentialError::AmbiguousSecret);
    }
    Ok(())
}

fn validate_document(
    document: &Map<String, Value>,
    depth: usize,
    budget: &mut usize,
) -> Result<(), CredentialError> {
    if document.len() > MAX_CREDENTIAL_CONTAINER_ITEMS {
        return Err(CredentialError::TooManyContainerItems);
    }
    for (key, value) in document {
        validate_string(key)?;
        validate_value(value, depth + 1, budget)?;
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize, budget: &mut usize) -> Result<(), CredentialError> {
    if depth > MAX_CREDENTIAL_NESTING_DEPTH {
        return Err(CredentialError::TooDeep);
    }
    *budget = budget
        .checked_sub(1)
        .ok_or(CredentialError::TooManyValues)?;
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) => validate_string(value),
        Value::Array(values) => {
            if values.len() > MAX_CREDENTIAL_CONTAINER_ITEMS {
                return Err(CredentialError::TooManyContainerItems);
            }
            for value in values {
                validate_value(value, depth + 1, budget)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > MAX_CREDENTIAL_CONTAINER_ITEMS {
                return Err(CredentialError::TooManyContainerItems);
            }
            for (key, value) in object {
                validate_string(key)?;
                validate_value(value, depth + 1, budget)?;
            }
            Ok(())
        }
    }
}

fn validate_string(value: &str) -> Result<(), CredentialError> {
    if value.len() > MAX_CREDENTIAL_FIELD_BYTES {
        return Err(CredentialError::FieldTooLarge);
    }
    if is_absolute_filesystem_path(value) {
        return Err(CredentialError::AbsolutePath);
    }
    Ok(())
}

fn validate_nonempty_string(value: &str, field: &'static str) -> Result<(), CredentialError> {
    validate_string(value)?;
    if value.trim().is_empty() {
        return Err(CredentialError::EmptyField(field));
    }
    Ok(())
}

fn is_absolute_filesystem_path(value: &str) -> bool {
    let value = value.trim();
    if value.starts_with('/') || value.starts_with('\\') {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

fn parse_strict_json(input: &str) -> Result<Value, CredentialError> {
    if input.len() > MAX_CREDENTIAL_SERIALIZED_BYTES {
        return Err(CredentialError::SerializedTooLarge);
    }
    let StrictValue(value) =
        serde_json::from_str(input).map_err(|_| CredentialError::InvalidJson)?;
    Ok(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(value)
                    .map(|number| StrictValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = Map::new();
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    let StrictValue(value) = map.next_value()?;
                    object.insert(key, value);
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized_user() -> Value {
        serde_json::json!({
            "type": "authorized_user",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "refresh_token": "refresh-token",
            "token_uri": "https://oauth2.example.test/token",
            "unknown_nested": {"preserve": [true, 7, null]}
        })
    }

    fn service_account() -> Value {
        serde_json::json!({
            "type": "service_account",
            "project_id": "project-id",
            "private_key": "-----BEGIN PRIVATE KEY-----\\nprivate\\n-----END PRIVATE KEY-----\\n",
            "client_email": "svc@example.test",
            "token_uri": "https://oauth2.example.test/token",
            "unknown_nested": {"preserve": "yes"}
        })
    }

    #[test]
    fn all_payloads_round_trip_semantically() {
        let credentials = [
            PortableCredential::oauth_access_token("access-token").unwrap(),
            PortableCredential::oauth_authorized_user(authorized_user()).unwrap(),
            PortableCredential::api_key("api-key").unwrap(),
            PortableCredential::vertex_service_account(service_account()).unwrap(),
        ];

        for credential in credentials {
            let encoded = credential.to_json_string().unwrap();
            let decoded = PortableCredential::from_json_str(&encoded).unwrap();
            assert_eq!(decoded, credential);
            let encoded_value = serde_json::from_str::<Value>(&encoded).unwrap();
            let decoded_reserialized = decoded.to_json_string().unwrap();
            let decoded_reserialized_value =
                serde_json::from_str::<Value>(&decoded_reserialized).unwrap();
            assert_eq!(encoded_value, decoded_reserialized_value);
        }
    }

    #[test]
    fn authorized_user_preserves_transient_access_token_with_refresh_token() {
        let mut document = authorized_user();
        document
            .as_object_mut()
            .expect("authorized-user fixture is an object")
            .insert(
                "access_token".to_string(),
                Value::String("ya29.transient-access".to_string()),
            );
        let credential = PortableCredential::oauth_authorized_user(document.clone()).unwrap();
        let decoded =
            PortableCredential::from_json_str(&credential.to_json_string().unwrap()).unwrap();
        assert_eq!(
            decoded
                .payload()
                .oauth_authorized_user()
                .unwrap()
                .get("refresh_token"),
            document.get("refresh_token")
        );
        assert_eq!(
            decoded
                .payload()
                .oauth_authorized_user()
                .unwrap()
                .get("access_token"),
            document.get("access_token")
        );
        assert_eq!(decoded, credential);
    }

    #[test]
    fn authorized_and_service_unknown_fields_survive_round_trip() {
        for (credential, field) in [
            (
                PortableCredential::oauth_authorized_user(authorized_user()).unwrap(),
                "unknown_nested",
            ),
            (
                PortableCredential::vertex_service_account(service_account()).unwrap(),
                "unknown_nested",
            ),
        ] {
            let decoded =
                PortableCredential::from_json_str(&credential.to_json_string().unwrap()).unwrap();
            let document = match decoded.payload() {
                CredentialPayload::OAuthAuthorizedUser(document)
                | CredentialPayload::VertexServiceAccount(document) => document,
                _ => unreachable!(),
            };
            assert!(document.contains_key(field));
        }
    }

    #[test]
    fn rejects_blank_missing_and_wrong_type_required_fields() {
        assert!(matches!(
            PortableCredential::oauth_access_token("  "),
            Err(CredentialError::EmptyField(_))
        ));
        assert!(matches!(
            PortableCredential::oauth_authorized_user(serde_json::json!({
                "type": "authorized_user",
                "client_id": "client",
                "client_secret": "",
                "refresh_token": "refresh",
                "token_uri": "https://example.test/token"
            })),
            Err(CredentialError::EmptyField("client_secret"))
        ));
        assert!(matches!(
            PortableCredential::oauth_authorized_user(serde_json::json!({
                "type": "authorized_user",
                "client_id": "client",
                "client_secret": "secret",
                "token_uri": "https://example.test/token"
            })),
            Err(CredentialError::MissingField("refresh_token"))
        ));
        assert!(matches!(
            PortableCredential::vertex_service_account(serde_json::json!({
                "type": "service_account",
                "project_id": "project",
                "private_key": 4,
                "client_email": "svc@example.test",
                "token_uri": "https://example.test/token"
            })),
            Err(CredentialError::InvalidFieldType("private_key"))
        ));
    }

    #[test]
    fn rejects_future_version_absolute_paths_and_ambiguous_secrets() {
        let future = r#"{"schema_version":2,"kind":"api_key","payload":{"api_key":"key"}}"#;
        assert!(matches!(
            PortableCredential::from_json_str(future),
            Err(CredentialError::FutureSchemaVersion)
        ));

        assert!(matches!(
            PortableCredential::api_key_document(serde_json::json!({
                "api_key": "key",
                "credential_path": "/tmp/credentials.json"
            })),
            Err(CredentialError::AbsolutePath)
        ));
        assert!(matches!(
            PortableCredential::api_key_document(serde_json::json!({
                "api_key": "key",
                "access_token": "also-a-secret"
            })),
            Err(CredentialError::AmbiguousSecret)
        ));
        assert!(matches!(
            PortableCredential::parse_oauth_authorized_user_json(
                r#"{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","token_uri":"https://example.test/token","api_key":"ambiguous"}"#
            ),
            Err(CredentialError::AmbiguousSecret)
        ));
        assert!(matches!(
            PortableCredential::from_json_str(
                r#"{"schema_version":1,"kind":"api_key","payload":{"api_key":"key","api_key":"duplicate"}}"#
            ),
            Err(CredentialError::InvalidJson)
        ));
    }

    #[test]
    fn rejects_oversize_fields_documents_depth_and_object_scale() {
        let long_field = "x".repeat(MAX_CREDENTIAL_FIELD_BYTES + 1);
        assert!(matches!(
            PortableCredential::oauth_access_token(long_field),
            Err(CredentialError::FieldTooLarge)
        ));

        let mut large_document = Map::new();
        large_document.insert("api_key".to_string(), Value::String("key".to_string()));
        for index in 0..=MAX_CREDENTIAL_CONTAINER_ITEMS {
            large_document.insert(format!("field-{index}"), Value::Null);
        }
        assert!(matches!(
            PortableCredential::api_key_document(Value::Object(large_document)),
            Err(CredentialError::TooManyContainerItems)
        ));

        let mut nested = Value::Null;
        for _ in 0..=MAX_CREDENTIAL_NESTING_DEPTH {
            nested = serde_json::json!({"nested": nested});
        }
        assert!(matches!(
            PortableCredential::api_key_document(serde_json::json!({
                "api_key": "key",
                "nested": nested
            })),
            Err(CredentialError::TooDeep)
        ));

        let huge = "x".repeat(MAX_CREDENTIAL_SERIALIZED_BYTES + 1);
        assert!(matches!(
            PortableCredential::from_json_str(&huge),
            Err(CredentialError::SerializedTooLarge)
        ));
    }

    #[test]
    fn fingerprint_is_stable_secret_specific_and_debug_safe() {
        let first = PortableCredential::oauth_access_token("first-secret").unwrap();
        let second = PortableCredential::oauth_access_token("second-secret").unwrap();
        let reparsed = PortableCredential::from_json_str(&first.to_json_string().unwrap()).unwrap();
        assert_eq!(first.fingerprint(), reparsed.fingerprint());
        assert_ne!(first.fingerprint(), second.fingerprint());

        let debug = format!("{first:?}");
        assert!(!debug.contains("first-secret"));
        assert!(!format!("{:?}", first.payload()).contains("first-secret"));

        let error = PortableCredential::oauth_access_token(" ").unwrap_err();
        let error_text = format!("{error:?} {error}");
        assert!(!error_text.contains("first-secret"));
    }

    #[test]
    fn google_auth_env_deny_list_covers_the_inherited_variables() {
        // AC-6.1: 这三个变量原来会被子进程原样继承，属于与当前账号无关的认证输入。
        for name in [
            "GOOGLE_API_KEY",
            "GOOGLE_GENAI_USE_VERTEXAI",
            "GOOGLE_CLOUD_LOCATION",
        ] {
            assert!(
                is_google_auth_env_var(name),
                "{name} must be part of the deny-by-default set"
            );
        }
        // launcher 已经清理的三个变量必须仍在表内，收口不能变窄。
        for name in [
            "GEMINI_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CLOUD_PROJECT",
        ] {
            assert!(is_google_auth_env_var(name));
        }
        assert!(!is_google_auth_env_var("PATH"));
        assert!(!is_google_auth_env_var("HOME"));

        let mut sorted = GOOGLE_AUTH_ENV_VARS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), GOOGLE_AUTH_ENV_VARS);
        assert!(
            GOOGLE_AUTH_ENV_VARS
                .iter()
                .all(|name| name.is_ascii() && !name.is_empty())
        );
        // R5 会直接遍历这张常量表来 deny-by-default 地清空子进程环境，
        // 所以名字必须是合法的环境变量名，且严格无重复。
        let unique: BTreeSet<&&str> = GOOGLE_AUTH_ENV_VARS.iter().collect();
        assert_eq!(unique.len(), GOOGLE_AUTH_ENV_VARS.len());
        assert!(GOOGLE_AUTH_ENV_VARS.iter().all(|name| {
            name.chars()
                .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == '_')
                && !name.starts_with(|value: char| value.is_ascii_digit())
        }));
        // 表内的每一项都必须能被 `is_google_auth_env_var` 认出来，两者不得漂移。
        assert!(
            GOOGLE_AUTH_ENV_VARS
                .iter()
                .all(|name| { is_google_auth_env_var(name) })
        );
    }

    #[test]
    fn raw_document_parsers_reject_portable_envelope_mismatch() {
        let portable = PortableCredential::oauth_access_token("token")
            .unwrap()
            .to_json_string()
            .unwrap();
        assert!(PortableCredential::parse_oauth_authorized_user_json(&portable).is_err());
        assert!(PortableCredential::parse_vertex_service_account_json(&portable).is_err());
    }
}
