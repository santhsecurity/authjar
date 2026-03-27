//! Multi-cookie session management.
//!
//! Tracks cookie jars by named session, supports domain- and path-scoped cookie
//! selection, and provides JSON persistence for cross-run reuse.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const MAX_COOKIE_NAME_LEN: usize = 256;
const MAX_COOKIE_VALUE_LEN: usize = 4096;
const MAX_COOKIE_PATH_LEN: usize = 1024;
const MAX_COOKIES_PER_SESSION: usize = 4096;
const MAX_SESSIONS_PER_STORE: usize = 1024;
const MAX_STORE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// An error type covering I/O and serialization operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthJarError {
    /// Any filesystem error while reading or writing JSON/TOML data.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or deserialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// TOML deserialization failure.
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    /// TOML serialization failure.
    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    /// Invalid cookie, domain, path, or session input.
    #[error("invalid input: {0}")]
    Invalid(String),
}

/// Settings that control session behavior for applications that want to externalize
/// their defaults in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionSettings {
    /// Optional default domain used when parsing Set-Cookie entries without a Domain
    /// attribute.
    pub default_domain: Option<String>,
    /// Default cookie path used when parsing Set-Cookie entries without a Path
    /// attribute.
    pub default_path: String,
    /// Enable parent-domain cookie reuse (e.g. `.example.com` applies to
    /// `api.example.com`).
    pub match_subdomains: bool,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            default_domain: None,
            default_path: String::from("/"),
            match_subdomains: true,
        }
    }
}

impl SessionSettings {
    /// Create settings from a TOML string.
    ///
    /// # Parameters
    ///
    /// - `value`: TOML text describing [`SessionSettings`].
    ///
    /// # Returns
    ///
    /// Returns validated settings parsed from `value`.
    ///
    /// # Errors
    /// Returns `AuthJarError` if parsing or validation fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn from_toml_str(value: &str) -> Result<Self, AuthJarError> {
        let settings: Self = toml::from_str(value)?;
        settings.validate()?;
        Ok(settings)
    }

    /// Load settings from a TOML file.
    ///
    /// # Parameters
    ///
    /// - `path`: TOML file path to read.
    ///
    /// # Returns
    ///
    /// Returns validated settings loaded from disk.
    ///
    /// # Errors
    /// Returns `AuthJarError` if the file cannot be read, parsed, or validated.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, AuthJarError> {
        let raw = fs::read_to_string(path)?;
        Self::from_toml_str(&raw)
    }

    /// Persist settings to a TOML file.
    ///
    /// # Parameters
    ///
    /// - `path`: Destination file path.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` after successful validation and write.
    ///
    /// # Errors
    /// Returns `AuthJarError` if validation, serialization, or writing fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use authjar::SessionSettings;
    ///
    /// let path = std::env::temp_dir().join("authjar-settings-doc.toml");
    ///
    /// SessionSettings::default().save_to_toml_file(&path).unwrap();
    /// assert!(path.exists());
    /// std::fs::remove_file(path).ok();
    /// ```
    pub fn save_to_toml_file(&self, path: impl AsRef<Path>) -> Result<(), AuthJarError> {
        self.validate()?;
        let rendered = toml::to_string_pretty(self)?;
        fs::write(path, rendered)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), AuthJarError> {
        if let Some(domain) = &self.default_domain {
            validate_domain(domain)?;
        }
        validate_cookie_path(&self.default_path)?;
        Ok(())
    }
}

/// A single cookie with name, value, and scope metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain scope for this cookie.
    pub domain: String,
    /// Path scope for this cookie.
    pub path: String,
    /// Whether this cookie is HTTP-only.
    pub http_only: bool,
    /// Whether this cookie is secure-only.
    pub secure: bool,
}

impl Cookie {
    /// Creates a cookie with a normalized domain, path `/`, and both flags disabled.
    ///
    /// # Parameters
    ///
    /// - `name`: Cookie name.
    /// - `value`: Cookie value.
    /// - `domain`: Cookie domain, normalized to lowercase without leading dots.
    ///
    /// # Returns
    ///
    /// Returns a new [`Cookie`] with default path and flags.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: normalize_domain(&domain.into()),
            path: "/".to_string(),
            http_only: false,
            secure: false,
        }
    }

    /// Parse an arbitrary cookie header line.
    ///
    /// The parser accepts both raw cookie pairs (`session=abc`) and full Set-Cookie
    /// lines (`Set-Cookie: session=abc; Path=/; HttpOnly`).
    /// # Parameters
    ///
    /// - `line`: Raw `Cookie` or `Set-Cookie` style header line.
    ///
    /// # Returns
    ///
    /// Returns `Some(cookie)` when parsing succeeds and all normalized fields pass
    /// validation, otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use authjar::Cookie;
    ///
    /// let cookie = Cookie::from_header_line_with_domain(
    ///     "Set-Cookie: sid=abc; Path=/app",
    ///     Some("app.example.com"),
    /// )
    /// .unwrap();
    ///
    /// assert_eq!(cookie.name, "sid");
    /// assert_eq!(cookie.domain, "app.example.com");
    /// assert_eq!(cookie.path, "/app");
    /// ```
    #[must_use]
    pub fn from_header_line(line: &str) -> Option<Self> {
        Self::from_header_line_with_domain(line, None)
    }

    /// Parse an arbitrary cookie header line with an optional fallback request host.
    ///
    /// When the cookie omits the `Domain` attribute, RFC 6265 defaults it to the
    /// request host that received the `Set-Cookie` header.
    /// # Parameters
    ///
    /// - `line`: Raw header line to parse.
    /// - `default_domain`: Domain to use when the cookie omits `Domain=`.
    ///
    /// # Returns
    ///
    /// Returns `Some(cookie)` when parsing and validation succeed, otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn from_header_line_with_domain(line: &str, default_domain: Option<&str>) -> Option<Self> {
        let line = line.trim();
        let value = match line.split_once(':') {
            Some((name, rest)) if name.eq_ignore_ascii_case("set-cookie") => rest.trim(),
            _ => line,
        };

        let mut parts = value.split(';');
        let pair = parts.next()?.trim();
        let mut segments = pair.splitn(2, '=');
        let name = segments.next()?.trim();
        let value = segments.next().map(str::trim).unwrap_or_default();
        let normalized_value = value.trim_matches('"');
        if !is_valid_cookie_name(name) || !is_valid_cookie_value(normalized_value) {
            return None;
        }

        let mut cookie = Cookie {
            name: name.to_string(),
            value: normalized_value.to_string(),
            domain: String::new(),
            path: "/".to_string(),
            http_only: false,
            secure: false,
        };

        for attr in parts {
            let attribute = attr.trim();
            if attribute.is_empty() {
                continue;
            }

            match attribute.split_once('=') {
                Some((key, value)) => match key.trim().to_ascii_lowercase().as_str() {
                    "domain" => {
                        let normalized = normalize_domain(value.trim().trim_matches('"'));
                        if validate_domain(&normalized).is_err() {
                            return None;
                        }
                        cookie.domain = normalized;
                    }
                    "path" => {
                        let path = value.trim();
                        cookie.path = if path.is_empty() {
                            "/".to_string()
                        } else {
                            path.to_string()
                        };
                        if validate_cookie_path(&cookie.path).is_err() {
                            return None;
                        }
                    }
                    _ => return None,
                },
                None => match attribute.to_ascii_lowercase().as_str() {
                    "httponly" => cookie.http_only = true,
                    "secure" => cookie.secure = true,
                    _ => {}
                },
            }
        }

        if cookie.domain.is_empty() {
            let default_domain = normalize_domain(default_domain.unwrap_or_default());
            if validate_domain(&default_domain).is_err() {
                return None;
            }
            cookie.domain = default_domain;
        }

        Some(cookie)
    }

    /// Parses a `Set-Cookie` value while supplying an explicit fallback domain.
    ///
    /// # Parameters
    ///
    /// - `header_value`: Raw `Set-Cookie` value or line.
    /// - `default_domain`: Domain to apply when the cookie omits `Domain=`.
    ///
    /// # Returns
    ///
    /// Returns `Some(cookie)` when the cookie is valid, otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn from_set_cookie(header_value: &str, default_domain: &str) -> Option<Self> {
        Self::from_header_line_with_domain(header_value, Some(default_domain))
    }

    /// Renders this cookie as a `Set-Cookie` header value.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns a serialized `Set-Cookie` string including `Domain`, `Path`, and any
    /// enabled flags.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn to_set_cookie_string(&self) -> String {
        let mut parts = vec![
            format!("{}={}", self.name, self.value),
            format!("Domain={}", self.domain),
            format!("Path={}", self.path),
        ];
        if self.http_only {
            parts.push("HttpOnly".to_string());
        }
        if self.secure {
            parts.push("Secure".to_string());
        }
        parts.join("; ")
    }

    fn key(&self) -> String {
        format!("{}:{}:{}", self.domain, self.path, self.name)
    }

    fn matches(
        &self,
        request_domain: &str,
        request_path: &str,
        request_is_secure: bool,
        settings: &SessionSettings,
    ) -> bool {
        if self.secure && !request_is_secure {
            return false;
        }

        if !domain_matches(request_domain, &self.domain, settings.match_subdomains) {
            return false;
        }

        path_matches(request_path, &self.path)
    }
}

/// A named authentication session with a cookie jar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// Session name (e.g. `"admin"`, `"user"`, `"browser-a"`).
    pub name: String,
    /// Cookies keyed by `domain:path:name`.
    cookies: HashMap<String, Cookie>,
}

impl AuthSession {
    /// Creates a new empty named authentication session.
    ///
    /// # Parameters
    ///
    /// - `name`: Session name used as the store key.
    ///
    /// # Returns
    ///
    /// Returns an empty [`AuthSession`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cookies: HashMap::new(),
        }
    }

    /// Adds or replaces a plain cookie using the default path `/`.
    ///
    /// Invalid inputs are rejected silently with a warning instead of returning an
    /// error, which keeps session mutation ergonomic for best-effort ingestion.
    ///
    /// # Parameters
    ///
    /// - `name`: Cookie name.
    /// - `value`: Cookie value.
    /// - `domain`: Cookie domain.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add_cookie(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
    ) {
        self.add_cookie_with_path(name, value, domain, "/", false, false);
    }

    /// Adds or replaces a cookie with explicit scope and security metadata.
    ///
    /// Invalid cookies or sessions that exceed the per-session limit are rejected
    /// and logged instead of causing an error.
    ///
    /// # Parameters
    ///
    /// - `name`: Cookie name.
    /// - `value`: Cookie value.
    /// - `domain`: Cookie domain.
    /// - `path`: Cookie path scope.
    /// - `http_only`: Whether the cookie should be marked HTTP-only.
    /// - `secure`: Whether the cookie should be sent only over secure contexts.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add_cookie_with_path(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        domain: impl Into<String>,
        path: impl Into<String>,
        http_only: bool,
        secure: bool,
    ) {
        let mut cookie = Cookie::new(name, value, domain);
        cookie.path = path.into();
        cookie.http_only = http_only;
        cookie.secure = secure;
        if !is_valid_cookie_name(&cookie.name)
            || !is_valid_cookie_value(&cookie.value)
            || validate_domain(&cookie.domain).is_err()
            || validate_cookie_path(&cookie.path).is_err()
        {
            tracing::warn!("rejected invalid cookie while adding to session");
            return;
        }
        let key = cookie.key();
        if !self.cookies.contains_key(&key) && self.cookies.len() >= MAX_COOKIES_PER_SESSION {
            tracing::warn!(
                "rejected cookie due to session cookie limit (Fix: lower cookie cardinality)"
            );
            return;
        }
        self.cookies.insert(key, cookie);
    }

    /// Parses and adds a cookie from a `Set-Cookie` value using a fallback domain.
    ///
    /// # Parameters
    ///
    /// - `header_value`: Raw `Set-Cookie` value or line.
    /// - `default_domain`: Domain to use when `Domain=` is absent.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add_set_cookie(&mut self, header_value: &str, default_domain: &str) {
        if let Some(cookie) = Cookie::from_set_cookie(header_value, default_domain) {
            let key = cookie.key();
            self.cookies.insert(key, cookie);
        }
    }

    /// Parses and adds a cookie from a raw header line without a fallback domain.
    ///
    /// # Parameters
    ///
    /// - `line`: Raw cookie or `Set-Cookie` line.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add_cookie_header_line(&mut self, line: &str) {
        if let Some(cookie) = Cookie::from_header_line(line) {
            let key = cookie.key();
            self.cookies.insert(key, cookie);
        }
    }

    /// Add a cookie from a raw header line, defaulting a missing Domain attribute
    /// to the request host that produced the header.
    ///
    /// # Parameters
    ///
    /// - `line`: Raw cookie or `Set-Cookie` line.
    /// - `request_host`: Host to use when the cookie omits `Domain=`.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add_cookie_header_line_for_host(&mut self, line: &str, request_host: &str) {
        if let Some(cookie) = Cookie::from_header_line_with_domain(line, Some(request_host)) {
            let key = cookie.key();
            self.cookies.insert(key, cookie);
        }
    }

    /// Collects matching cookies for `domain` as a `Cookie` header string.
    ///
    /// # Parameters
    ///
    /// - `domain`: Request host whose cookies should be selected.
    /// - `settings`: Matching rules that control default path and subdomain reuse.
    ///
    /// # Returns
    ///
    /// Returns a stable, sorted `Cookie` header string.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use authjar::{AuthSession, SessionSettings};
    ///
    /// let mut session = AuthSession::new("admin");
    /// session.add_cookie("sid", "abc", "example.com");
    ///
    /// let header = session.cookie_header("example.com", &SessionSettings::default());
    /// assert_eq!(header, "sid=abc");
    /// ```
    #[must_use]
    pub fn cookie_header(&self, domain: &str, settings: &SessionSettings) -> String {
        self.cookie_header_for(domain, "/", false, settings)
    }

    /// Collects cookies for a full request context including path and transport security.
    ///
    /// # Parameters
    ///
    /// - `domain`: Request host.
    /// - `path`: Request path.
    /// - `is_secure`: Whether the request uses a secure transport such as HTTPS.
    /// - `settings`: Cookie matching behavior.
    ///
    /// # Returns
    ///
    /// Returns a sorted `Cookie` header string containing only matching cookies.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn cookie_header_for(
        &self,
        domain: &str,
        path: &str,
        is_secure: bool,
        settings: &SessionSettings,
    ) -> String {
        let mut values: Vec<String> = self
            .cookies
            .values()
            .filter(|cookie| cookie.matches(domain, path, is_secure, settings))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect();

        values.sort_unstable();
        values.join("; ")
    }

    /// Returns matching cookies as borrowed name/value tuples for programmatic use.
    ///
    /// # Parameters
    ///
    /// - `domain`: Request host.
    /// - `path`: Request path.
    /// - `is_secure`: Whether the request is secure.
    /// - `settings`: Cookie matching behavior.
    ///
    /// # Returns
    ///
    /// Returns every cookie that would be sent for the request context.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn cookies_for_domain(
        &self,
        domain: &str,
        path: &str,
        is_secure: bool,
        settings: &SessionSettings,
    ) -> Vec<(&str, &str)> {
        self.cookies
            .values()
            .filter(|cookie| cookie.matches(domain, path, is_secure, settings))
            .map(|cookie| (cookie.name.as_str(), cookie.value.as_str()))
            .collect()
    }

    /// Reports whether the session currently contains any cookies.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `true` when the session contains zero cookies.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Returns the total number of cookies stored in this session.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns the number of stored cookies.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Counts cookies that would match a request to `domain` using default path `/`.
    ///
    /// # Parameters
    ///
    /// - `domain`: Request host to test.
    /// - `settings`: Matching behavior.
    ///
    /// # Returns
    ///
    /// Returns the number of matching cookies.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn cookie_count_for_domain(&self, domain: &str, settings: &SessionSettings) -> usize {
        self.cookies_for_domain(domain, "/", false, settings).len()
    }
}

/// Multi-session store for reusable web tools.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStore {
    sessions: HashMap<String, AuthSession>,
    /// Runtime options used when matching cookie scope.
    #[serde(default)]
    settings: SessionSettings,
}

impl SessionStore {
    /// Creates an empty session store with default matching settings.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns a new empty [`SessionStore`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty session store with caller-supplied settings.
    ///
    /// # Parameters
    ///
    /// - `settings`: Matching configuration to apply to the store.
    ///
    /// # Returns
    ///
    /// Returns a new [`SessionStore`] using `settings`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn with_settings(settings: SessionSettings) -> Self {
        Self {
            sessions: HashMap::new(),
            settings,
        }
    }

    /// Returns an immutable reference to the store's session settings.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns the current [`SessionSettings`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn settings(&self) -> &SessionSettings {
        &self.settings
    }

    /// Returns a mutable reference to the store's session settings.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns a mutable [`SessionSettings`] reference for in-place updates.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn settings_mut(&mut self) -> &mut SessionSettings {
        &mut self.settings
    }

    /// Persist the whole store as JSON.
    ///
    /// # Parameters
    ///
    /// - `path`: Destination JSON file path.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` after validating and writing the store.
    ///
    /// # Errors
    /// Returns `AuthJarError` if saving to file fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use authjar::{AuthSession, SessionStore};
    ///
    /// let path = std::env::temp_dir().join("authjar-sessions-doc.json");
    ///
    /// let mut store = SessionStore::new();
    /// store.add(AuthSession::new("admin"));
    /// store.save_to_file(&path).unwrap();
    ///
    /// let loaded = SessionStore::load_from_file(&path).unwrap();
    /// assert_eq!(loaded.len(), 1);
    /// std::fs::remove_file(path).ok();
    /// ```
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), AuthJarError> {
        self.validate()?;
        tracing::warn!("authjar session persistence is plaintext JSON; protect the file with OS-level encryption or a secret store");
        let payload = serde_json::to_string_pretty(self)?;
        fs::write(path, payload)?;
        Ok(())
    }

    /// Persist the whole store as JSON using async filesystem APIs.
    ///
    /// # Parameters
    ///
    /// - `path`: Destination JSON file path.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` after validating, serializing, and writing the store.
    ///
    /// # Errors
    /// Returns `AuthJarError` if serialization or async file writing fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[cfg(feature = "tokio")]
    pub async fn save_to_file_async(&self, path: impl AsRef<Path>) -> Result<(), AuthJarError> {
        self.validate()?;
        tracing::warn!("authjar session persistence is plaintext JSON; protect the file with OS-level encryption or a secret store");
        let payload = serde_json::to_string_pretty(self)?;
        tokio::fs::write(path, payload).await?;
        Ok(())
    }

    /// Load a store from JSON.
    ///
    /// # Parameters
    ///
    /// - `path`: JSON file path to read.
    ///
    /// # Returns
    ///
    /// Returns the validated [`SessionStore`] loaded from disk.
    ///
    /// # Errors
    /// Returns `AuthJarError` if loading from file fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, AuthJarError> {
        let metadata = fs::metadata(path.as_ref())?;
        if metadata.len() > MAX_STORE_FILE_BYTES {
            return Err(AuthJarError::Invalid(format!(
                "session store file too large ({} bytes). Fix: keep file <= {} bytes",
                metadata.len(),
                MAX_STORE_FILE_BYTES
            )));
        }
        let payload = fs::read_to_string(path)?;
        let store: Self = serde_json::from_str(&payload)?;
        store.validate()?;
        Ok(store)
    }

    /// Load a store from JSON using async filesystem APIs.
    ///
    /// # Parameters
    ///
    /// - `path`: JSON file path to read.
    ///
    /// # Returns
    ///
    /// Returns the validated [`SessionStore`] loaded asynchronously from disk.
    ///
    /// # Errors
    /// Returns `AuthJarError` if async file reading, deserialization, or validation fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[cfg(feature = "tokio")]
    pub async fn load_from_file_async(path: impl AsRef<Path>) -> Result<Self, AuthJarError> {
        let metadata = tokio::fs::metadata(path.as_ref()).await?;
        if metadata.len() > MAX_STORE_FILE_BYTES {
            return Err(AuthJarError::Invalid(format!(
                "session store file too large ({} bytes). Fix: keep file <= {} bytes",
                metadata.len(),
                MAX_STORE_FILE_BYTES
            )));
        }
        let payload = tokio::fs::read_to_string(path).await?;
        let store: Self = serde_json::from_str(&payload)?;
        store.validate()?;
        Ok(store)
    }

    /// Adds or replaces a session by name.
    ///
    /// New sessions that would exceed the store limit are rejected and logged.
    ///
    /// # Parameters
    ///
    /// - `session`: Session to insert.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add(&mut self, session: AuthSession) {
        if !self.sessions.contains_key(&session.name)
            && self.sessions.len() >= MAX_SESSIONS_PER_STORE
        {
            tracing::warn!("rejected session due to store limit (Fix: prune old sessions)");
            return;
        }
        self.sessions.insert(session.name.clone(), session);
    }

    /// Adds a plain cookie to a named session, creating the session if needed.
    ///
    /// # Parameters
    ///
    /// - `session_name`: Target session name.
    /// - `cookie_name`: Cookie name.
    /// - `cookie_value`: Cookie value.
    /// - `cookie_domain`: Cookie domain.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add_cookie_to_session(
        &mut self,
        session_name: &str,
        cookie_name: impl Into<String>,
        cookie_value: impl Into<String>,
        cookie_domain: impl Into<String>,
    ) {
        if !self.sessions.contains_key(session_name)
            && self.sessions.len() >= MAX_SESSIONS_PER_STORE
        {
            tracing::warn!(
                "rejected session creation due to store limit (Fix: prune old sessions)"
            );
            return;
        }
        let entry = self
            .sessions
            .entry(session_name.to_string())
            .or_insert_with(|| AuthSession::new(session_name));

        entry.add_cookie(cookie_name, cookie_value, cookie_domain);
    }

    /// Parses and adds a `Set-Cookie` line to a named session.
    ///
    /// # Parameters
    ///
    /// - `session_name`: Target session name.
    /// - `header_value`: Raw `Set-Cookie` value or line.
    /// - `default_domain`: Fallback domain for cookies without `Domain=`.
    ///
    /// # Returns
    ///
    /// This function returns no value.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn add_set_cookie_to_session(
        &mut self,
        session_name: &str,
        header_value: &str,
        default_domain: &str,
    ) {
        if !self.sessions.contains_key(session_name)
            && self.sessions.len() >= MAX_SESSIONS_PER_STORE
        {
            tracing::warn!(
                "rejected session creation due to store limit (Fix: prune old sessions)"
            );
            return;
        }
        let entry = self
            .sessions
            .entry(session_name.to_string())
            .or_insert_with(|| AuthSession::new(session_name));

        entry.add_set_cookie(header_value, default_domain);
    }

    /// Looks up a session by name.
    ///
    /// # Parameters
    ///
    /// - `name`: Session name to retrieve.
    ///
    /// # Returns
    ///
    /// Returns `Some(&AuthSession)` when the session exists, otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&AuthSession> {
        self.sessions.get(name)
    }

    /// Looks up a mutable session by name.
    ///
    /// # Parameters
    ///
    /// - `name`: Session name to retrieve.
    ///
    /// # Returns
    ///
    /// Returns `Some(&mut AuthSession)` when the session exists, otherwise `None`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut AuthSession> {
        self.sessions.get_mut(name)
    }

    /// Lists all session names in sorted order.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns sorted session names as borrowed `&str` values.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<_> = self.sessions.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Returns the number of sessions currently stored.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns the number of sessions.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Reports whether the store currently contains zero sessions.
    ///
    /// # Parameters
    ///
    /// This function takes no additional parameters.
    ///
    /// # Returns
    ///
    /// Returns `true` when the store is empty.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn validate(&self) -> Result<(), AuthJarError> {
        self.settings.validate()?;
        if self.sessions.len() > MAX_SESSIONS_PER_STORE {
            return Err(AuthJarError::Invalid(format!(
                "too many sessions: {} (Fix: keep <= {MAX_SESSIONS_PER_STORE})",
                self.sessions.len()
            )));
        }
        for (name, session) in &self.sessions {
            if name.trim().is_empty() || name.chars().any(char::is_control) {
                return Err(AuthJarError::Invalid(format!(
                    "invalid session name `{name}`"
                )));
            }
            if session.cookies.len() > MAX_COOKIES_PER_SESSION {
                return Err(AuthJarError::Invalid(format!(
                    "too many cookies in session `{name}`: {} (Fix: keep <= {MAX_COOKIES_PER_SESSION})",
                    session.cookies.len()
                )));
            }
            for cookie in session.cookies.values() {
                if !is_valid_cookie_name(&cookie.name) || !is_valid_cookie_value(&cookie.value) {
                    return Err(AuthJarError::Invalid(format!(
                        "invalid cookie `{}` in session `{name}`",
                        cookie.name
                    )));
                }
                validate_domain(&cookie.domain)?;
                validate_cookie_path(&cookie.path)?;
            }
        }
        Ok(())
    }
}

fn is_valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_COOKIE_NAME_LEN
        && name
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x7e) && !b"()<>@,;:\\\"/[]?={} \t".contains(&byte))
}

fn is_valid_cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COOKIE_VALUE_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21..=0x7e) && !matches!(byte, b';' | b',' | b'\\' | b'"'))
}

fn validate_domain(domain: &str) -> Result<(), AuthJarError> {
    if domain.is_empty() {
        return Err(AuthJarError::Invalid(
            "cookie domain cannot be empty".to_string(),
        ));
    }

    if domain.len() > 253
        || domain.starts_with('-')
        || domain.ends_with('-')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(AuthJarError::Invalid(format!(
            "invalid cookie domain `{domain}`"
        )));
    }

    if !domain
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
    {
        return Err(AuthJarError::Invalid(format!(
            "invalid cookie domain `{domain}`"
        )));
    }

    Ok(())
}

fn validate_cookie_path(path: &str) -> Result<(), AuthJarError> {
    if path.is_empty()
        || path.len() > MAX_COOKIE_PATH_LEN
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
    {
        return Err(AuthJarError::Invalid(format!(
            "invalid cookie path `{path}`"
        )));
    }
    Ok(())
}

fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn domain_matches(request_domain: &str, cookie_domain: &str, include_subdomains: bool) -> bool {
    let request_domain = normalize_domain(request_domain);
    if request_domain.is_empty() || cookie_domain.is_empty() {
        return false;
    }

    if request_domain == cookie_domain {
        return true;
    }

    if !include_subdomains {
        return false;
    }

    request_domain.ends_with(&format!(".{cookie_domain}"))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    let request_path = if request_path.is_empty() {
        "/"
    } else {
        request_path
    };
    if cookie_path == "/" {
        return true;
    }
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }

    cookie_path.ends_with('/')
        || request_path
            .as_bytes()
            .get(cookie_path.len())
            .is_some_and(|byte| *byte == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, fs, io::Write, path::PathBuf};

    fn temp_path(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time since epoch")
            .as_nanos();
        path.push(format!("{name}-{since_epoch}.json"));
        path
    }

    #[test]
    fn session_basic() {
        let mut session = AuthSession::new("admin");
        session.add_cookie("PHPSESSID", "abc123", "example.com");
        session.add_cookie("auth", "xyz", "example.com");

        assert_eq!(session.cookie_count(), 2);
        let header =
            session.cookie_header_for("example.com", "/", false, &SessionSettings::default());
        assert!(header.contains("PHPSESSID=abc123"));
        assert!(header.contains("auth=xyz"));
    }

    #[test]
    fn session_domain_scoping() {
        let mut session = AuthSession::new("user");
        session.add_cookie("a", "1", "example.com");
        session.add_cookie("b", "2", "other.com");

        let settings = SessionSettings::default();
        let header = session.cookie_header_for("example.com", "/", false, &settings);
        assert!(header.contains("a=1"));
        assert!(!header.contains("b=2"));
    }

    #[test]
    fn session_subdomain_matching() {
        let mut session = AuthSession::new("user");
        session.add_cookie("sess", "val", "example.com");

        let settings = SessionSettings::default();
        let header = session.cookie_header_for("api.example.com", "/", false, &settings);
        assert!(header.contains("sess=val"));
    }

    #[test]
    fn session_subdomain_disabled() {
        let settings = SessionSettings {
            match_subdomains: false,
            ..Default::default()
        };

        let mut session = AuthSession::new("user");
        session.add_cookie("sess", "val", "example.com");

        let header = session.cookie_header_for("api.example.com", "/", false, &settings);
        assert!(!header.contains("sess=val"));
    }

    #[test]
    fn session_parent_domain_blocks_prefix_collision() {
        let mut session = AuthSession::new("user3");
        session.add_cookie("root_sess", "secret", "example.com");

        let settings = SessionSettings::default();
        let header = session.cookie_header_for("bad-example.com", "/", false, &settings);
        assert!(!header.contains("root_sess=secret"));
    }

    #[test]
    fn parse_set_cookie() {
        let cookie = Cookie::from_set_cookie(
            "session=abc; Path=/; Domain=.example.com; HttpOnly; Secure",
            "fallback.com",
        )
        .expect("cookie parse");

        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc");
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert!(cookie.http_only);
        assert!(cookie.secure);
    }

    #[test]
    fn parse_set_cookie_without_domain_uses_fallback() {
        let cookie = Cookie::from_set_cookie("sid=xyz; Path=/app", "example.com").unwrap();
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/app");
    }

    #[test]
    fn parse_header_line_without_domain_uses_request_host() {
        let cookie = Cookie::from_header_line_with_domain(
            "Set-Cookie: sid=xyz; Path=/app",
            Some("app.example.com"),
        )
        .unwrap();
        assert_eq!(cookie.domain, "app.example.com");
        assert_eq!(cookie.path, "/app");
    }

    #[test]
    fn parse_set_cookie_fails_without_domain() {
        assert!(Cookie::from_set_cookie("sid=1", "").is_none());
    }

    #[test]
    fn parse_set_cookie_rejects_invalid_domain() {
        assert!(Cookie::from_set_cookie("sid=1; Domain=bad domain", "fallback.com").is_none());
    }

    #[test]
    fn parse_set_cookie_rejects_invalid_path() {
        assert!(Cookie::from_set_cookie("sid=1; Path=relative", "example.com").is_none());
    }

    #[test]
    fn parse_set_cookie_rejects_cookie_injection_value() {
        assert!(Cookie::from_set_cookie("sid=abc;admin=true; Path=/", "example.com").is_none());
    }

    #[test]
    fn parse_header_with_set_cookie_prefix() {
        let cookie =
            Cookie::from_header_line("Set-Cookie: x=1; Domain=.example.com; Path=/; Secure")
                .expect("header parse");

        assert_eq!(cookie.name, "x");
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert!(cookie.secure);
    }

    #[test]
    fn parse_header_rejects_blank_cookie() {
        assert!(Cookie::from_header_line("Set-Cookie: =").is_none());
    }

    #[test]
    fn parse_set_cookie_preserves_case_for_domain() {
        let cookie = Cookie::from_set_cookie("sid=1; Domain=EXAMPLE.COM", "fallback.com").unwrap();
        assert_eq!(cookie.domain, "example.com");
    }

    #[test]
    fn cookie_new_normalizes_domain_and_defaults() {
        let cookie = Cookie::new("sid", "v", ".EXAMPLE.com.");
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert!(!cookie.http_only);
        assert!(!cookie.secure);
    }

    #[test]
    fn parse_header_line_with_unknown_attribute_rejected() {
        assert!(Cookie::from_header_line_with_domain(
            "Set-Cookie: sid=1; Path=/; SameSite=Lax",
            Some("example.com")
        )
        .is_none());
    }

    #[test]
    fn parse_header_line_with_empty_path_defaults_to_root() {
        let cookie = Cookie::from_header_line_with_domain(
            "Set-Cookie: sid=1; Path=; Domain=example.com",
            None,
        )
        .unwrap();
        assert_eq!(cookie.path, "/");
    }

    #[test]
    fn parse_header_line_rejects_null_byte_in_value() {
        assert!(
            Cookie::from_header_line_with_domain("Set-Cookie: sid=ab\0cd", Some("example.com"))
                .is_none()
        );
    }

    #[test]
    fn parse_header_line_rejects_unicode_cookie_value() {
        assert!(
            Cookie::from_header_line_with_domain("Set-Cookie: sid=こんにちは", Some("example.com"))
                .is_none()
        );
    }

    #[test]
    fn add_cookie_rejects_invalid_inputs() {
        let mut session = AuthSession::new("invalid");
        session.add_cookie_with_path("bad name", "value", "bad domain", "relative", false, false);
        assert!(session.is_empty());
    }

    #[test]
    fn add_cookie_rejects_header_injection_value() {
        let mut session = AuthSession::new("invalid-value");
        session.add_cookie("sid", "a\r\nSet-Cookie: hacked=1", "example.com");
        assert!(session.is_empty());
    }

    #[test]
    fn add_cookie_rejects_empty_inputs() {
        let mut session = AuthSession::new("empty");
        session.add_cookie("", "", "");
        assert!(session.is_empty());
    }

    #[test]
    fn add_cookie_rejects_huge_value() {
        let mut session = AuthSession::new("huge");
        let huge_value = "a".repeat(MAX_COOKIE_VALUE_LEN + 1);
        session.add_cookie("sid", huge_value, "example.com");
        assert!(session.is_empty());
    }

    #[test]
    fn add_cookie_header_line_for_host_adds_cookie_without_domain_attr() {
        let mut session = AuthSession::new("host-fallback");
        session.add_cookie_header_line_for_host("Set-Cookie: sid=1; Path=/app", "api.example.com");
        let cookies = session.cookie_header_for(
            "api.example.com",
            "/app/dashboard",
            false,
            &SessionSettings::default(),
        );
        assert!(cookies.contains("sid=1"));
    }

    #[test]
    fn add_cookie_header_line_without_domain_does_not_add_cookie() {
        let mut session = AuthSession::new("missing-domain");
        session.add_cookie_header_line("Set-Cookie: sid=1; Path=/");
        assert!(session.is_empty());
    }

    #[test]
    fn cookies_for_domain_returns_only_matches() {
        let mut session = AuthSession::new("tuples");
        session.add_cookie_with_path("a", "1", "example.com", "/app", false, false);
        session.add_cookie_with_path("b", "2", "other.com", "/", false, false);
        let matched = session.cookies_for_domain("example.com", "/app/x", false, &SessionSettings::default());
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0], ("a", "1"));
    }

    #[test]
    fn cookie_count_for_domain_uses_default_path_and_security_context() {
        let mut session = AuthSession::new("count");
        session.add_cookie_with_path("a", "1", "example.com", "/app", false, false);
        assert_eq!(
            session.cookie_count_for_domain("example.com", &SessionSettings::default()),
            0
        );
        assert_eq!(
            session.cookies_for_domain("example.com", "/app", false, &SessionSettings::default()).len(),
            1
        );
    }

    #[test]
    fn cookie_path_matching_root() {
        let mut session = AuthSession::new("p");
        session.add_cookie_with_path("a", "1", "example.com", "/", false, false);

        let settings = SessionSettings::default();
        assert!(session
            .cookie_header_for("example.com", "/admin", false, &settings)
            .contains("a=1"));
    }

    #[test]
    fn cookie_path_matching_prefix() {
        let mut session = AuthSession::new("p2");
        session.add_cookie_with_path("a", "1", "example.com", "/app", false, false);

        let settings = SessionSettings::default();
        assert!(session
            .cookie_header_for("example.com", "/app", false, &settings)
            .contains("a=1"));
        assert!(session
            .cookie_header_for("example.com", "/app/profile", false, &settings)
            .contains("a=1"));
        assert!(!session
            .cookie_header_for("example.com", "/application", false, &settings)
            .contains("a=1"));
    }

    #[test]
    fn cookie_secure_only_requires_https() {
        let mut session = AuthSession::new("secure");
        session.add_cookie_with_path("sid", "1", "example.com", "/", false, true);

        let settings = SessionSettings::default();
        assert!(!session
            .cookie_header_for("example.com", "/", false, &settings)
            .contains("sid=1"));
        assert!(session
            .cookie_header_for("example.com", "/", true, &settings)
            .contains("sid=1"));
    }

    #[test]
    fn cookie_set_cookie_serialization_preserves_flags() {
        let mut cookie = Cookie::new("sid", "1", "example.com");
        cookie.path = "/app".to_string();
        cookie.http_only = true;
        cookie.secure = true;

        assert_eq!(
            cookie.to_set_cookie_string(),
            "sid=1; Domain=example.com; Path=/app; HttpOnly; Secure"
        );
    }

    #[test]
    fn session_store_multi_user() {
        let mut store = SessionStore::new();

        let mut admin = AuthSession::new("admin");
        admin.add_cookie("session", "admin-sess", "target.com");

        let mut user = AuthSession::new("user");
        user.add_cookie("session", "user-sess", "target.com");

        store.add(admin);
        store.add(user);

        assert_eq!(store.len(), 2);

        let settings = SessionSettings::default();
        let admin_cookies =
            store
                .get("admin")
                .unwrap()
                .cookie_header_for("target.com", "/", false, &settings);
        let user_cookies =
            store
                .get("user")
                .unwrap()
                .cookie_header_for("target.com", "/", false, &settings);

        assert!(admin_cookies.contains("admin-sess"));
        assert!(user_cookies.contains("user-sess"));
        assert!(!admin_cookies.contains("user-sess"));
    }

    #[test]
    fn session_store_names_sorted() {
        let mut store = SessionStore::new();
        store.add(AuthSession::new("z"));
        store.add(AuthSession::new("a"));
        store.add(AuthSession::new("m"));

        assert_eq!(store.names(), vec!["a", "m", "z"]);
    }

    #[test]
    fn serde_roundtrip() {
        let mut session = AuthSession::new("test");
        session.add_cookie("key", "value", "example.com");

        let json = serde_json::to_string(&session).unwrap();
        let back: AuthSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert_eq!(back.cookie_count(), 1);
    }

    #[test]
    fn session_store_serde_roundtrip_with_settings() {
        let settings = SessionSettings {
            match_subdomains: false,
            ..Default::default()
        };

        let mut store = SessionStore::with_settings(settings);
        let mut admin = AuthSession::new("admin");
        admin.add_cookie("session", "a", "example.com");
        store.add(admin);

        let json = serde_json::to_string(&store).unwrap();
        let loaded: SessionStore = serde_json::from_str(&json).unwrap();

        assert!(!loaded.settings.match_subdomains);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn session_store_settings_accessors_work() {
        let mut store = SessionStore::new();
        assert_eq!(store.settings().default_path, "/");
        store.settings_mut().default_path = "/api".to_string();
        assert_eq!(store.settings().default_path, "/api");
    }

    #[test]
    fn session_store_add_cookie_to_session_creates_session() {
        let mut store = SessionStore::new();
        store.add_cookie_to_session("worker", "sid", "1", "example.com");
        assert_eq!(store.len(), 1);
        assert!(store.get("worker").is_some());
    }

    #[test]
    fn session_store_add_set_cookie_to_session_creates_session() {
        let mut store = SessionStore::new();
        store.add_set_cookie_to_session("worker", "sid=1; Path=/", "example.com");
        assert_eq!(store.len(), 1);
        let header = store
            .get("worker")
            .unwrap()
            .cookie_header("example.com", &SessionSettings::default());
        assert!(header.contains("sid=1"));
    }

    #[test]
    fn session_store_get_mut_can_modify_session() {
        let mut store = SessionStore::new();
        store.add(AuthSession::new("mutable"));
        store
            .get_mut("mutable")
            .unwrap()
            .add_cookie("sid", "1", "example.com");
        assert!(store
            .get("mutable")
            .unwrap()
            .cookie_header("example.com", &SessionSettings::default())
            .contains("sid=1"));
    }

    #[test]
    fn session_store_is_empty_tracks_state() {
        let mut store = SessionStore::new();
        assert!(store.is_empty());
        store.add(AuthSession::new("a"));
        assert!(!store.is_empty());
    }

    #[test]
    fn session_store_save_and_load_file() {
        let path = temp_path("session_store");
        let mut store = SessionStore::new();

        let mut session = AuthSession::new("bot");
        session.add_cookie("token", "abc", "example.com");
        store.add(session);

        store.save_to_file(&path).unwrap();

        let loaded = SessionStore::load_from_file(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded
            .get("bot")
            .unwrap()
            .cookie_header("example.com", &SessionSettings::default())
            .contains("token=abc"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn session_store_load_from_file_with_legacy_format() {
        let path = temp_path("legacy_store");
        let legacy = serde_json::json!({"sessions":{"legacy":{"name":"legacy","cookies":{}}}});

        let mut file = fs::File::create(&path).unwrap();
        file.write_all(serde_json::to_string(&legacy).unwrap().as_bytes())
            .unwrap();

        let loaded = SessionStore::load_from_file(&path).unwrap();
        assert_eq!(loaded.len(), 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn session_settings_toml_roundtrip() {
        let settings = SessionSettings {
            default_domain: Some("example.com".to_string()),
            match_subdomains: false,
            ..Default::default()
        };

        let text = toml::to_string_pretty(&settings).unwrap();
        let parsed = SessionSettings::from_toml_str(&text).unwrap();

        assert_eq!(parsed.default_domain, Some("example.com".to_string()));
        assert!(!parsed.match_subdomains);
    }

    #[test]
    fn session_settings_from_toml_file() {
        let path = temp_path("settings");
        let settings = SessionSettings {
            default_domain: Some("example.com".to_string()),
            default_path: "/app".to_string(),
            match_subdomains: true,
        };

        settings.save_to_toml_file(&path).unwrap();
        let loaded = SessionSettings::from_toml_file(&path).unwrap();

        assert_eq!(loaded.default_domain, Some("example.com".to_string()));
        assert_eq!(loaded.default_path, "/app");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn session_settings_reject_invalid_default_path() {
        let err = SessionSettings::from_toml_str("default_path = 'relative'").unwrap_err();
        assert!(err.to_string().contains("invalid cookie path"));
    }

    #[test]
    fn session_settings_reject_unicode_default_domain() {
        let err = SessionSettings::from_toml_str("default_domain = 'éxample.com'").unwrap_err();
        assert!(err.to_string().contains("invalid cookie domain"));
    }

    #[test]
    fn session_settings_from_toml_file_errors_for_missing_path() {
        let path = temp_path("settings_missing");
        let err = SessionSettings::from_toml_file(&path).unwrap_err();
        assert!(matches!(err, AuthJarError::Io(_)));
    }

    #[test]
    fn concurrent_store_access_via_mutex_is_stable() {
        let store = Arc::new(Mutex::new(SessionStore::new()));
        let mut handles = Vec::new();

        for i in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for j in 0..32 {
                    let mut guard = store.lock().unwrap();
                    guard.add_cookie_to_session(
                        &format!("s{i}"),
                        format!("k{j}"),
                        format!("v{j}"),
                        "example.com",
                    );
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let guard = store.lock().unwrap();
        assert_eq!(guard.len(), 8);
        for i in 0..8 {
            assert_eq!(
                guard
                    .get(&format!("s{i}"))
                    .unwrap()
                    .cookie_count(),
                32
            );
        }
    }

    #[test]
    fn save_to_file_returns_io_error_for_invalid_path() {
        let mut store = SessionStore::new();
        store.add(AuthSession::new("x"));
        let err = store.save_to_file("/proc/authjar-should-fail/session.json").unwrap_err();
        assert!(matches!(err, AuthJarError::Io(_)));
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn session_store_async_save_and_load_file() {
        let path = temp_path("session_store_async");
        let mut store = SessionStore::new();
        let mut session = AuthSession::new("bot");
        session.add_cookie("token", "abc", "example.com");
        store.add(session);

        store.save_to_file_async(&path).await.unwrap();
        let loaded = SessionStore::load_from_file_async(&path).await.unwrap();

        assert_eq!(loaded.len(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn session_store_rejects_oversized_file() {
        let path = temp_path("oversized_store");
        let oversized =
            vec![
                b'a';
                usize::try_from(MAX_STORE_FILE_BYTES).expect("store size fits in usize") + 1
            ];
        fs::write(&path, oversized).unwrap();

        let err = SessionStore::load_from_file(&path).unwrap_err();
        assert!(err.to_string().contains("Fix: keep file <="));

        let _ = fs::remove_file(path);
    }
}
