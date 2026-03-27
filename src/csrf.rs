//! CSRF token extraction and injection.
//!
//! Automatically finds CSRF tokens from three sources:
//! 1. HTML meta tags (e.g., `<meta name="csrf-token" content="...">`)
//! 2. HTTP response headers (e.g., `X-CSRF-Token`)
//! 3. Cookies (e.g., `XSRF-TOKEN`)
//!
//! Then injects the token back into outgoing requests via the
//! appropriate mechanism (form field, header, or cookie header).

use serde::{Deserialize, Serialize};

/// Where the CSRF token was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsrfSource {
    /// From an HTML `<meta>` or `<input>` tag.
    HtmlTag,
    /// From a response header (e.g., `X-CSRF-Token`).
    Header,
    /// From a cookie (e.g., `XSRF-TOKEN`).
    Cookie,
}

/// A discovered CSRF token with its source and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfToken {
    /// The token value.
    pub value: String,
    /// Where the token was found.
    pub source: CsrfSource,
    /// The field/header/cookie name the token was found under.
    pub field_name: String,
}

/// Well-known CSRF cookie names.
const CSRF_COOKIE_NAMES: &[&str] = &[
    "xsrf-token",
    "csrf-token",
    "csrftoken",
    "_csrf",
    "csrf",
    "x-csrf-token",
    "x-xsrf-token",
    "__requestverificationtoken",
];

/// Well-known CSRF header names.
const CSRF_HEADER_NAMES: &[&str] = &[
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "x-csrftoken",
];

/// Well-known CSRF meta tag / input names.
const CSRF_HTML_NAMES: &[&str] = &[
    "csrf-token",
    "csrf_token",
    "csrfmiddlewaretoken",
    "_token",
    "authenticity_token",
    "__requestverificationtoken",
    "antiforgerytoken",
    "_csrf",
];

use std::sync::OnceLock;
use regex::Regex;

const MAX_HTML_SCAN_BYTES: usize = 256 * 1024;
const MAX_TOKEN_NAME_LEN: usize = 128;
const MAX_TOKEN_VALUE_LEN: usize = 4096;
const MAX_EXTRACTED_TOKENS: usize = 128;

fn meta_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Allow name before content OR content before name
    RE.get_or_init(|| {
        Regex::new(r#"(?i)<meta\s+(?:name=["']([^"']+)["']\s+content=["']([^"']+)["']|content=["']([^"']+)["']\s+name=["']([^"']+)["'])"#).unwrap_or_else(|_| unreachable!())
    })
}

fn input_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Allow name before value OR value before name
    RE.get_or_init(|| {
        Regex::new(r#"(?i)<input\s+(?:[^>]*name=["']([^"']+)["'][^>]*value=["']([^"']+)["']|[^>]*value=["']([^"']+)["'][^>]*name=["']([^"']+)["'])"#).unwrap_or_else(|_| unreachable!())
    })
}

/// Extract CSRF tokens from an HTTP response.
///
/// Searches HTML body, response headers, and cookies for known CSRF patterns.
/// Returns all discovered tokens, ordered by confidence (HTML > Header > Cookie).
#[must_use]
pub fn extract_csrf_tokens(
    html_body: &str,
    response_headers: &[(String, String)],
    cookies: &[(String, String)],
) -> Vec<CsrfToken> {
    let mut tokens = Vec::new();
    let html = if html_body.len() > MAX_HTML_SCAN_BYTES {
        &html_body[..MAX_HTML_SCAN_BYTES]
    } else {
        html_body
    };

    // 1. HTML meta tags: <meta name="csrf-token" content="...">
    for cap in meta_regex().captures_iter(html) {
        let (name, value) = if let Some(n) = cap.get(1) {
            (n.as_str(), cap.get(2).map_or("", |m| m.as_str()))
        } else if let Some(c) = cap.get(3) {
            (cap.get(4).map_or("", |m| m.as_str()), c.as_str())
        } else {
            ("", "")
        };

        if is_allowed_html_name(name) && is_safe_token_value(value) {
            tokens.push(CsrfToken {
                value: value.to_string(),
                source: CsrfSource::HtmlTag,
                field_name: name.to_string(),
            });
            if tokens.len() >= MAX_EXTRACTED_TOKENS {
                return tokens;
            }
        }
    }

    // Replace the complex input input_pattern logic
    for cap in input_regex().captures_iter(html) {
        let (name, value) = if let Some(n) = cap.get(1) {
            (n.as_str(), cap.get(2).map_or("", |m| m.as_str()))
        } else if let Some(v) = cap.get(3) {
            (cap.get(4).map_or("", |m| m.as_str()), v.as_str())
        } else {
            ("", "")
        };

        if is_allowed_html_name(name) && is_safe_token_value(value) {
            tokens.push(CsrfToken {
                value: value.to_string(),
                source: CsrfSource::HtmlTag,
                field_name: name.to_string(),
            });
            if tokens.len() >= MAX_EXTRACTED_TOKENS {
                return tokens;
            }
        }
    }

    // 2. Response headers
    for (name, value) in response_headers {
        if is_allowed_header_name(name) && is_safe_token_value(value) {
            tokens.push(CsrfToken {
                value: value.clone(),
                source: CsrfSource::Header,
                field_name: name.clone(),
            });
            if tokens.len() >= MAX_EXTRACTED_TOKENS {
                return tokens;
            }
        }
    }

    // 3. Cookies
    for (name, value) in cookies {
        if is_allowed_cookie_name(name) && is_safe_token_value(value) {
            tokens.push(CsrfToken {
                value: value.clone(),
                source: CsrfSource::Cookie,
                field_name: name.clone(),
            });
            if tokens.len() >= MAX_EXTRACTED_TOKENS {
                return tokens;
            }
        }
    }

    tokens
}

fn is_safe_token_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_NAME_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
}

fn is_safe_token_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_VALUE_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x20..=0x7e) && !matches!(byte, b'\r' | b'\n'))
}

fn is_allowed_html_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_safe_token_name(&lower) && CSRF_HTML_NAMES.contains(&lower.as_str())
}

fn is_allowed_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_safe_token_name(&lower) && CSRF_HEADER_NAMES.contains(&lower.as_str())
}

fn is_allowed_cookie_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_safe_token_name(&lower) && CSRF_COOKIE_NAMES.contains(&lower.as_str())
}

/// Inject a CSRF token into an outgoing request.
///
/// Returns the header name and value to add to the request.
/// For cookie-based tokens, returns an `X-CSRF-Token` or `X-XSRF-Token` header.
/// For header-based tokens, returns the same header.
/// For HTML-based tokens, returns the form field name and value
/// (caller must add to the request body).
#[must_use]
pub fn inject_csrf_token(token: &CsrfToken) -> (&str, &str) {
    match token.source {
        CsrfSource::Header | CsrfSource::HtmlTag => (&token.field_name, &token.value),
        CsrfSource::Cookie => {
            // Cookie-based CSRF: inject as X-XSRF-Token header
            let header = if token.field_name.to_lowercase().contains("xsrf") {
                "X-XSRF-Token"
            } else {
                "X-CSRF-Token"
            };
            (header, &token.value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_meta_tag() {
        let html = r#"<html><head><meta name="csrf-token" content="meta-token-123"></head></html>"#;
        let tokens = extract_csrf_tokens(html, &[], &[]);
        assert!(!tokens.is_empty());
        assert_eq!(tokens[0].value, "meta-token-123");
        assert_eq!(tokens[0].source, CsrfSource::HtmlTag);
    }

    #[test]
    fn extract_from_input_field() {
        let html = r#"<form><input type="hidden" name="csrfmiddlewaretoken" value="form-token-456"></form>"#;
        let tokens = extract_csrf_tokens(html, &[], &[]);
        assert!(!tokens.is_empty());
        assert_eq!(tokens[0].value, "form-token-456");
    }

    #[test]
    fn extract_from_header() {
        let headers = vec![("X-CSRF-Token".to_string(), "header-token-789".to_string())];
        let tokens = extract_csrf_tokens("", &headers, &[]);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].value, "header-token-789");
        assert_eq!(tokens[0].source, CsrfSource::Header);
    }

    #[test]
    fn extract_from_cookie() {
        let cookies = vec![("XSRF-TOKEN".to_string(), "cookie-token-abc".to_string())];
        let tokens = extract_csrf_tokens("", &[], &cookies);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].value, "cookie-token-abc");
        assert_eq!(tokens[0].source, CsrfSource::Cookie);
    }

    #[test]
    fn extract_all_sources() {
        let html = r#"<meta name="csrf-token" content="meta-val">"#;
        let headers = vec![("X-CSRF-Token".to_string(), "header-val".to_string())];
        let cookies = vec![("XSRF-TOKEN".to_string(), "cookie-val".to_string())];

        let tokens = extract_csrf_tokens(html, &headers, &cookies);
        assert!(tokens.len() >= 3);
    }

    #[test]
    fn inject_cookie_based() {
        let token = CsrfToken {
            value: "token-val".to_string(),
            source: CsrfSource::Cookie,
            field_name: "XSRF-TOKEN".to_string(),
        };
        let (header, value) = inject_csrf_token(&token);
        assert_eq!(header, "X-XSRF-Token");
        assert_eq!(value, "token-val");
    }

    #[test]
    fn inject_header_based() {
        let token = CsrfToken {
            value: "token-val".to_string(),
            source: CsrfSource::Header,
            field_name: "X-CSRF-Token".to_string(),
        };
        let (header, value) = inject_csrf_token(&token);
        assert_eq!(header, "X-CSRF-Token");
        assert_eq!(value, "token-val");
    }

    #[test]
    fn empty_values_skipped() {
        let cookies = vec![("XSRF-TOKEN".to_string(), String::new())];
        let tokens = extract_csrf_tokens("", &[], &cookies);
        assert!(tokens.is_empty());
    }

    #[test]
    fn skips_header_injection_values() {
        let headers = vec![(
            "X-CSRF-Token".to_string(),
            "good\r\nX-Injected: evil".to_string(),
        )];
        let tokens = extract_csrf_tokens("", &headers, &[]);
        assert!(tokens.is_empty());
    }

    #[test]
    fn caps_extracted_token_count() {
        let mut html = String::new();
        for _ in 0..256 {
            html.push_str(r#"<meta name="csrf-token" content="v">"#);
        }
        let tokens = extract_csrf_tokens(&html, &[], &[]);
        assert_eq!(tokens.len(), MAX_EXTRACTED_TOKENS);
    }
}
