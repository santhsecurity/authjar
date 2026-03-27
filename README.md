# authjar

Multi-session cookie management. Parse Set-Cookie headers, store cookies with domain and path scoping, match cookies to requests, and persist sessions to JSON. Includes CSRF token extraction and injection helpers.

Warning: `SessionStore::save_to_file` writes plaintext session material. Use filesystem encryption, a protected secrets store, or wrap persistence with your own encryption before storing production credentials.

```rust
use authjar::{AuthSession, Cookie, SessionStore, SessionSettings};

// Create a session and add cookies
let mut session = AuthSession::new("admin");
session.add_cookie("PHPSESSID", "abc123", "example.com");
session.add_cookie("auth_token", "xyz789", "example.com");

// Build Cookie header for a request
let header = session.cookie_header("example.com");
assert!(header.contains("PHPSESSID=abc123"));
```

## Why this exists

HTTP clients handle cookies, but most lack multi-session support. When scanning web apps, you need to switch between user roles. Admin session here. Regular user session there. Guest session for unauthenticated flows. Each with its own cookie jar.

authjar provides named sessions with domain-scoped storage, path matching, secure cookie handling, and JSON persistence. CSRF helpers extract tokens from HTML meta tags, headers, and cookies, then inject them into outgoing requests.

## Session management

Named sessions isolate cookie jars:

```rust
use authjar::SessionStore;

let mut store = SessionStore::new();

let mut admin = AuthSession::new("admin");
admin.add_cookie("session", "admin-sess", "target.com");

let mut user = AuthSession::new("user");
user.add_cookie("session", "user-sess", "target.com");

store.add(admin);
store.add(user);

// Later
let settings = SessionSettings::default();
let admin_cookies = store.get("admin").unwrap()
    .cookie_header_for("target.com", "/", true, &settings);
```

## Cookie parsing

Parse Set-Cookie headers with full attribute support:

```rust
use authjar::Cookie;

let cookie = Cookie::from_set_cookie(
    "session=abc; Path=/; Domain=.example.com; HttpOnly; Secure",
    "fallback.com"
).unwrap();

assert_eq!(cookie.name, "session");
assert!(cookie.http_only);
assert!(cookie.secure);
assert_eq!(
    cookie.to_set_cookie_string(),
    "session=abc; Domain=example.com; Path=/; HttpOnly; Secure"
);
```

Parse raw header lines:

```rust
let cookie = Cookie::from_header_line(
    "Set-Cookie: token=xyz; Domain=api.example.com"
).unwrap();
```

When the header omits `Domain`, pass the request host so host-only cookies are scoped correctly:

```rust
let cookie = Cookie::from_header_line_with_domain(
    "Set-Cookie: token=xyz; Path=/api",
    Some("api.example.com")
).unwrap();
assert_eq!(cookie.domain, "api.example.com");
```

## Domain and path scoping

Cookies match requests by domain and path rules:

| Request | Cookie Domain | Match? |
|---------|---------------|--------|
| api.example.com | example.com | Yes (subdomain) |
| example.com | .example.com | Yes (leading dot) |
| bad-example.com | example.com | No (prefix collision) |
| /api/v1 | /api | Yes (path prefix) |
| /application | /app | No (partial match) |

Disable subdomain matching via `SessionSettings`:

```rust
let settings = SessionSettings {
    match_subdomains: false,
    ..Default::default()
};
```

## Secure cookies

Secure-flagged cookies only match HTTPS requests:

```rust
session.add_cookie_with_path("sid", "1", "example.com", "/", false, true);

// Won't include for http://
let http_cookies = session.cookie_header_for("example.com", "/", false, &settings);
assert!(!http_cookies.contains("sid"));

// Will include for https://
let https_cookies = session.cookie_header_for("example.com", "/", true, &settings);
assert!(https_cookies.contains("sid"));
```

## CSRF token handling

Extract tokens from multiple sources:

```rust
use authjar::{extract_csrf_tokens, inject_csrf_token};

let html = r#"<meta name="csrf-token" content="token-123">"#;
let headers = vec![("X-CSRF-Token".to_string(), "header-token".to_string())];
let cookies = vec![("XSRF-TOKEN".to_string(), "cookie-token".to_string())];

let tokens = extract_csrf_tokens(html, &headers, &cookies);
```

Inject tokens into requests:

```rust
if let Some(token) = tokens.first() {
    let (header_name, value) = inject_csrf_token(token);
    request.set_header(&header_name, &value);
}
```

CSRF token sources:

- HTML meta tags: `<meta name="csrf-token" content="...">`
- HTML input fields: `<input name="csrf_token" value="...">`
- Response headers: `X-CSRF-Token`, `X-XSRF-Token`
- Cookies: `XSRF-TOKEN`, `csrf-token`, `csrftoken`

## Persistence

Save and load sessions as JSON:

```rust
// Save
store.save_to_file("/tmp/sessions.json")?;

// Load
let loaded = SessionStore::load_from_file("/tmp/sessions.json")?;
```

Session settings can be loaded from TOML:

```rust
let settings = SessionSettings::from_toml_str(r#"
default_domain = "example.com"
match_subdomains = true
"#)?;
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/authjar.svg)](https://crates.io/crates/authjar)
[![docs.rs](https://docs.rs/authjar/badge.svg)](https://docs.rs/authjar)
