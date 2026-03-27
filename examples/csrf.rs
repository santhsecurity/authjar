use authjar::{extract_csrf_tokens, inject_csrf_token};

fn main() {
    let html = r#"
        <html>
            <head>
                <meta name="csrf-token" content="meta-token-1">
            </head>
            <body>
                <form>
                    <input type="hidden" name="csrfmiddlewaretoken" value="form-token-2">
                </form>
            </body>
        </html>
    "#;

    let headers = vec![("X-CSRF-Token".to_string(), "header-token-3".to_string())];
    let cookies = vec![("XSRF-TOKEN".to_string(), "cookie-token-4".to_string())];

    let tokens = extract_csrf_tokens(html, &headers, &cookies);
    for token in tokens {
        let (field, value) = inject_csrf_token(&token);
        println!("{:?} injection => {field}: {value}", token.source);
    }
}
