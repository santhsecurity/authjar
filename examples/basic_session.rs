use authjar::SessionStore;

fn main() {
    let mut store = SessionStore::new();
    let mut user = authjar::AuthSession::new("user");

    user.add_cookie("session_id", "u-123", "example.com");
    user.add_cookie("prefs", "dark", "example.com");
    user.add_cookie("api_token", "token-456", "api.example.com");

    let direct_cookie = user.cookie_header("example.com", &authjar::SessionSettings::default());
    println!("cookies for example.com: {direct_cookie}");

    user.add_cookie_header_line("Set-Cookie: promo=summer; Domain=.example.com; Path=/");
    let all = user.cookie_header("example.com", &authjar::SessionSettings::default());
    println!("cookies after header parse: {all}");

    store.add(user);
    let settings = store.settings();
    println!("store sessions: {:?}", store.names());
    println!(
        "session cookie header: {}",
        store
            .get("user")
            .expect("session exists")
            .cookie_header_for("api.example.com", "/", false, settings)
    );

}
