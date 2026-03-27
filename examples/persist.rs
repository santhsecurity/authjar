use authjar::{AuthSession, SessionStore};
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let path: PathBuf = std::env::temp_dir().join("authjar-session-store.json");

    let mut store = SessionStore::new();
    let mut session = AuthSession::new("runner");
    session.add_cookie("session-id", "abc123", "example.com");
    store.add(session);

    store.save_to_file(&path)?;
    println!("saved sessions to {}", path.display());

    let loaded = SessionStore::load_from_file(&path)?;
    println!("loaded sessions: {:?}", loaded.names());
    println!(
        "loaded cookie header: {}",
        loaded
            .get("runner")
            .expect("runner session exists")
            .cookie_header("example.com", &authjar::SessionSettings::default())
    );

    Ok(())
}
