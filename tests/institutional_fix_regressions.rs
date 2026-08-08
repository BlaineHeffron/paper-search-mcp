//! Regression locks for security findings raised during joint review.
//!
//! Owned by the security reviewer. Each test corresponds to a specific finding
//! and independently verifies the fix rather than taking the implementer's word
//! for it. The finding id in each test name maps to the review thread.
//!
//! If one of these fails, a previously-closed security finding has reopened.

mod common;

use std::{fs, path::Path, sync::Arc, sync::Mutex, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use paper_search::institutional::{
    retrieval::{
        HostResolver, InstitutionalRetriever, RetrievalConfig, RetrievalError, RetrievalTransport,
        TransportRequest, TransportResponse,
    },
    store::{KeyProtectionStatus, KeyProvider, StoreError},
    InstitutionalSessionConfig, InstitutionalSessionManager,
};
use reqwest::Url;
use tempfile::TempDir;
use zeroize::Zeroizing;

const PROXY_HOST: &str = "proxy.example.edu";

struct WorkingKeys {
    key: Mutex<Option<Vec<u8>>>,
}

impl WorkingKeys {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            key: Mutex::new(None),
        })
    }
}

impl KeyProvider for WorkingKeys {
    fn get(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.key
            .lock()
            .unwrap()
            .clone()
            .map(Zeroizing::new)
            .ok_or(StoreError::KeyMissing)
    }
    fn get_or_create(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let mut guard = self.key.lock().unwrap();
        if guard.is_none() {
            *guard = Some(vec![0x11; 32]);
        }
        Ok(Zeroizing::new(guard.clone().unwrap()))
    }
    fn delete(&self) -> Result<(), StoreError> {
        *self.key.lock().unwrap() = None;
        Ok(())
    }
    fn status(&self) -> KeyProtectionStatus {
        KeyProtectionStatus::OsKeyring
    }
}

fn private_temp() -> TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn config_for(temp: &TempDir, allowed_hosts: Vec<String>) -> InstitutionalSessionConfig {
    InstitutionalSessionConfig {
        data_dir: temp.path().to_path_buf(),
        institution_id: "example-university".to_string(),
        institution_name: "Example University".to_string(),
        allowed_hosts,
        max_session_ttl_seconds: 12 * 3600,
    }
}

fn manager(temp: &TempDir) -> InstitutionalSessionManager {
    InstitutionalSessionManager::with_key_provider(
        config_for(temp, vec![PROXY_HOST.to_string()]),
        WorkingKeys::new(),
    )
    .expect("manager constructs")
}

fn auth_url() -> Url {
    Url::parse("https://proxy.example.edu/login").unwrap()
}

fn write_export(path: &str, contents: &str) {
    fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn scoped_cookies() -> String {
    common::netscape_cookie_file(PROXY_HOST, Utc::now().timestamp() + 86_400)
}

// ── H1: repository detection must work in a distributed binary ──────────────

/// The original check compared against `env!("CARGO_MANIFEST_DIR")`, a path
/// baked in at compile time. In a released binary that path does not exist on
/// the user's machine, so the check errored and disabled the whole subsystem.
/// The fix must detect repositories at RUNTIME.
#[test]
fn h1_repository_detection_is_runtime_not_compile_time() {
    // A data dir with no `.git` anywhere above it must be accepted. Under the
    // old compile-time check this failed on any machine that was not the
    // builder; here it proves the check no longer depends on build-time paths.
    let temp = private_temp();
    assert!(
        InstitutionalSessionManager::with_key_provider(
            config_for(&temp, vec![PROXY_HOST.to_string()]),
            WorkingKeys::new(),
        )
        .is_ok(),
        "a data dir outside any repository must be accepted"
    );
}

/// The check must still do its actual job: refuse a data directory inside a
/// git worktree, so secrets cannot land in version control.
#[test]
fn h1_data_dir_inside_a_repository_is_still_refused() {
    let temp = private_temp();
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(repo.join(".git")).unwrap();
    let inside = repo.join("data");
    fs::create_dir(&inside).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let config = InstitutionalSessionConfig {
        data_dir: inside,
        ..config_for(&temp, vec![PROXY_HOST.to_string()])
    };
    assert!(
        InstitutionalSessionManager::with_key_provider(config, WorkingKeys::new()).is_err(),
        "a data dir inside a git worktree must be refused"
    );
}

/// `.git` is a FILE, not a directory, in linked worktrees and submodules. A
/// check written as `is_dir()` would miss those.
#[test]
fn h1_git_file_worktree_marker_is_also_detected() {
    let temp = private_temp();
    let repo = temp.path().join("worktree");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join(".git"), b"gitdir: /elsewhere/.git/worktrees/wt\n").unwrap();
    let inside = repo.join("data");
    fs::create_dir(&inside).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let config = InstitutionalSessionConfig {
        data_dir: inside,
        ..config_for(&temp, vec![PROXY_HOST.to_string()])
    };
    assert!(
        InstitutionalSessionManager::with_key_provider(config, WorkingKeys::new()).is_err(),
        "a `.git` FILE marks a linked worktree and must be detected too"
    );
}

// ── H2: the data directory's own mode is enforced ───────────────────────────

/// A group- or world-writable data directory permits a rename-swap against our
/// 0700 child, which the child's own check cannot detect. The parent must be
/// validated too, and the refusal must be honest rather than a silent downgrade.
#[cfg(unix)]
#[test]
fn h2_permissive_data_dir_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    for (mode, why) in common::UNSAFE_DIR_MODES {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(*mode)).unwrap();

        let result = InstitutionalSessionManager::with_key_provider(
            config_for(&temp, vec![PROXY_HOST.to_string()]),
            WorkingKeys::new(),
        );
        assert!(
            result.is_err(),
            "data dir at mode {mode:o} must be refused ({why})"
        );
    }
}

// ── H3 / R4: public-suffix scoping ──────────────────────────────────────────

/// `host_in_scope` matches on a dotted suffix, so a bare public suffix as an
/// allowed host would scope session cookies to every domain under it.
#[test]
fn h3_bare_public_suffixes_are_rejected_as_allowed_hosts() {
    for suffix in ["edu", "com", "co.uk", "ac.uk", "org", "net"] {
        let temp = private_temp();
        let result = InstitutionalSessionManager::with_key_provider(
            config_for(&temp, vec![suffix.to_string()]),
            WorkingKeys::new(),
        );
        assert!(
            result.is_err(),
            "bare public suffix must be refused as an allowed host: {suffix}"
        );
    }
}

/// The check must not be so blunt that legitimate hosts break, including
/// multi-label public suffixes used properly.
#[test]
fn h3_legitimate_institution_hosts_are_accepted() {
    for host in [
        "proxy.example.edu",
        "proxyiub.uits.iu.edu",
        "library.example.co.uk",
    ] {
        let temp = private_temp();
        assert!(
            InstitutionalSessionManager::with_key_provider(
                config_for(&temp, vec![host.to_string()]),
                WorkingKeys::new(),
            )
            .is_ok(),
            "legitimate institution host must be accepted: {host}"
        );
    }
}

// ── H4: cookie header injection ─────────────────────────────────────────────

/// A cookie value containing `;` forges an extra cookie pair when the header is
/// assembled. `HeaderValue` does not reject `;`, so this has to be caught at
/// import.
#[test]
fn h4_cookie_delimiter_and_control_injection_is_refused_at_import() {
    let expiry = Utc::now().timestamp() + 86_400;
    let injections = [
        ("semicolon in value forges a second cookie", "a;evil=1"),
        ("comma in value", "a,evil=1"),
        ("CR in value", "a\revil=1"),
        ("LF in value", "a\nevil=1"),
        ("NUL in value", "a\u{0000}evil"),
        ("space in value", "a evil"),
    ];

    for (why, value) in injections {
        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager.start(&auth_url()).unwrap();
        write_export(
            &start.cookie_export_path,
            &format!("{PROXY_HOST}\tTRUE\t/\tTRUE\t{expiry}\tsession\t{value}\n"),
        );

        assert!(
            manager.complete(&start.request_id).is_err(),
            "cookie value must be refused ({why}): {value:?}"
        );
    }
}

/// Injection through the cookie NAME is equally effective and must also fail.
#[test]
fn h4_cookie_name_injection_is_refused_at_import() {
    let expiry = Utc::now().timestamp() + 86_400;
    for (why, name) in [
        ("equals in name breaks name=value parsing", "a=b"),
        ("semicolon in name", "a;b"),
        ("space in name", "a b"),
        ("CRLF in name", "a\r\nb"),
    ] {
        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager.start(&auth_url()).unwrap();
        write_export(
            &start.cookie_export_path,
            &format!("{PROXY_HOST}\tTRUE\t/\tTRUE\t{expiry}\t{name}\tvalue\n"),
        );

        assert!(
            manager.complete(&start.request_id).is_err(),
            "cookie name must be refused ({why}): {name:?}"
        );
    }
}

// ── R1 / R2: staged plaintext visibility and lifecycle ──────────────────────

/// A lingering plaintext export must be reported in EVERY state, including a
/// healthy one. Reporting it only on error means the user never learns that
/// cleartext session cookies are sitting on disk.
#[test]
fn r1_lingering_plaintext_export_is_reported_even_when_a_session_is_ready() {
    let temp = private_temp();
    let manager = manager(&temp);

    // Establish a healthy session first.
    let first = manager.start(&auth_url()).unwrap();
    write_export(&first.cookie_export_path, &scoped_cookies());
    let ready = manager.complete(&first.request_id).unwrap();
    assert!(!ready.plaintext_export_present);

    // Now leave an abandoned plaintext export from a second request.
    let second = manager.start(&auth_url()).unwrap();
    write_export(&second.cookie_export_path, &scoped_cookies());

    let status = manager.status().unwrap();
    assert!(
        status.plaintext_export_present,
        "a lingering plaintext export must be reported even when a session is Ready"
    );
    assert!(
        status.plaintext_export_oldest_age_seconds.is_some(),
        "the age of the lingering export must be reported"
    );

    // And the status must still carry no secret material.
    let json = serde_json::to_string(&status).unwrap();
    common::assert_no_secrets(&json, "status with lingering export", &[]);
}

/// Repeated `start()` calls must not accumulate staging directories, each of
/// which could hold a plaintext export forever.
#[test]
fn r2_a_new_start_supersedes_and_purges_the_previous_request() {
    let temp = private_temp();
    let manager = manager(&temp);

    let first = manager.start(&auth_url()).unwrap();
    write_export(&first.cookie_export_path, &scoped_cookies());
    assert!(Path::new(&first.cookie_export_path).exists());

    let second = manager.start(&auth_url()).unwrap();
    assert_ne!(first.request_id, second.request_id);

    assert!(
        !Path::new(&first.cookie_export_path).exists(),
        "a new start must purge the previous request's plaintext export"
    );
    assert!(
        manager.complete(&first.request_id).is_err(),
        "the superseded request must no longer be completable"
    );

    let status = manager.status().unwrap();
    assert_eq!(
        status.pending_request_count, 1,
        "exactly one request may be outstanding"
    );
}

// ── R3: revocation must always work ─────────────────────────────────────────

/// `clear()` is the user's only lever. It previously refused when store
/// permissions had drifted — which is exactly the condition that makes
/// revocation urgent.
#[cfg(unix)]
#[test]
fn r3_clear_succeeds_even_when_store_permissions_have_drifted() {
    use std::os::unix::fs::PermissionsExt;

    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();
    write_export(&start.cookie_export_path, &scoped_cookies());
    manager.complete(&start.request_id).unwrap();

    let store = find_store_file(temp.path()).expect("store exists");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o644)).unwrap();
    // Loading must fail-closed...
    assert!(manager.load_jar().is_err());

    // ...but revocation must still work.
    manager
        .clear()
        .expect("clear must work even when permissions have drifted");
    assert!(
        find_store_file(temp.path()).is_none(),
        "the ciphertext must be gone after clear"
    );
}

/// Revocation must also survive a keyring that cannot delete the key: the
/// ciphertext is what matters, and an orphaned key is inert.
#[test]
fn r3_clear_purges_local_state_even_if_the_keyring_delete_fails() {
    struct DeleteFailsKeys {
        key: Mutex<Option<Vec<u8>>>,
    }
    impl KeyProvider for DeleteFailsKeys {
        fn get(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
            self.key
                .lock()
                .unwrap()
                .clone()
                .map(Zeroizing::new)
                .ok_or(StoreError::KeyMissing)
        }
        fn get_or_create(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
            let mut guard = self.key.lock().unwrap();
            if guard.is_none() {
                *guard = Some(vec![0x33; 32]);
            }
            Ok(Zeroizing::new(guard.clone().unwrap()))
        }
        fn delete(&self) -> Result<(), StoreError> {
            Err(StoreError::KeyringUnavailable)
        }
        fn status(&self) -> KeyProtectionStatus {
            KeyProtectionStatus::OsKeyring
        }
    }

    let temp = private_temp();
    let manager = InstitutionalSessionManager::with_key_provider(
        config_for(&temp, vec![PROXY_HOST.to_string()]),
        Arc::new(DeleteFailsKeys {
            key: Mutex::new(None),
        }),
    )
    .unwrap();

    let start = manager.start(&auth_url()).unwrap();
    write_export(&start.cookie_export_path, &scoped_cookies());
    manager.complete(&start.request_id).unwrap();
    assert!(find_store_file(temp.path()).is_some());

    // Whether clear reports the partial failure or not, the ciphertext must go.
    let _ = manager.clear();
    assert!(
        find_store_file(temp.path()).is_none(),
        "the ciphertext must be removed even when the keyring delete fails"
    );
}

// ── V4 / S8: expired session distinguished from a broken download ───────────

/// An HTML body returned with a session attached almost always means the proxy
/// bounced us to a login page. Reporting that as a generic "not a PDF" makes
/// the caller retry, which is the paywall-probing pattern the rate limiter
/// exists to suppress.
#[tokio::test]
async fn v4_html_login_page_is_reported_as_an_expired_session() {
    struct Html;
    #[async_trait]
    impl RetrievalTransport for Html {
        async fn get(
            &self,
            _request: TransportRequest<'_>,
        ) -> Result<TransportResponse, RetrievalError> {
            Ok(TransportResponse {
                status: 200,
                content_type: Some("text/html; charset=utf-8".to_string()),
                location: None,
                body: b"<!DOCTYPE html><html><body>Please sign in</body></html>".to_vec(),
            })
        }
    }

    struct Public;
    #[async_trait]
    impl HostResolver for Public {
        async fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, RetrievalError> {
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }
    }

    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();
    write_export(&start.cookie_export_path, &scoped_cookies());
    manager.complete(&start.request_id).unwrap();
    let jar = manager.load_jar().unwrap();

    let retriever = InstitutionalRetriever::with_components(
        RetrievalConfig {
            download_root: temp.path().join("downloads"),
            allowed_hosts: vec![PROXY_HOST.to_string()],
            max_response_bytes: 256 * 1024,
            max_redirects: 3,
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(5),
            minimum_interval: Duration::from_secs(1),
            hourly_limit: 10,
        },
        Arc::new(Html),
        Arc::new(Public),
    )
    .unwrap();

    let result = retriever
        .retrieve(
            &jar,
            Url::parse(&format!("https://{PROXY_HOST}/paper.pdf")).unwrap(),
            &Url::parse("https://publisher.example/article").unwrap(),
            None,
            None,
        )
        .await;

    assert!(
        matches!(result, Err(RetrievalError::SessionExpiredOrRejected)),
        "an HTML login page with a session attached must be reported as an \
         expired/rejected session so the caller re-authenticates instead of \
         retrying, got {result:?}"
    );

    // And the error must not carry any page content back to the caller.
    let rendered = format!("{:?}", result.err());
    assert!(
        !rendered.to_lowercase().contains("sign in") && !rendered.contains('<'),
        "response body content must not appear in the error"
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn find_store_file(root: &Path) -> Option<std::path::PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            if entry.file_type().ok()?.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains("session") && n.ends_with(".json"))
            {
                return Some(path);
            }
        }
    }
    None
}
