//! Mock integration tests for the institutional session lifecycle.
//!
//! Owned by the security reviewer. Nothing here contacts IU, a real publisher,
//! or the user's real OS keyring — the key provider is supplied by the test, so
//! `cargo test` never writes to gnome-keyring and passes on machines with no
//! secret service at all.
//!
//! The canary discipline: every fixture cookie carries `COOKIE_CANARY`, and any
//! output that could reach an LLM, a log, or a disk file is asserted not to
//! contain it. `assert_no_secrets` panics without echoing the offending text so
//! a real leak cannot be published into CI output by the failure itself.

mod common;

use std::{fs, path::Path, sync::Arc, sync::Mutex};

use chrono::Utc;
use paper_search::institutional::{
    store::{KeyProtectionStatus, KeyProvider, StoreError},
    InstitutionalSessionConfig, InstitutionalSessionManager, SessionError, SessionState,
};
use reqwest::Url;
use tempfile::TempDir;
use zeroize::Zeroizing;

// ── Test key providers ──────────────────────────────────────────────────────

/// A working in-memory key provider. Stands in for a healthy OS keyring.
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
            *guard = Some(vec![0x2a; 32]);
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

/// A provider that always fails with a configured error. Drives the degraded
/// keyring states without touching a real secret service.
struct FailingKeys {
    error: StoreError,
    status: KeyProtectionStatus,
}

impl FailingKeys {
    fn locked() -> Arc<Self> {
        Arc::new(Self {
            error: StoreError::KeyringLocked,
            status: KeyProtectionStatus::OsKeyringLocked,
        })
    }

    fn unavailable() -> Arc<Self> {
        Arc::new(Self {
            error: StoreError::KeyringUnavailable,
            status: KeyProtectionStatus::OsKeyringUnavailable,
        })
    }

    fn clone_error(&self) -> StoreError {
        match self.error {
            StoreError::KeyringLocked => StoreError::KeyringLocked,
            StoreError::KeyringUnavailable => StoreError::KeyringUnavailable,
            _ => StoreError::KeyringUnavailable,
        }
    }
}

impl KeyProvider for FailingKeys {
    fn get(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        Err(self.clone_error())
    }

    fn get_or_create(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        Err(self.clone_error())
    }

    fn delete(&self) -> Result<(), StoreError> {
        Err(self.clone_error())
    }

    fn status(&self) -> KeyProtectionStatus {
        self.status
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────────

const INSTITUTION_ID: &str = "example-university";
const PROXY_HOST: &str = "proxy.example.edu";

fn private_temp() -> TempDir {
    let temp = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

fn manager_with(temp: &TempDir, keys: Arc<dyn KeyProvider>) -> InstitutionalSessionManager {
    InstitutionalSessionManager::with_key_provider(
        InstitutionalSessionConfig {
            data_dir: temp.path().to_path_buf(),
            institution_id: INSTITUTION_ID.to_string(),
            institution_name: "Example University".to_string(),
            allowed_hosts: vec![PROXY_HOST.to_string()],
            max_session_ttl_seconds: 12 * 3600,
        },
        keys,
    )
    .expect("manager constructs")
}

fn manager(temp: &TempDir) -> InstitutionalSessionManager {
    manager_with(temp, WorkingKeys::new())
}

fn auth_url() -> Url {
    Url::parse("https://proxy.example.edu/login?url=https%3A%2F%2Fpublisher.example%2Fa.pdf")
        .unwrap()
}

/// Write a cookie export at the mode the server demands.
fn write_export(path: &str, contents: &str) {
    fs::write(path, contents).expect("write export");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn scoped_cookie_file() -> String {
    common::netscape_cookie_file(PROXY_HOST, Utc::now().timestamp() + 86_400)
}

// ── Happy path ──────────────────────────────────────────────────────────────

/// The complete browser-handoff lifecycle, end to end, with no network and no
/// real keyring. Also the primary redaction check: the canary must not appear
/// in the completion status, and the plaintext export must be gone afterwards.
#[test]
fn full_lifecycle_start_complete_status_clear() {
    let temp = private_temp();
    let manager = manager(&temp);

    let start = manager.start(&auth_url()).expect("start succeeds");
    assert_eq!(start.request_id.len(), 32);

    // The start response is LLM-visible. It must contain no secret and must say
    // authentication happens elsewhere.
    let start_json = serde_json::to_string(&start).unwrap();
    common::assert_no_secrets(&start_json, "session start response", &[]);

    write_export(&start.cookie_export_path, &scoped_cookie_file());
    assert!(Path::new(&start.cookie_export_path).exists());

    let status = manager.complete(&start.request_id).expect("complete");
    assert!(matches!(status.state, SessionState::Ready));
    assert_eq!(status.cookie_count, 2);
    assert_eq!(status.domains, vec![PROXY_HOST.to_string()]);

    // The plaintext export must be deleted once it is sealed.
    assert!(
        !Path::new(&start.cookie_export_path).exists(),
        "plaintext cookie export must not survive a successful completion"
    );

    // Status is serialized straight into an MCP result.
    let status_json = serde_json::to_string(&status).unwrap();
    common::assert_no_secrets(&status_json, "session status", &[]);

    let jar = manager.load_jar().expect("jar loads");
    assert_eq!(jar.cookie_count(), 2);
    // Debug on the jar must not render values.
    common::assert_no_secrets(&format!("{jar:?}"), "cookie jar Debug", &[]);

    let cleared = manager.clear().expect("clear succeeds");
    assert!(matches!(cleared.state, SessionState::NoSession));
    assert!(manager.load_jar().is_err(), "jar must be gone after clear");
}

/// Nothing written under the data directory may contain cookie material, at any
/// point in the lifecycle. This walks the whole tree rather than checking the
/// one file we expect, so a stray temp file or backup would be caught.
#[test]
fn no_plaintext_cookie_material_anywhere_under_data_dir() {
    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();
    write_export(&start.cookie_export_path, &scoped_cookie_file());
    manager.complete(&start.request_id).unwrap();

    let mut checked = 0usize;
    let mut stack = vec![temp.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("readable") {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
                continue;
            }
            let bytes = fs::read(&path).unwrap();
            checked += 1;
            assert!(
                !bytes
                    .windows(common::COOKIE_CANARY.len())
                    .any(|w| w == common::COOKIE_CANARY.as_bytes()),
                "cookie material found at rest in {}",
                path.display()
            );
        }
    }
    assert!(checked > 0, "expected at least one file to inspect");
}

// ── request_id: traversal and injection ─────────────────────────────────────

/// `complete()` both reads and DELETES through the request id, so a traversal
/// here would be an arbitrary-file-delete primitive.
#[test]
fn hostile_request_ids_are_rejected() {
    let temp = private_temp();
    let manager = manager(&temp);

    for (hostile, why) in common::HOSTILE_REQUEST_IDS {
        let result = manager.complete(hostile);
        assert!(
            matches!(result, Err(SessionError::InvalidRequest)),
            "request id must be rejected ({why}): {hostile:?}"
        );
    }
}

/// A traversing request id must not delete a file outside the request tree,
/// whatever error it returns. Belt-and-braces on the test above.
#[test]
fn traversing_request_id_deletes_nothing() {
    let temp = private_temp();
    let manager = manager(&temp);

    let bystander = temp.path().join("do-not-delete.txt");
    fs::write(&bystander, b"important").unwrap();

    for hostile in [
        "../do-not-delete.txt",
        "../../do-not-delete.txt",
        "./do-not-delete.txt",
    ] {
        let _ = manager.complete(hostile);
        assert!(
            bystander.exists(),
            "a traversing request id deleted a file outside the request tree: {hostile}"
        );
    }
}

// ── Cookie export validation ────────────────────────────────────────────────

/// A world- or group-readable cookie file is a readable session. Refuse it.
#[cfg(unix)]
#[test]
fn insecure_export_permissions_are_refused() {
    use std::os::unix::fs::PermissionsExt;

    for (mode, why) in common::UNSAFE_FILE_MODES {
        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager.start(&auth_url()).unwrap();

        fs::write(&start.cookie_export_path, scoped_cookie_file()).unwrap();
        fs::set_permissions(&start.cookie_export_path, fs::Permissions::from_mode(*mode)).unwrap();

        assert!(
            matches!(
                manager.complete(&start.request_id),
                Err(SessionError::InsecureCookieExport)
            ),
            "mode {mode:o} must be refused ({why})"
        );
    }
}

/// A symlink at the export path would make the server read — and then unlink —
/// a file of the attacker's choosing.
#[cfg(unix)]
#[test]
fn symlinked_export_is_refused_and_target_survives() {
    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();

    let target = temp.path().join("secret-elsewhere.txt");
    fs::write(&target, b"not a cookie file").unwrap();
    std::os::unix::fs::symlink(&target, &start.cookie_export_path).unwrap();

    let result = manager.complete(&start.request_id);
    assert!(
        result.is_err(),
        "a symlinked cookie export must never be accepted"
    );
    assert!(
        target.exists(),
        "the symlink target must not be deleted by a refused completion"
    );
}

/// Missing export is a distinct, actionable state.
#[test]
fn missing_export_reports_its_own_error() {
    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();

    assert!(matches!(
        manager.complete(&start.request_id),
        Err(SessionError::CookieExportMissing)
    ));
}

/// Malformed exports must fail cleanly — no panic, and no echo of file content
/// (which is cookie material) into the error.
#[test]
fn malformed_exports_fail_without_echoing_content() {
    for (why, contents) in common::malformed_cookie_files() {
        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager.start(&auth_url()).unwrap();
        write_export(&start.cookie_export_path, &contents);

        let error = match manager.complete(&start.request_id) {
            Ok(_) => panic!("malformed export must be refused: {why}"),
            Err(error) => error,
        };

        let rendered = format!("{error:?} {error}");
        common::assert_no_secrets(&rendered, &format!("error for '{why}'"), &[]);
    }
}

/// Out-of-scope cookies must be dropped, not stored. The canary lives on the
/// out-of-scope entry here, so if scope filtering fails the canary reaches the
/// store and the at-rest check fires.
#[test]
fn out_of_scope_cookies_are_filtered_out() {
    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();

    let expiry = Utc::now().timestamp() + 86_400;
    let mixed = format!(
        "# Netscape HTTP Cookie File\n\
         evil.test\tTRUE\t/\tTRUE\t{expiry}\tstolen\t{canary}\n\
         attacker.example.edu\tTRUE\t/\tTRUE\t{expiry}\talso_stolen\t{canary}\n\
         {proxy}\tTRUE\t/\tTRUE\t{expiry}\tezproxy\tin-scope-value\n",
        expiry = expiry,
        canary = common::COOKIE_CANARY,
        proxy = PROXY_HOST,
    );
    write_export(&start.cookie_export_path, &mixed);

    let status = manager.complete(&start.request_id).expect("completes");
    assert_eq!(
        status.cookie_count, 1,
        "only the in-scope cookie may be stored"
    );
    assert_eq!(status.domains, vec![PROXY_HOST.to_string()]);
}

/// An export with nothing in scope is its own state, not a generic parse error:
/// it usually means the wrong domain was exported.
#[test]
fn export_with_no_in_scope_cookies_is_distinguished() {
    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();
    write_export(
        &start.cookie_export_path,
        &common::netscape_cookie_file("unrelated.example", Utc::now().timestamp() + 3600),
    );

    assert!(matches!(
        manager.complete(&start.request_id),
        Err(SessionError::NoScopedCookies)
    ));
}

// ── Expiry ──────────────────────────────────────────────────────────────────

/// Already-expired cookies must not produce a live session.
#[test]
fn expired_cookies_do_not_create_a_session() {
    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();
    write_export(
        &start.cookie_export_path,
        &common::netscape_cookie_file(PROXY_HOST, Utc::now().timestamp() - 3600),
    );

    assert!(
        manager.complete(&start.request_id).is_err(),
        "expired cookies must not yield a session"
    );
}

/// A session cookie with no expiry must be capped at the configured TTL rather
/// than stored indefinitely. Proxy sessions are short-lived by nature.
#[test]
fn session_cookies_are_capped_at_the_configured_ttl() {
    let temp = private_temp();
    let ttl = 3600i64;
    let manager = InstitutionalSessionManager::with_key_provider(
        InstitutionalSessionConfig {
            data_dir: temp.path().to_path_buf(),
            institution_id: INSTITUTION_ID.to_string(),
            institution_name: "Example University".to_string(),
            allowed_hosts: vec![PROXY_HOST.to_string()],
            max_session_ttl_seconds: ttl,
        },
        WorkingKeys::new(),
    )
    .unwrap();

    let start = manager.start(&auth_url()).unwrap();
    let before = Utc::now().timestamp();
    // Expiry 0 marks a session cookie; a far-future expiry must also be capped.
    write_export(
        &start.cookie_export_path,
        &format!(
            "{proxy}\tTRUE\t/\tTRUE\t0\tsession\tvalue-a\n\
             {proxy}\tTRUE\t/\tTRUE\t99999999999\tlong\tvalue-b\n",
            proxy = PROXY_HOST
        ),
    );

    let status = manager.complete(&start.request_id).expect("completes");
    let expires = status.expires_at.expect("expiry reported").timestamp();
    assert!(
        expires <= before + ttl + 5,
        "expiry {expires} must be capped at the configured TTL"
    );
}

// ── Keyring degradation ─────────────────────────────────────────────────────

/// With no usable keyring the session must NOT be stored, and above all must
/// not be stored in the clear. Fail closed.
#[test]
fn keyring_failure_stores_nothing_and_never_falls_back_to_plaintext() {
    for (label, keys) in [
        ("locked", FailingKeys::locked() as Arc<dyn KeyProvider>),
        (
            "unavailable",
            FailingKeys::unavailable() as Arc<dyn KeyProvider>,
        ),
    ] {
        let temp = private_temp();
        let manager = manager_with(&temp, keys);
        let start = manager.start(&auth_url()).unwrap();
        write_export(&start.cookie_export_path, &scoped_cookie_file());

        assert!(
            manager.complete(&start.request_id).is_err(),
            "completion must fail when the keyring is {label}"
        );
        assert!(
            manager.load_jar().is_err(),
            "no session may be readable when the keyring is {label}"
        );

        // Critically: no ENCRYPTED-store file may have been written with a
        // plaintext or absent key. Walk the tree and confirm the only place the
        // canary can appear is the user's own staged export.
        let mut stack = vec![temp.path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.file_name().and_then(|n| n.to_str()) == Some("cookies.txt") {
                    continue; // the user's own staged plaintext, by design
                }
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !bytes
                        .windows(common::COOKIE_CANARY.len())
                        .any(|w| w == common::COOKIE_CANARY.as_bytes()),
                    "cookie material written outside the staged export while keyring was {label}: {}",
                    path.display()
                );
            }
        }
    }
}

/// The three keyring conditions must be distinguishable — the operator's fix
/// differs for each, and collapsing them sends people looking for the wrong
/// problem.
#[test]
fn keyring_states_are_reported_distinctly() {
    let locked_temp = private_temp();
    let locked = manager_with(&locked_temp, FailingKeys::locked());
    let locked_status = locked.status().expect("status is always available");
    assert!(
        matches!(locked_status.state, SessionState::KeyringLocked),
        "locked keyring must report KeyringLocked, got {:?}",
        locked_status.state
    );

    let missing_temp = private_temp();
    let missing = manager_with(&missing_temp, FailingKeys::unavailable());
    let missing_status = missing.status().expect("status is always available");
    assert!(
        matches!(missing_status.state, SessionState::KeyringUnavailable),
        "unavailable keyring must report KeyringUnavailable, got {:?}",
        missing_status.state
    );

    let healthy_temp = private_temp();
    let healthy = manager(&healthy_temp);
    let healthy_status = healthy.status().unwrap();
    assert!(matches!(healthy_status.state, SessionState::NoSession));
}

// ── Store tampering and permissions ─────────────────────────────────────────

/// Every mutation of the sealed store must fail authentication rather than
/// yielding plaintext, and the failure must not leak content.
#[test]
fn tampered_store_fails_authenticated_decryption() {
    for tamper in common::ALL_TAMPERS {
        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager.start(&auth_url()).unwrap();
        write_export(&start.cookie_export_path, &scoped_cookie_file());
        manager.complete(&start.request_id).unwrap();

        let store_path = find_store_file(temp.path()).expect("store file exists");
        let mut bytes = fs::read(&store_path).unwrap();

        match tamper {
            common::Tamper::Empty => bytes.clear(),
            common::Tamper::Garbage => bytes = b"garbage not even json".to_vec(),
            common::Tamper::Truncate => {
                bytes.truncate(bytes.len() / 2);
            }
            // The remaining variants all mutate bytes inside the serialized
            // envelope. Flipping a byte in the base64 ciphertext or nonce, or
            // in an AAD-bound field, must all fail the tag check.
            _ => {
                if let Some(last) = bytes.len().checked_sub(4) {
                    bytes[last] ^= 0x01;
                }
            }
        }
        fs::write(&store_path, &bytes).unwrap();

        let result = manager.load_jar();
        assert!(
            result.is_err(),
            "tampered store must not decrypt: {tamper:?}"
        );
        let rendered = format!("{:?}", result.err());
        common::assert_no_secrets(&rendered, &format!("tamper {tamper:?}"), &[]);
    }
}

/// Wrong permissions must fail closed and must NOT be silently repaired —
/// silent repair destroys the evidence that something tampered with the store.
#[cfg(unix)]
#[test]
fn unsafe_store_permissions_fail_closed_without_repair() {
    use std::os::unix::fs::PermissionsExt;

    for (mode, why) in common::UNSAFE_FILE_MODES {
        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager.start(&auth_url()).unwrap();
        write_export(&start.cookie_export_path, &scoped_cookie_file());
        manager.complete(&start.request_id).unwrap();

        let store_path = find_store_file(temp.path()).expect("store exists");
        fs::set_permissions(&store_path, fs::Permissions::from_mode(*mode)).unwrap();

        assert!(
            manager.load_jar().is_err(),
            "store at mode {mode:o} must not load ({why})"
        );

        let after = fs::metadata(&store_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            after, *mode,
            "permissions must not be silently repaired; that would erase tamper evidence"
        );
    }
}

/// The secret directory and file must be created with the right modes rather
/// than chmod-ed afterwards.
#[cfg(unix)]
#[test]
fn store_is_created_with_private_modes() {
    use std::os::unix::fs::PermissionsExt;

    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();
    write_export(&start.cookie_export_path, &scoped_cookie_file());
    manager.complete(&start.request_id).unwrap();

    let store_path = find_store_file(temp.path()).expect("store exists");
    let file_mode = fs::metadata(&store_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        file_mode,
        common::SAFE_FILE_MODE,
        "secret file must be 0600"
    );

    let dir_mode = fs::metadata(store_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, common::SAFE_DIR_MODE, "secret dir must be 0700");
}

/// Revocation must work. It is the user's only lever when something is wrong,
/// and deleting is safe by definition.
#[test]
fn clear_is_idempotent_and_removes_the_store() {
    let temp = private_temp();
    let manager = manager(&temp);
    let start = manager.start(&auth_url()).unwrap();
    write_export(&start.cookie_export_path, &scoped_cookie_file());
    manager.complete(&start.request_id).unwrap();
    assert!(find_store_file(temp.path()).is_some());

    manager.clear().expect("first clear succeeds");
    assert!(
        find_store_file(temp.path()).is_none(),
        "ciphertext must be gone after clear"
    );

    manager.clear().expect("clear is idempotent");
}

// ── Authentication URL scoping ──────────────────────────────────────────────

/// `start()` must not mint a request for a host outside the configured
/// institution, or over a scheme that would expose the session.
#[test]
fn out_of_scope_or_insecure_authentication_urls_are_refused() {
    let temp = private_temp();
    let manager = manager(&temp);

    for bad in [
        "http://proxy.example.edu/login",
        "https://evil.test/login",
        "https://proxy.example.edu.evil.test/login",
        "https://proxy.example.edu:8443/login",
        "https://user:pass@proxy.example.edu/login",
        "https://127.0.0.1/login",
    ] {
        let url = Url::parse(bad).expect("parses as a URL");
        assert!(
            manager.start(&url).is_err(),
            "authentication URL must be refused: {bad}"
        );
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Locate the encrypted store beneath the data dir without hard-coding the
/// implementation's directory hashing.
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
