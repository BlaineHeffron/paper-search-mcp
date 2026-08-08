pub mod retrieval;
mod secret;
pub mod store;

use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{aead::Generate, XNonce};
use chrono::{DateTime, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub use store::{KeyProtectionStatus, StoreError};

use self::{
    secret::SecretString,
    store::{
        atomic_replace_private, create_private_dir, read_private_bounded, validate_private_dir,
        CookieJar, KeyProvider, OsKeyringProvider, SessionStore, StoredCookie,
    },
};

const REQUEST_LIFETIME_SECONDS: i64 = 15 * 60;
const MAX_COOKIE_EXPORT_BYTES: u64 = 1024 * 1024;
const REQUEST_FILE: &str = "request.json";
const COOKIE_EXPORT_FILE: &str = "cookies.txt";

#[derive(Debug, Clone)]
pub struct InstitutionalSessionConfig {
    pub data_dir: PathBuf,
    pub institution_id: String,
    pub institution_name: String,
    pub allowed_hosts: Vec<String>,
    pub max_session_ttl_seconds: i64,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("institutional session configuration is invalid")]
    InvalidConfiguration,
    #[error("authentication request is invalid or expired")]
    InvalidRequest,
    #[error("cookie export is missing")]
    CookieExportMissing,
    #[error("cookie export has insecure permissions")]
    InsecureCookieExport,
    #[error("cookie export is invalid")]
    InvalidCookieExport,
    #[error("cookie export contains no usable cookies in the configured scope")]
    NoScopedCookies,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionStart {
    pub request_id: String,
    pub institution: String,
    pub authentication_url: String,
    pub cookie_export_path: String,
    pub request_expires_at: DateTime<Utc>,
    pub next_step: &'static str,
    pub security_note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Ready,
    PendingBrowserExport,
    NoSession,
    Expired,
    CorruptStore,
    InsecurePermissions,
    KeyringLocked,
    KeyringUnavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionStatus {
    pub state: SessionState,
    pub institution: String,
    pub protection: KeyProtectionStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub domains: Vec<String>,
    pub cookie_count: usize,
    pub pending_request_count: usize,
    pub plaintext_export_present: bool,
    pub plaintext_export_oldest_age_seconds: Option<i64>,
    pub operational_note: String,
}

#[derive(Serialize, Deserialize)]
struct AuthenticationRequest {
    version: u8,
    request_id: String,
    institution_id: String,
    authentication_url: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Clone)]
pub struct InstitutionalSessionManager {
    config: Arc<InstitutionalSessionConfig>,
    store: SessionStore,
    requests_root: PathBuf,
    lifecycle: Arc<Mutex<()>>,
}

impl InstitutionalSessionManager {
    pub fn new(config: InstitutionalSessionConfig) -> Result<Self, SessionError> {
        validate_config(&config)?;
        let keys: Arc<dyn KeyProvider> = Arc::new(OsKeyringProvider::new(
            &config.institution_id,
            &config.data_dir,
        ));
        Self::with_key_provider(config, keys)
    }

    pub fn with_key_provider(
        config: InstitutionalSessionConfig,
        keys: Arc<dyn KeyProvider>,
    ) -> Result<Self, SessionError> {
        validate_config(&config)?;
        let store = SessionStore::new(&config.data_dir, config.institution_id.clone(), keys)?;
        let requests_root = store.root().join("requests");
        create_private_dir(&requests_root)?;
        Ok(Self {
            config: Arc::new(config),
            store,
            requests_root,
            lifecycle: Arc::new(Mutex::new(())),
        })
    }

    pub fn start(&self, authentication_url: &Url) -> Result<SessionStart, SessionError> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| StoreError::Io)?;
        self.validate_authentication_url(authentication_url)?;
        self.reset_requests()?;
        let request_id = URL_SAFE_NO_PAD.encode(XNonce::generate());
        let request_dir = self.requests_root.join(&request_id);
        create_private_dir(&request_dir)?;
        let now = Utc::now().timestamp();
        let expires_at = now + REQUEST_LIFETIME_SECONDS;
        let request = AuthenticationRequest {
            version: 1,
            request_id: request_id.clone(),
            institution_id: self.config.institution_id.clone(),
            authentication_url: authentication_url.to_string(),
            created_at: now,
            expires_at,
        };
        let request_bytes =
            serde_json::to_vec(&request).map_err(|_| SessionError::InvalidRequest)?;
        atomic_replace_private(
            &request_dir,
            &request_dir.join(REQUEST_FILE),
            &request_bytes,
        )?;
        Ok(SessionStart {
            request_id,
            institution: self.config.institution_name.clone(),
            authentication_url: authentication_url.to_string(),
            cookie_export_path: request_dir
                .join(COOKIE_EXPORT_FILE)
                .to_string_lossy()
                .into_owned(),
            request_expires_at: DateTime::from_timestamp(expires_at, 0)
                .ok_or(SessionError::InvalidRequest)?,
            next_step: "Open authentication_url in a real browser, complete login/MFA, export only the institutional/proxy cookies in Netscape cookie-file format to cookie_export_path, set that file to mode 0600, then call complete_institutional_session with request_id.",
            security_note: "Never paste cookie values into chat or an MCP argument. The plaintext export is temporary and remains user-controlled until completion succeeds.",
        })
    }

    pub fn complete(&self, request_id: &str) -> Result<SessionStatus, SessionError> {
        validate_request_id(request_id)?;
        let _lifecycle = self.lifecycle.lock().map_err(|_| StoreError::Io)?;
        self.purge_expired_requests()?;
        validate_private_dir(&self.requests_root)?;
        let request_dir = self.requests_root.join(request_id);
        validate_private_dir(&request_dir).map_err(|_| SessionError::InvalidRequest)?;
        let request_path = request_dir.join(REQUEST_FILE);
        let request_bytes = read_private_bounded(&request_path, 64 * 1024)
            .map_err(|_| SessionError::InvalidRequest)?;
        let request: AuthenticationRequest =
            serde_json::from_slice(&request_bytes).map_err(|_| SessionError::InvalidRequest)?;
        let now = Utc::now().timestamp();
        if request.version != 1
            || request.request_id != request_id
            || request.institution_id != self.config.institution_id
            || request.expires_at <= now
        {
            return Err(SessionError::InvalidRequest);
        }
        let export_path = request_dir.join(COOKIE_EXPORT_FILE);
        let mut export = match read_private_bounded(&export_path, MAX_COOKIE_EXPORT_BYTES) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(StoreError::NotFound) => return Err(SessionError::CookieExportMissing),
            Err(StoreError::InsecurePermissions) => return Err(SessionError::InsecureCookieExport),
            Err(error) => return Err(error.into()),
        };
        let jar = parse_netscape_cookie_export(
            &export,
            &self.config.institution_id,
            &self.config.allowed_hosts,
            now,
            self.config.max_session_ttl_seconds,
        )?;
        self.store.save(&jar)?;
        export.as_mut_slice().fill(0);
        if fs::remove_file(&export_path).is_err() {
            let _ = self.store.clear();
            return Err(StoreError::Io.into());
        }
        fs::remove_file(request_path).map_err(|_| StoreError::Io)?;
        fs::remove_dir(request_dir).map_err(|_| StoreError::Io)?;
        self.status_unlocked()
    }

    pub fn status(&self) -> Result<SessionStatus, SessionError> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| StoreError::Io)?;
        self.purge_expired_requests()?;
        self.status_unlocked()
    }

    fn status_unlocked(&self) -> Result<SessionStatus, SessionError> {
        let protection = self.store.protection_status();
        if matches!(
            self.store.validate_root_permissions(),
            Err(StoreError::InsecurePermissions)
        ) {
            return Ok(empty_status(
                &self.config.institution_name,
                protection,
                SessionState::InsecurePermissions,
                0,
                false,
                None,
                "Stored session directory permissions are unsafe; loading is refused. Use clear_institutional_session to purge and recreate local state.",
            ));
        }
        let (pending_count, plaintext_export_present, plaintext_age) = self.pending_summary()?;
        if self.store.has_store() {
            return match self.store.load() {
                Ok(jar) => Ok(status_from_jar(
                    &self.config.institution_name,
                    protection,
                    &jar,
                    pending_count,
                    plaintext_export_present,
                    plaintext_age,
                )),
                Err(StoreError::Expired) => Ok(empty_status(
                    &self.config.institution_name,
                    protection,
                    SessionState::Expired,
                    pending_count,
                    plaintext_export_present,
                    plaintext_age,
                    "Stored session expired; clear it and authenticate again.",
                )),
                Err(StoreError::InsecurePermissions) => Ok(empty_status(
                    &self.config.institution_name,
                    protection,
                    SessionState::InsecurePermissions,
                    pending_count,
                    plaintext_export_present,
                    plaintext_age,
                    "Stored session permissions are unsafe; loading is refused.",
                )),
                Err(StoreError::KeyringLocked) => Ok(empty_status(
                    &self.config.institution_name,
                    protection,
                    SessionState::KeyringLocked,
                    pending_count,
                    plaintext_export_present,
                    plaintext_age,
                    "OS keyring is locked; unlock it locally and retry.",
                )),
                Err(StoreError::KeyringUnavailable | StoreError::KeyMissing) => Ok(empty_status(
                    &self.config.institution_name,
                    protection,
                    SessionState::KeyringUnavailable,
                    pending_count,
                    plaintext_export_present,
                    plaintext_age,
                    "OS keyring or session key is unavailable; plaintext fallback is disabled.",
                )),
                Err(_) => Ok(empty_status(
                    &self.config.institution_name,
                    protection,
                    SessionState::CorruptStore,
                    pending_count,
                    plaintext_export_present,
                    plaintext_age,
                    "Stored session failed authenticated decryption; clear it and authenticate again.",
                )),
            };
        }
        if pending_count > 0 {
            return Ok(empty_status(
                &self.config.institution_name,
                protection,
                SessionState::PendingBrowserExport,
                pending_count,
                plaintext_export_present,
                plaintext_age,
                "Authentication request prepared; browser login/export and completion are still required.",
            ));
        }
        let (state, note) = match protection {
            KeyProtectionStatus::OsKeyring => (
                SessionState::NoSession,
                "No stored institutional session. OS keyring protection is available.",
            ),
            KeyProtectionStatus::OsKeyringLocked => (
                SessionState::KeyringLocked,
                "OS keyring is locked; no plaintext fallback is allowed.",
            ),
            KeyProtectionStatus::OsKeyringUnavailable => (
                SessionState::KeyringUnavailable,
                "OS keyring is unavailable; no plaintext fallback is allowed.",
            ),
        };
        Ok(empty_status(
            &self.config.institution_name,
            protection,
            state,
            pending_count,
            plaintext_export_present,
            plaintext_age,
            note,
        ))
    }

    pub fn load_jar(&self) -> Result<CookieJar, SessionError> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| StoreError::Io)?;
        Ok(self.store.load()?)
    }

    pub fn clear(&self) -> Result<SessionStatus, SessionError> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| StoreError::Io)?;
        let key_deleted = self.store.purge_and_recreate()?;
        create_private_dir(&self.requests_root)?;
        let protection = self.store.protection_status();
        let note = match key_deleted {
            true => {
                "Local ciphertext, staged exports, and the OS-keyring key were deleted. Institution-side logout is still separate."
            }
            false => {
                "Local ciphertext and staged exports were deleted. The OS-keyring key could not be deleted; the key alone cannot reconstruct the removed session. Institution-side logout is still separate."
            }
        };
        Ok(empty_status(
            &self.config.institution_name,
            protection,
            SessionState::NoSession,
            0,
            false,
            None,
            note,
        ))
    }

    fn pending_summary(&self) -> Result<(usize, bool, Option<i64>), SessionError> {
        validate_private_dir(&self.requests_root)?;
        let now = Utc::now().timestamp();
        let mut pending_count = 0;
        let mut plaintext_export_present = false;
        let mut oldest_plaintext_created_at: Option<i64> = None;
        for entry in fs::read_dir(&self.requests_root).map_err(|_| StoreError::Io)? {
            let entry = entry.map_err(|_| StoreError::Io)?;
            let file_type = entry.file_type().map_err(|_| StoreError::Io)?;
            if !file_type.is_dir() {
                continue;
            }
            let has_plaintext = fs::symlink_metadata(entry.path().join(COOKIE_EXPORT_FILE)).is_ok();
            if has_plaintext {
                plaintext_export_present = true;
            }
            let request_path = entry.path().join(REQUEST_FILE);
            let Ok(bytes) = read_private_bounded(&request_path, 64 * 1024) else {
                continue;
            };
            let Ok(request) = serde_json::from_slice::<AuthenticationRequest>(&bytes) else {
                continue;
            };
            if request.institution_id == self.config.institution_id && request.expires_at > now {
                pending_count += 1;
                if has_plaintext {
                    oldest_plaintext_created_at = Some(
                        oldest_plaintext_created_at
                            .map_or(request.created_at, |oldest| oldest.min(request.created_at)),
                    );
                }
            }
        }
        Ok((
            pending_count,
            plaintext_export_present,
            oldest_plaintext_created_at.map(|created| now.saturating_sub(created)),
        ))
    }

    fn reset_requests(&self) -> Result<(), SessionError> {
        if self.requests_root.exists() {
            fs::remove_dir_all(&self.requests_root).map_err(|_| StoreError::Io)?;
        }
        create_private_dir(&self.requests_root)?;
        Ok(())
    }

    fn purge_expired_requests(&self) -> Result<(), SessionError> {
        validate_private_dir(&self.requests_root)?;
        let now = Utc::now().timestamp();
        for entry in fs::read_dir(&self.requests_root).map_err(|_| StoreError::Io)? {
            let entry = entry.map_err(|_| StoreError::Io)?;
            if !entry.file_type().map_err(|_| StoreError::Io)?.is_dir() {
                continue;
            }
            let request_path = entry.path().join(REQUEST_FILE);
            let expired = read_private_bounded(&request_path, 64 * 1024)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<AuthenticationRequest>(&bytes).ok())
                .is_none_or(|request| {
                    request.institution_id != self.config.institution_id
                        || request.expires_at <= now
                });
            if expired {
                fs::remove_dir_all(entry.path()).map_err(|_| StoreError::Io)?;
            }
        }
        Ok(())
    }

    fn validate_authentication_url(&self, url: &Url) -> Result<(), SessionError> {
        if url.scheme() != "https"
            || url.port_or_known_default() != Some(443)
            || url.username() != ""
            || url.password().is_some()
        {
            return Err(SessionError::InvalidConfiguration);
        }
        let host = url
            .host_str()
            .map(str::to_ascii_lowercase)
            .ok_or(SessionError::InvalidConfiguration)?;
        if !host_in_scope(&host, &self.config.allowed_hosts) {
            return Err(SessionError::InvalidConfiguration);
        }
        Ok(())
    }
}

fn validate_config(config: &InstitutionalSessionConfig) -> Result<(), SessionError> {
    if config.institution_id.trim().is_empty()
        || config.institution_name.trim().is_empty()
        || config.allowed_hosts.is_empty()
        || !(60..=86_400).contains(&config.max_session_ttl_seconds)
    {
        return Err(SessionError::InvalidConfiguration);
    }
    for host in &config.allowed_hosts {
        if normalize_host(host).as_deref() != Some(host.as_str()) {
            return Err(SessionError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), SessionError> {
    if request_id.len() != 32
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(SessionError::InvalidRequest);
    }
    Ok(())
}

fn parse_netscape_cookie_export(
    bytes: &[u8],
    institution_id: &str,
    allowed_hosts: &[String],
    now: i64,
    max_ttl: i64,
) -> Result<CookieJar, SessionError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SessionError::InvalidCookieExport)?;
    let ceiling = now
        .checked_add(max_ttl)
        .ok_or(SessionError::InvalidCookieExport)?;
    let mut cookies = Vec::new();
    for raw_line in text.lines() {
        let mut line = raw_line.trim_end_matches('\r');
        let http_only = line.starts_with("#HttpOnly_");
        if http_only {
            line = line
                .strip_prefix("#HttpOnly_")
                .ok_or(SessionError::InvalidCookieExport)?;
        } else if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.splitn(7, '\t').collect();
        if fields.len() != 7 {
            return Err(SessionError::InvalidCookieExport);
        }
        let domain = normalize_host(fields[0]).ok_or(SessionError::InvalidCookieExport)?;
        if !host_in_scope(&domain, allowed_hosts) {
            continue;
        }
        if !fields[1].eq_ignore_ascii_case("TRUE") && !fields[1].eq_ignore_ascii_case("FALSE") {
            return Err(SessionError::InvalidCookieExport);
        }
        if !fields[3].eq_ignore_ascii_case("TRUE") {
            continue;
        }
        let path = fields[2];
        if !valid_cookie_path(path) {
            return Err(SessionError::InvalidCookieExport);
        }
        let raw_expiry = fields[4]
            .parse::<i64>()
            .map_err(|_| SessionError::InvalidCookieExport)?;
        let expires_at = if raw_expiry <= 0 {
            ceiling
        } else {
            raw_expiry.min(ceiling)
        };
        if expires_at <= now {
            continue;
        }
        if !valid_cookie_name(fields[5]) || !valid_cookie_value(fields[6]) {
            return Err(SessionError::InvalidCookieExport);
        }
        cookies.push(StoredCookie {
            domain,
            include_subdomains: fields[1].eq_ignore_ascii_case("TRUE"),
            path: path.to_string(),
            secure: true,
            http_only,
            expires_at,
            name: fields[5].to_string(),
            value: SecretString::new(fields[6].to_string()),
        });
    }
    if cookies.is_empty() {
        return Err(SessionError::NoScopedCookies);
    }
    let expires_at = cookies
        .iter()
        .map(|cookie| cookie.expires_at)
        .max()
        .ok_or(SessionError::NoScopedCookies)?;
    Ok(CookieJar {
        institution_id: institution_id.to_string(),
        created_at: now,
        expires_at,
        cookies,
    })
}

fn normalize_host(input: &str) -> Option<String> {
    let host = input.trim().trim_start_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.parse::<std::net::IpAddr>().is_ok()
        || psl::domain(host.as_bytes()).is_none()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        None
    } else {
        Some(host)
    }
}

pub(crate) fn host_in_scope(host: &str, allowed_hosts: &[String]) -> bool {
    allowed_hosts
        .iter()
        .any(|allowed| host == allowed || host.ends_with(&format!(".{allowed}")))
}

fn valid_cookie_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 2048 && !path.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b';' | b',' | b'=')
        })
}

fn valid_cookie_value(value: &str) -> bool {
    value.len() <= 16 * 1024
        && !value.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace() || matches!(byte, b';' | b',')
        })
}

fn status_from_jar(
    institution: &str,
    protection: KeyProtectionStatus,
    jar: &CookieJar,
    pending_request_count: usize,
    plaintext_export_present: bool,
    plaintext_export_oldest_age_seconds: Option<i64>,
) -> SessionStatus {
    SessionStatus {
        state: SessionState::Ready,
        institution: institution.to_string(),
        protection,
        expires_at: DateTime::from_timestamp(jar.expires_at(), 0),
        domains: jar.domains(),
        cookie_count: jar.cookie_count(),
        pending_request_count,
        plaintext_export_present,
        plaintext_export_oldest_age_seconds,
        operational_note: "Ready for one-at-a-time institutional fallback retrieval. Browser need not remain open. Access remains subject to institutional and publisher terms.".to_string(),
    }
}

fn empty_status(
    institution: &str,
    protection: KeyProtectionStatus,
    state: SessionState,
    pending_request_count: usize,
    plaintext_export_present: bool,
    plaintext_export_oldest_age_seconds: Option<i64>,
    note: &str,
) -> SessionStatus {
    SessionStatus {
        state,
        institution: institution.to_string(),
        protection,
        expires_at: None,
        domains: Vec::new(),
        cookie_count: 0,
        pending_request_count,
        plaintext_export_present,
        plaintext_export_oldest_age_seconds,
        operational_note: note.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use tempfile::TempDir;

    use super::{store::test_support::MemoryKeyProvider, *};

    fn private_temp() -> TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    fn manager(temp: &TempDir) -> InstitutionalSessionManager {
        InstitutionalSessionManager::with_key_provider(
            InstitutionalSessionConfig {
                data_dir: temp.path().to_path_buf(),
                institution_id: "example-university".to_string(),
                institution_name: "Example University".to_string(),
                allowed_hosts: vec!["proxy.example.edu".to_string()],
                max_session_ttl_seconds: 12 * 3600,
            },
            Arc::new(MemoryKeyProvider::available()),
        )
        .unwrap()
    }

    #[test]
    fn complete_browser_export_lifecycle() {
        let temp = private_temp();
        let manager = manager(&temp);
        let auth = Url::parse(
            "https://proxy.example.edu/login?url=https%3A%2F%2Fpublisher.example%2Fpaper.pdf",
        )
        .unwrap();
        let start = manager.start(&auth).unwrap();
        let cookie = format!(
            "# Netscape HTTP Cookie File\n.proxy.example.edu\tTRUE\t/\tTRUE\t{}\tsession\tsecret-cookie-value\n",
            Utc::now().timestamp() + 86_400
        );
        fs::write(&start.cookie_export_path, cookie).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&start.cookie_export_path, fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let status = manager.complete(&start.request_id).unwrap();
        assert!(matches!(status.state, SessionState::Ready));
        assert!(!status.plaintext_export_present);
        assert_eq!(status.pending_request_count, 0);
        assert!(!std::path::Path::new(&start.cookie_export_path).exists());
        assert_eq!(manager.load_jar().unwrap().cookie_count(), 1);
        let cleared = manager.clear().unwrap();
        assert!(matches!(cleared.state, SessionState::NoSession));
    }

    #[cfg(unix)]
    #[test]
    fn insecure_plaintext_export_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager
            .start(&Url::parse("https://proxy.example.edu/login").unwrap())
            .unwrap();
        fs::write(&start.cookie_export_path, b"cookie").unwrap();
        fs::set_permissions(&start.cookie_export_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            manager.complete(&start.request_id),
            Err(SessionError::InsecureCookieExport)
        ));
    }

    #[test]
    fn request_id_traversal_is_rejected() {
        let temp = private_temp();
        let manager = manager(&temp);
        assert!(matches!(
            manager.complete("../../cookies"),
            Err(SessionError::InvalidRequest)
        ));
    }

    #[test]
    fn cookie_scope_and_expiry_are_enforced() {
        let now = Utc::now().timestamp();
        let export = format!(
            ".evil.example\tTRUE\t/\tTRUE\t{}\tbad\tbad-value\n.proxy.example.edu\tTRUE\t/\tTRUE\t0\tgood\tgood-value\n",
            now + 3600
        );
        let jar = parse_netscape_cookie_export(
            export.as_bytes(),
            "example",
            &["proxy.example.edu".to_string()],
            now,
            3600,
        )
        .unwrap();
        assert_eq!(jar.cookie_count(), 1);
        assert_eq!(jar.expires_at(), now + 3600);
        assert!(!format!("{jar:?}").contains("good-value"));
    }

    #[cfg(unix)]
    #[test]
    fn status_detects_staged_plaintext_and_clear_repairs_drift() {
        use std::os::unix::fs::PermissionsExt;

        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager
            .start(&Url::parse("https://proxy.example.edu/login").unwrap())
            .unwrap();
        fs::write(&start.cookie_export_path, b"plaintext-cookie-export").unwrap();
        fs::set_permissions(&start.cookie_export_path, fs::Permissions::from_mode(0o600)).unwrap();
        let status = manager.status().unwrap();
        assert!(status.plaintext_export_present);
        assert_eq!(status.pending_request_count, 1);

        fs::set_permissions(manager.store.root(), fs::Permissions::from_mode(0o755)).unwrap();
        let insecure = manager.status().unwrap();
        assert!(matches!(insecure.state, SessionState::InsecurePermissions));
        let cleared = manager.clear().unwrap();
        assert!(matches!(cleared.state, SessionState::NoSession));
        assert!(!PathBuf::from(start.cookie_export_path).exists());
        assert_eq!(
            fs::metadata(manager.store.root())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn a_new_start_supersedes_and_purges_the_previous_request() {
        let temp = private_temp();
        let manager = manager(&temp);
        let auth = Url::parse("https://proxy.example.edu/login").unwrap();
        let first = manager.start(&auth).unwrap();
        fs::write(&first.cookie_export_path, b"temporary-export").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&first.cookie_export_path, fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let second = manager.start(&auth).unwrap();
        assert_ne!(first.request_id, second.request_id);
        assert!(!PathBuf::from(first.cookie_export_path).exists());
        let status = manager.status().unwrap();
        assert_eq!(status.pending_request_count, 1);
        assert!(!status.plaintext_export_present);
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_cookie_export_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let temp = private_temp();
        let manager = manager(&temp);
        let start = manager
            .start(&Url::parse("https://proxy.example.edu/login").unwrap())
            .unwrap();
        let outside = temp.path().join("outside-cookie-file");
        fs::write(&outside, b"secret-cookie-material").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&outside, &start.cookie_export_path).unwrap();
        assert!(matches!(
            manager.complete(&start.request_id),
            Err(SessionError::InsecureCookieExport)
        ));
        assert_eq!(fs::read(&outside).unwrap(), b"secret-cookie-material");
    }
}
