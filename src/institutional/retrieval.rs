use std::{
    collections::VecDeque,
    fs::{self, File},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use reqwest::{header, redirect::Policy, StatusCode, Url};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::sync::Mutex;

use super::{host_in_scope, secret::SecretString, store::CookieJar};

#[derive(Debug, Clone)]
pub struct RetrievalConfig {
    pub download_root: PathBuf,
    pub allowed_hosts: Vec<String>,
    pub max_response_bytes: usize,
    pub max_redirects: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub minimum_interval: Duration,
    pub hourly_limit: usize,
}

impl RetrievalConfig {
    pub fn validate(&self) -> Result<(), RetrievalError> {
        if self.allowed_hosts.is_empty()
            || self.max_response_bytes < 1024
            || self.max_response_bytes > 100 * 1024 * 1024
            || self.max_redirects > 5
            || self.max_redirects == 0
            || self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(30)
            || self.request_timeout < self.connect_timeout
            || self.request_timeout > Duration::from_secs(120)
            || self.minimum_interval < Duration::from_secs(1)
            || self.hourly_limit == 0
            || self.hourly_limit > 60
        {
            return Err(RetrievalError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum RetrievalError {
    #[error("institutional retrieval configuration is invalid")]
    InvalidConfiguration,
    #[error("another institutional retrieval is already in progress")]
    Busy,
    #[error("institutional retrieval rate limit reached")]
    RateLimited,
    #[error("remote target is not an allowed HTTPS:443 institutional host")]
    UnsafeTarget,
    #[error("remote target resolved to a prohibited network address")]
    ProhibitedAddress,
    #[error("remote target could not be resolved safely")]
    ResolutionFailed,
    #[error("institutional request failed")]
    RequestFailed,
    #[error("institutional request timed out")]
    Timeout,
    #[error("institutional redirect was missing or invalid")]
    InvalidRedirect,
    #[error("institutional redirect limit exceeded")]
    RedirectLimit,
    #[error("institutional session appears expired or unauthorized")]
    Unauthorized,
    #[error("institutional session was rejected or redirected to a login page")]
    SessionExpiredOrRejected,
    #[error("response exceeded the configured size limit")]
    ResponseTooLarge,
    #[error("response was not a validated PDF")]
    NotPdf,
    #[error("destination filename is unsafe")]
    UnsafeFilename,
    #[error("download destination is unsafe or has insecure permissions")]
    UnsafeDestination,
    #[error("download destination already exists")]
    DestinationExists,
    #[error("download persistence failed")]
    PersistenceFailed,
}

pub struct TransportRequest<'a> {
    pub url: &'a Url,
    pub pinned_ip: IpAddr,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    cookie_header: Option<&'a SecretString>,
}

pub struct TransportResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait RetrievalTransport: Send + Sync {
    async fn get(&self, request: TransportRequest<'_>)
        -> Result<TransportResponse, RetrievalError>;
}

#[async_trait]
pub trait HostResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, RetrievalError>;
}

#[derive(Default)]
pub struct SystemResolver;

#[async_trait]
impl HostResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, RetrievalError> {
        let addresses = tokio::net::lookup_host((host, 443))
            .await
            .map_err(|_| RetrievalError::ResolutionFailed)?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(RetrievalError::ResolutionFailed);
        }
        Ok(addresses)
    }
}

#[derive(Default)]
pub struct ReqwestTransport;

#[async_trait]
impl RetrievalTransport for ReqwestTransport {
    async fn get(
        &self,
        request: TransportRequest<'_>,
    ) -> Result<TransportResponse, RetrievalError> {
        let host = request.url.host_str().ok_or(RetrievalError::UnsafeTarget)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .https_only(true)
            .no_proxy()
            .connect_timeout(request.connect_timeout)
            .timeout(request.request_timeout)
            .resolve(host, SocketAddr::new(request.pinned_ip, 443))
            .build()
            .map_err(|_| RetrievalError::RequestFailed)?;
        let mut builder = client
            .get(request.url.clone())
            .header(
                header::ACCEPT,
                "application/pdf, application/octet-stream;q=0.5",
            )
            .header(
                header::USER_AGENT,
                "paper-search/0.1 institutional-single-paper",
            );
        if let Some(cookie) = request.cookie_header {
            let value = header::HeaderValue::from_str(cookie.expose())
                .map_err(|_| RetrievalError::RequestFailed)?;
            builder = builder.header(header::COOKIE, value);
        }
        let response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                RetrievalError::Timeout
            } else {
                RetrievalError::RequestFailed
            }
        })?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        if response
            .content_length()
            .is_some_and(|length| length > request.max_response_bytes as u64)
        {
            return Err(RetrievalError::ResponseTooLarge);
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| RetrievalError::RequestFailed)?;
            if body.len().saturating_add(chunk.len()) > request.max_response_bytes {
                return Err(RetrievalError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(TransportResponse {
            status,
            content_type,
            location,
            body,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RedirectProvenance {
    pub url: String,
    pub status: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetrievedPaper {
    pub path: String,
    pub provenance_path: String,
    pub filename: String,
    pub size_bytes: usize,
    pub sha256: String,
    pub source_url: String,
    pub doi: Option<String>,
    pub retrieved_at: DateTime<Utc>,
    pub redirects: Vec<RedirectProvenance>,
    pub access_type: &'static str,
    pub terms_note: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct PersistedProvenance {
    schema_version: u8,
    filename: String,
    size_bytes: usize,
    sha256: String,
    source_url: String,
    doi: Option<String>,
    retrieved_at: DateTime<Utc>,
    redirects: Vec<RedirectProvenance>,
    access_type: &'static str,
    terms_note: &'static str,
}

#[derive(Default)]
struct RateState {
    last_attempt: Option<Instant>,
    hourly_attempts: VecDeque<Instant>,
}

#[derive(Clone)]
pub struct InstitutionalRetriever {
    config: Arc<RetrievalConfig>,
    transport: Arc<dyn RetrievalTransport>,
    resolver: Arc<dyn HostResolver>,
    active: Arc<Mutex<()>>,
    rate: Arc<Mutex<RateState>>,
}

impl InstitutionalRetriever {
    pub fn new(config: RetrievalConfig) -> Result<Self, RetrievalError> {
        Self::with_components(config, Arc::new(ReqwestTransport), Arc::new(SystemResolver))
    }

    pub fn with_components(
        config: RetrievalConfig,
        transport: Arc<dyn RetrievalTransport>,
        resolver: Arc<dyn HostResolver>,
    ) -> Result<Self, RetrievalError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            transport,
            resolver,
            active: Arc::new(Mutex::new(())),
            rate: Arc::new(Mutex::new(RateState::default())),
        })
    }

    pub async fn retrieve(
        &self,
        jar: &CookieJar,
        institutional_url: Url,
        source_url: &Url,
        doi: Option<&str>,
        preferred_filename: Option<&str>,
    ) -> Result<RetrievedPaper, RetrievalError> {
        let _active = self.active.try_lock().map_err(|_| RetrievalError::Busy)?;
        self.record_rate_attempt().await?;
        self.validate_public_source(source_url).await?;
        let mut current = institutional_url;
        let mut chain = Vec::new();
        for redirect_count in 0..=self.config.max_redirects {
            let (host, ip) = self.validate_and_resolve(&current).await?;
            let path = if current.path().is_empty() {
                "/"
            } else {
                current.path()
            };
            let cookie = jar.cookie_header(&host, path, Utc::now().timestamp());
            let session_cookie_attached = cookie.is_some();
            let response = tokio::time::timeout(
                self.config.request_timeout,
                self.transport.get(TransportRequest {
                    url: &current,
                    pinned_ip: ip,
                    connect_timeout: self.config.connect_timeout,
                    request_timeout: self.config.request_timeout,
                    max_response_bytes: self.config.max_response_bytes,
                    cookie_header: cookie.as_ref(),
                }),
            )
            .await
            .map_err(|_| RetrievalError::Timeout)??;
            if response.body.len() > self.config.max_response_bytes {
                return Err(RetrievalError::ResponseTooLarge);
            }
            chain.push(RedirectProvenance {
                url: redact_url(&current),
                status: response.status,
            });
            let status =
                StatusCode::from_u16(response.status).map_err(|_| RetrievalError::RequestFailed)?;
            if status.is_redirection() {
                if redirect_count == self.config.max_redirects {
                    return Err(RetrievalError::RedirectLimit);
                }
                let location = response.location.ok_or(RetrievalError::InvalidRedirect)?;
                current = current
                    .join(&location)
                    .map_err(|_| RetrievalError::InvalidRedirect)?;
                continue;
            }
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                return Err(RetrievalError::Unauthorized);
            }
            if !status.is_success() {
                return Err(RetrievalError::RequestFailed);
            }
            validate_pdf(
                &response.content_type,
                &response.body,
                session_cookie_attached,
            )?;
            return persist_pdf(
                &self.config.download_root,
                response.body,
                source_url,
                doi,
                preferred_filename,
                chain,
            );
        }
        Err(RetrievalError::RedirectLimit)
    }

    async fn record_rate_attempt(&self) -> Result<(), RetrievalError> {
        let now = Instant::now();
        let mut state = self.rate.lock().await;
        if state
            .last_attempt
            .is_some_and(|last| now.duration_since(last) < self.config.minimum_interval)
        {
            return Err(RetrievalError::RateLimited);
        }
        while state
            .hourly_attempts
            .front()
            .is_some_and(|attempt| now.duration_since(*attempt) >= Duration::from_secs(3600))
        {
            state.hourly_attempts.pop_front();
        }
        if state.hourly_attempts.len() >= self.config.hourly_limit {
            return Err(RetrievalError::RateLimited);
        }
        state.last_attempt = Some(now);
        state.hourly_attempts.push_back(now);
        Ok(())
    }

    async fn validate_and_resolve(&self, url: &Url) -> Result<(String, IpAddr), RetrievalError> {
        let host = validated_https_host(url)?;
        if host.parse::<IpAddr>().is_ok() || !host_in_scope(&host, &self.config.allowed_hosts) {
            return Err(RetrievalError::UnsafeTarget);
        }
        let addresses = self.resolve_public_addresses(&host).await?;
        Ok((host, addresses[0]))
    }

    async fn validate_public_source(&self, url: &Url) -> Result<(), RetrievalError> {
        let host = validated_https_host(url)?;
        if host.parse::<IpAddr>().is_ok() {
            return Err(RetrievalError::UnsafeTarget);
        }
        self.resolve_public_addresses(&host).await?;
        Ok(())
    }

    async fn resolve_public_addresses(&self, host: &str) -> Result<Vec<IpAddr>, RetrievalError> {
        let addresses = self.resolver.resolve(&host).await?;
        if addresses.is_empty() {
            return Err(RetrievalError::ResolutionFailed);
        }
        if addresses.iter().any(|address| is_prohibited_ip(*address)) {
            return Err(RetrievalError::ProhibitedAddress);
        }
        Ok(addresses)
    }
}

fn validated_https_host(url: &Url) -> Result<String, RetrievalError> {
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || url.username() != ""
        || url.password().is_some()
    {
        return Err(RetrievalError::UnsafeTarget);
    }
    url.host_str()
        .map(str::to_ascii_lowercase)
        .ok_or(RetrievalError::UnsafeTarget)
}

pub fn is_prohibited_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_prohibited_v4(address),
        IpAddr::V6(address) => is_prohibited_v6(address),
    }
}

fn is_prohibited_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_prohibited_v6(address: Ipv6Addr) -> bool {
    if let Some(v4) = address.to_ipv4_mapped() {
        return is_prohibited_v4(v4);
    }
    let segments = address.segments();
    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return is_prohibited_v4(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ));
    }
    if segments == [0; 8]
        || address == Ipv6Addr::LOCALHOST
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xff00 == 0xff00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0])
    {
        return true;
    }
    // RFC 6052 well-known NAT64 prefix 64:ff9b::/96.
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return is_prohibited_v4(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ));
    }
    // RFC 3056 6to4 embeds an IPv4 address after 2002::/16.
    if segments[0] == 0x2002 {
        return is_prohibited_v4(Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        ));
    }
    false
}

fn validate_pdf(
    content_type: &Option<String>,
    body: &[u8],
    session_cookie_attached: bool,
) -> Result<(), RetrievalError> {
    let media_type = content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    if !matches!(
        media_type.as_deref(),
        Some("application/pdf" | "application/octet-stream")
    ) || !body.starts_with(b"%PDF-")
    {
        let first_non_whitespace = body
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace());
        if session_cookie_attached
            && (media_type.as_deref() == Some("text/html") || first_non_whitespace == Some(b'<'))
        {
            return Err(RetrievalError::SessionExpiredOrRejected);
        }
        return Err(RetrievalError::NotPdf);
    }
    Ok(())
}

fn persist_pdf(
    root: &Path,
    body: Vec<u8>,
    source_url: &Url,
    doi: Option<&str>,
    preferred_filename: Option<&str>,
    redirects: Vec<RedirectProvenance>,
) -> Result<RetrievedPaper, RetrievalError> {
    create_private_download_root(root)?;
    reject_symlink_components(root)?;
    let canonical_root = root
        .canonicalize()
        .map_err(|_| RetrievalError::UnsafeDestination)?;
    reject_symlink_components(&canonical_root)?;
    let sha256 = format!("{:x}", Sha256::digest(&body));
    let filename = safe_filename(preferred_filename, doi, &sha256)?;
    let destination = canonical_root.join(&filename);
    if destination.parent() != Some(canonical_root.as_path()) {
        return Err(RetrievalError::UnsafeDestination);
    }
    let provenance_destination = canonical_root.join(format!("{filename}.provenance.json"));
    if destination.exists() || provenance_destination.exists() {
        return Err(RetrievalError::DestinationExists);
    }
    let retrieved_at = Utc::now();
    let normalized_doi = doi.map(normalize_doi).transpose()?;
    let persisted = PersistedProvenance {
        schema_version: 1,
        filename: filename.clone(),
        size_bytes: body.len(),
        sha256: sha256.clone(),
        source_url: redact_url(source_url),
        doi: normalized_doi.clone(),
        retrieved_at,
        redirects: redirects.clone(),
        access_type: "institutional_authenticated_fallback",
        terms_note: "Retrieved as one explicitly requested paper. Use only within institutional and publisher terms; no DRM, CAPTCHA, MFA, or access-control bypass was attempted.",
    };
    let provenance =
        serde_json::to_vec_pretty(&persisted).map_err(|_| RetrievalError::PersistenceFailed)?;
    persist_noclobber(&canonical_root, &destination, &body)?;
    if let Err(error) = persist_noclobber(&canonical_root, &provenance_destination, &provenance) {
        let _ = fs::remove_file(&destination);
        return Err(error);
    }
    sync_directory(&canonical_root)?;
    Ok(RetrievedPaper {
        path: destination.to_string_lossy().into_owned(),
        provenance_path: provenance_destination.to_string_lossy().into_owned(),
        filename,
        size_bytes: body.len(),
        sha256,
        source_url: redact_url(source_url),
        doi: normalized_doi,
        retrieved_at,
        redirects,
        access_type: "institutional_authenticated_fallback",
        terms_note: "Retrieved as one explicitly requested paper. Use only within institutional and publisher terms; no DRM, CAPTCHA, MFA, or access-control bypass was attempted.",
    })
}

fn safe_filename(
    preferred: Option<&str>,
    doi: Option<&str>,
    sha256: &str,
) -> Result<String, RetrievalError> {
    let candidate = if let Some(preferred) = preferred {
        if preferred.is_empty()
            || preferred.len() > 120
            || preferred.starts_with('.')
            || preferred.contains(['/', '\\', '\0'])
            || preferred.chars().any(char::is_control)
            || Path::new(preferred)
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(RetrievalError::UnsafeFilename);
        }
        preferred.to_string()
    } else if let Some(doi) = doi {
        format!("{}.pdf", sanitize_component(&normalize_doi(doi)?))
    } else {
        format!("paper-{}.pdf", &sha256[..16])
    };
    let mut sanitized = sanitize_component(&candidate);
    if sanitized.is_empty() || sanitized.starts_with('.') {
        return Err(RetrievalError::UnsafeFilename);
    }
    if !sanitized.to_ascii_lowercase().ends_with(".pdf") {
        sanitized.push_str(".pdf");
    }
    if sanitized.len() > 128 {
        return Err(RetrievalError::UnsafeFilename);
    }
    Ok(sanitized)
}

fn sanitize_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_underscore = false;
    for character in value.chars() {
        let safe = character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.');
        let next = if safe { character } else { '_' };
        if next == '_' && previous_underscore {
            continue;
        }
        previous_underscore = next == '_';
        output.push(next);
    }
    output.trim_matches('_').to_string()
}

fn normalize_doi(value: &str) -> Result<String, RetrievalError> {
    let normalized = value
        .trim()
        .strip_prefix("doi:")
        .unwrap_or(value.trim())
        .trim_start_matches("https://doi.org/")
        .to_string();
    if normalized.is_empty()
        || normalized.len() > 255
        || !normalized.contains('/')
        || normalized.chars().any(char::is_control)
    {
        return Err(RetrievalError::UnsafeFilename);
    }
    Ok(normalized)
}

fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();
    redacted.set_query(None);
    redacted.set_fragment(None);
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.to_string()
}

fn create_private_download_root(root: &Path) -> Result<(), RetrievalError> {
    if !root.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(root)
                .map_err(|_| RetrievalError::PersistenceFailed)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(root).map_err(|_| RetrievalError::PersistenceFailed)?;
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| RetrievalError::UnsafeDestination)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RetrievalError::UnsafeDestination);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(RetrievalError::UnsafeDestination);
        }
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), RetrievalError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| RetrievalError::UnsafeDestination)?;
        if metadata.file_type().is_symlink() {
            return Err(RetrievalError::UnsafeDestination);
        }
    }
    Ok(())
}

fn persist_noclobber(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), RetrievalError> {
    let mut temporary =
        NamedTempFile::new_in(directory).map_err(|_| RetrievalError::PersistenceFailed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if temporary
            .as_file()
            .metadata()
            .map_err(|_| RetrievalError::PersistenceFailed)?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(RetrievalError::UnsafeDestination);
        }
    }
    temporary
        .write_all(bytes)
        .map_err(|_| RetrievalError::PersistenceFailed)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| RetrievalError::PersistenceFailed)?;
    temporary.persist_noclobber(destination).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            RetrievalError::DestinationExists
        } else {
            RetrievalError::PersistenceFailed
        }
    })?;
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), RetrievalError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| RetrievalError::PersistenceFailed)
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex as StdMutex};

    use super::*;
    use crate::institutional::store::{
        test_support::MemoryKeyProvider, SessionStore, StoredCookie,
    };

    struct MockResolver {
        addresses: Vec<IpAddr>,
    }

    #[async_trait]
    impl HostResolver for MockResolver {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, RetrievalError> {
            Ok(self.addresses.clone())
        }
    }

    struct MockTransport {
        responses: StdMutex<VecDeque<TransportResponse>>,
    }

    #[async_trait]
    impl RetrievalTransport for MockTransport {
        async fn get(
            &self,
            _request: TransportRequest<'_>,
        ) -> Result<TransportResponse, RetrievalError> {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(RetrievalError::RequestFailed)
        }
    }

    fn private_temp() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    fn test_jar() -> CookieJar {
        let now = Utc::now().timestamp();
        CookieJar {
            institution_id: "example".to_string(),
            created_at: now,
            expires_at: now + 3600,
            cookies: vec![StoredCookie {
                domain: "proxy.example.edu".to_string(),
                include_subdomains: true,
                path: "/".to_string(),
                secure: true,
                http_only: true,
                expires_at: now + 3600,
                name: "session".to_string(),
                value: SecretString::new("never-render-me".to_string()),
            }],
        }
    }

    fn retriever(root: PathBuf, responses: Vec<TransportResponse>) -> InstitutionalRetriever {
        InstitutionalRetriever::with_components(
            RetrievalConfig {
                download_root: root,
                allowed_hosts: vec!["proxy.example.edu".to_string()],
                max_response_bytes: 1024 * 1024,
                max_redirects: 2,
                connect_timeout: Duration::from_secs(1),
                request_timeout: Duration::from_secs(5),
                minimum_interval: Duration::from_secs(1),
                hourly_limit: 10,
            },
            Arc::new(MockTransport {
                responses: StdMutex::new(responses.into()),
            }),
            Arc::new(MockResolver {
                addresses: vec!["93.184.216.34".parse().unwrap()],
            }),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn mock_redirect_retrieval_persists_valid_pdf_and_redacted_provenance() {
        let temp = private_temp();
        let retriever = retriever(
            temp.path().join("downloads"),
            vec![
                TransportResponse {
                    status: 302,
                    content_type: None,
                    location: Some(
                        "https://journal.proxy.example.edu/paper.pdf?ticket=secret".to_string(),
                    ),
                    body: Vec::new(),
                },
                TransportResponse {
                    status: 200,
                    content_type: Some("application/pdf".to_string()),
                    location: None,
                    body: b"%PDF-1.7\nmock".to_vec(),
                },
            ],
        );
        let source = Url::parse("https://publisher.example/paper?token=source-secret").unwrap();
        let result = retriever
            .retrieve(
                &test_jar(),
                Url::parse("https://proxy.example.edu/login?url=target").unwrap(),
                &source,
                Some("10.1234/example"),
                None,
            )
            .await
            .unwrap();
        assert!(Path::new(&result.path).exists());
        assert!(Path::new(&result.provenance_path).exists());
        let provenance = fs::read_to_string(&result.provenance_path).unwrap();
        assert!(!provenance.contains("source-secret"));
        assert!(!provenance.contains("ticket=secret"));
        assert!(!provenance.contains("never-render-me"));
        assert_eq!(result.redirects.len(), 2);
    }

    #[tokio::test]
    async fn oversized_and_non_pdf_responses_are_rejected() {
        let temp = private_temp();
        let oversized = retriever(
            temp.path().join("large"),
            vec![TransportResponse {
                status: 200,
                content_type: Some("application/pdf".to_string()),
                location: None,
                body: vec![b'x'; 1024 * 1024 + 1],
            }],
        );
        assert!(matches!(
            oversized
                .retrieve(
                    &test_jar(),
                    Url::parse("https://proxy.example.edu/paper").unwrap(),
                    &Url::parse("https://publisher.example/paper").unwrap(),
                    None,
                    None,
                )
                .await,
            Err(RetrievalError::ResponseTooLarge)
        ));

        let html = retriever(
            temp.path().join("html"),
            vec![TransportResponse {
                status: 200,
                content_type: Some("text/html".to_string()),
                location: None,
                body: b"<html>login</html>".to_vec(),
            }],
        );
        assert!(matches!(
            html.retrieve(
                &test_jar(),
                Url::parse("https://proxy.example.edu/paper").unwrap(),
                &Url::parse("https://publisher.example/paper").unwrap(),
                None,
                None,
            )
            .await,
            Err(RetrievalError::SessionExpiredOrRejected)
        ));
    }

    #[tokio::test]
    async fn redirect_abuse_and_private_resolution_are_rejected() {
        let temp = private_temp();
        let redirect = retriever(
            temp.path().join("redirect"),
            vec![TransportResponse {
                status: 302,
                content_type: None,
                location: Some("https://evil.example/private".to_string()),
                body: Vec::new(),
            }],
        );
        assert!(matches!(
            redirect
                .retrieve(
                    &test_jar(),
                    Url::parse("https://proxy.example.edu/paper").unwrap(),
                    &Url::parse("https://publisher.example/paper").unwrap(),
                    None,
                    None,
                )
                .await,
            Err(RetrievalError::UnsafeTarget)
        ));

        let private = InstitutionalRetriever::with_components(
            RetrievalConfig {
                download_root: temp.path().join("private"),
                allowed_hosts: vec!["proxy.example.edu".to_string()],
                max_response_bytes: 1024,
                max_redirects: 1,
                connect_timeout: Duration::from_secs(1),
                request_timeout: Duration::from_secs(2),
                minimum_interval: Duration::from_secs(1),
                hourly_limit: 1,
            },
            Arc::new(MockTransport {
                responses: StdMutex::new(VecDeque::new()),
            }),
            Arc::new(MockResolver {
                addresses: vec!["169.254.169.254".parse().unwrap()],
            }),
        )
        .unwrap();
        assert!(matches!(
            private
                .retrieve(
                    &test_jar(),
                    Url::parse("https://proxy.example.edu/paper").unwrap(),
                    &Url::parse("https://publisher.example/paper").unwrap(),
                    None,
                    None,
                )
                .await,
            Err(RetrievalError::ProhibitedAddress)
        ));
    }

    #[test]
    fn blocks_embedded_private_ipv4_and_filename_traversal() {
        for address in [
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:0001::",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(is_prohibited_ip(address.parse().unwrap()), "{address}");
        }
        assert!(matches!(
            safe_filename(Some("../../paper.pdf"), None, &"a".repeat(64)),
            Err(RetrievalError::UnsafeFilename)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn insecure_download_directory_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let temp = private_temp();
        let root = temp.path().join("downloads");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            persist_pdf(
                &root,
                b"%PDF-1.7\nmock".to_vec(),
                &Url::parse("https://publisher.example/paper").unwrap(),
                None,
                None,
                Vec::new(),
            ),
            Err(RetrievalError::UnsafeDestination)
        ));
    }

    #[test]
    fn test_only_store_imports_do_not_leak_cookie_debug() {
        let temp = private_temp();
        let _store = SessionStore::new(
            temp.path(),
            "unused".to_string(),
            Arc::new(MemoryKeyProvider::available()),
        )
        .unwrap();
        assert!(!format!("{:?}", test_jar()).contains("never-render-me"));
    }
}
