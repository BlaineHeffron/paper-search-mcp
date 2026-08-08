//! Adversarial tests for authorized PDF retrieval.
//!
//! Owned by the security reviewer. No real publisher, proxy, or network is
//! contacted: the transport and the DNS resolver are both mocked through the
//! public seams, so every hostile response is synthesised locally.
//!
//! The cookie jar is built through the real session lifecycle rather than
//! constructed directly, so these tests exercise the same jar the server would
//! actually use — including the canary, which must never surface in a result,
//! an error, or the provenance file.

mod common;

use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use paper_search::institutional::{
    retrieval::{
        HostResolver, InstitutionalRetriever, RetrievalConfig, RetrievalError, RetrievalTransport,
        TransportRequest, TransportResponse,
    },
    store::{CookieJar, KeyProtectionStatus, KeyProvider, StoreError},
    InstitutionalSessionConfig, InstitutionalSessionManager,
};
use reqwest::Url;
use tempfile::TempDir;
use zeroize::Zeroizing;

const PROXY_HOST: &str = "proxy.example.edu";

// ── Test doubles ────────────────────────────────────────────────────────────

struct WorkingKeys {
    key: Mutex<Option<Vec<u8>>>,
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
            *guard = Some(vec![0x5c; 32]);
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

/// Serves a scripted sequence of responses.
struct ScriptedTransport {
    responses: Mutex<Vec<TransportResponse>>,
    delay: Option<Duration>,
}

impl ScriptedTransport {
    fn new(responses: Vec<TransportResponse>) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into_iter().rev().collect()),
            delay: None,
        })
    }

    fn slow(responses: Vec<TransportResponse>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into_iter().rev().collect()),
            delay: Some(delay),
        })
    }
}

#[async_trait]
impl RetrievalTransport for ScriptedTransport {
    async fn get(
        &self,
        _request: TransportRequest<'_>,
    ) -> Result<TransportResponse, RetrievalError> {
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        self.responses
            .lock()
            .unwrap()
            .pop()
            .ok_or(RetrievalError::RequestFailed)
    }
}

/// A transport that must never be reached. Used to prove that validation
/// happens BEFORE any network activity — a check that runs after the request
/// has already gone out is not a check.
struct ForbiddenTransport;

#[async_trait]
impl RetrievalTransport for ForbiddenTransport {
    async fn get(
        &self,
        request: TransportRequest<'_>,
    ) -> Result<TransportResponse, RetrievalError> {
        panic!(
            "transport must not be reached for a target that fails validation: {}",
            request.url
        );
    }
}

struct FixedResolver(Vec<IpAddr>);

#[async_trait]
impl HostResolver for FixedResolver {
    async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, RetrievalError> {
        Ok(self.0.clone())
    }
}

fn public_resolver() -> Arc<FixedResolver> {
    Arc::new(FixedResolver(vec!["93.184.216.34".parse().unwrap()]))
}

// ── Fixtures ────────────────────────────────────────────────────────────────

fn private_temp() -> TempDir {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    temp
}

/// Build a real cookie jar by driving the real lifecycle. The jar carries the
/// canary, so any leak into retrieval output is caught.
fn real_jar(temp: &TempDir) -> CookieJar {
    let manager = InstitutionalSessionManager::with_key_provider(
        InstitutionalSessionConfig {
            data_dir: temp.path().to_path_buf(),
            institution_id: "example-university".to_string(),
            institution_name: "Example University".to_string(),
            allowed_hosts: vec![PROXY_HOST.to_string()],
            max_session_ttl_seconds: 12 * 3600,
        },
        Arc::new(WorkingKeys {
            key: Mutex::new(None),
        }),
    )
    .unwrap();

    let start = manager
        .start(&Url::parse("https://proxy.example.edu/login").unwrap())
        .unwrap();
    fs::write(
        &start.cookie_export_path,
        common::netscape_cookie_file(PROXY_HOST, Utc::now().timestamp() + 86_400),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&start.cookie_export_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    manager.complete(&start.request_id).unwrap();
    manager.load_jar().unwrap()
}

fn config(download_root: PathBuf) -> RetrievalConfig {
    RetrievalConfig {
        download_root,
        allowed_hosts: vec![PROXY_HOST.to_string()],
        max_response_bytes: 256 * 1024,
        max_redirects: 3,
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(5),
        minimum_interval: Duration::from_secs(1),
        hourly_limit: 20,
    }
}

fn retriever(root: PathBuf, transport: Arc<dyn RetrievalTransport>) -> InstitutionalRetriever {
    InstitutionalRetriever::with_components(config(root), transport, public_resolver()).unwrap()
}

fn pdf_response() -> TransportResponse {
    TransportResponse {
        status: 200,
        content_type: Some("application/pdf".to_string()),
        location: None,
        body: common::valid_pdf_bytes(),
    }
}

fn proxy_url(path: &str) -> Url {
    Url::parse(&format!("https://{PROXY_HOST}{path}")).unwrap()
}

fn source_url() -> Url {
    Url::parse("https://publisher.example/article").unwrap()
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn valid_pdf_is_persisted_with_correct_digest_and_private_mode() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let root = temp.path().join("downloads");
    let retriever = retriever(root.clone(), ScriptedTransport::new(vec![pdf_response()]));

    let result = retriever
        .retrieve(
            &jar,
            proxy_url("/paper.pdf"),
            &source_url(),
            Some("10.1234/example"),
            None,
        )
        .await
        .expect("valid PDF is retrieved");

    let path = Path::new(&result.path);
    assert!(path.exists(), "PDF must be written");

    let written = fs::read(path).unwrap();
    assert_eq!(written, common::valid_pdf_bytes());
    assert_eq!(result.size_bytes, written.len());

    // Digest must be over the actual bytes.
    let expected = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(&written));
    assert_eq!(result.sha256, expected, "sha256 must cover the body");

    // Confined beneath the download root.
    let canonical_root = root.canonicalize().unwrap();
    assert!(
        path.canonicalize().unwrap().starts_with(&canonical_root),
        "download must live beneath the configured root"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "retrieved PDF must be created 0600");
    }
}

/// The retrieval result is serialized into an MCP response, and the provenance
/// file lands on disk. Neither may contain cookie material or SSO tokens.
#[tokio::test]
async fn result_and_provenance_carry_no_secrets_or_tokens() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let retriever = retriever(
        temp.path().join("downloads"),
        ScriptedTransport::new(vec![
            TransportResponse {
                status: 302,
                content_type: None,
                // A redirect carrying a one-time SSO ticket, as CAS and some
                // SAML bindings do.
                location: Some(format!(
                    "https://journal.{PROXY_HOST}/paper.pdf?ticket=ST-ONE-TIME-SECRET&SAMLResponse=abc"
                )),
                body: Vec::new(),
            },
            pdf_response(),
        ]),
    );

    let source_with_token =
        Url::parse("https://publisher.example/article?access_token=SOURCE-SECRET#frag").unwrap();

    let result = retriever
        .retrieve(
            &jar,
            proxy_url("/login?url=target&ticket=OUTER-SECRET"),
            &source_with_token,
            Some("10.1234/example"),
            None,
        )
        .await
        .expect("retrieval succeeds through the redirect");

    let serialized = serde_json::to_string(&result).unwrap();
    common::assert_no_secrets(
        &serialized,
        "retrieval result",
        &["ST-ONE-TIME-SECRET", "SOURCE-SECRET", "OUTER-SECRET"],
    );
    common::assert_url_redacted(&serialized, "retrieval result");

    let provenance = fs::read_to_string(&result.provenance_path).unwrap();
    common::assert_no_secrets(
        &provenance,
        "persisted provenance",
        &["ST-ONE-TIME-SECRET", "SOURCE-SECRET", "OUTER-SECRET"],
    );
    common::assert_url_redacted(&provenance, "persisted provenance");

    // Provenance must still be useful: every hop recorded.
    assert_eq!(result.redirects.len(), 2, "each hop must be recorded");
}

// ── SSRF and host confinement ───────────────────────────────────────────────

/// Targets outside the configured institution must be refused BEFORE any
/// request is issued.
#[tokio::test]
async fn off_scope_targets_are_refused_before_any_request() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    for hostile in [
        "https://evil.test/paper.pdf",
        "https://proxy.example.edu.evil.test/paper.pdf",
        "https://notproxy.example.edu/paper.pdf",
        "https://127.0.0.1/paper.pdf",
        "https://[::1]/paper.pdf",
        "https://169.254.169.254/latest/meta-data/",
    ] {
        // A fresh retriever per case: the rate limiter records an attempt
        // before target validation runs, so a shared instance would return
        // RateLimited for every case after the first and mask the real result.
        let retriever = retriever(temp.path().join("downloads"), Arc::new(ForbiddenTransport));
        let url = Url::parse(hostile).unwrap();
        let result = retriever
            .retrieve(&jar, url, &source_url(), None, None)
            .await;
        assert!(
            matches!(result, Err(RetrievalError::UnsafeTarget)),
            "must be refused as unsafe: {hostile}"
        );
    }
}

/// Non-HTTPS and non-443 targets must be refused, including the schemes that
/// parse cleanly as URLs.
#[tokio::test]
async fn insecure_schemes_and_ports_are_refused_before_any_request() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    for hostile in [
        "http://proxy.example.edu/paper.pdf",
        "https://proxy.example.edu:8443/paper.pdf",
        "https://proxy.example.edu:22/paper.pdf",
        "https://user:pass@proxy.example.edu/paper.pdf",
    ] {
        // Fresh retriever per case; see the note in the off-scope test above.
        let retriever = retriever(temp.path().join("downloads"), Arc::new(ForbiddenTransport));
        let url = Url::parse(hostile).unwrap();
        assert!(
            matches!(
                retriever
                    .retrieve(&jar, url, &source_url(), None, None)
                    .await,
                Err(RetrievalError::UnsafeTarget)
            ),
            "must be refused as unsafe: {hostile}"
        );
    }
}

/// A host that is in scope but resolves into private space must be refused.
/// This is the DNS-rebinding shape: the name looks legitimate, the address does
/// not.
#[tokio::test]
async fn in_scope_host_resolving_to_private_space_is_refused() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    for address in [
        "127.0.0.1",
        "169.254.169.254",
        "10.0.0.1",
        "192.168.1.1",
        "::1",
        "::ffff:127.0.0.1",
        "::127.0.0.1",
        "fc00::1",
    ] {
        let retriever = InstitutionalRetriever::with_components(
            config(temp.path().join("downloads")),
            Arc::new(ForbiddenTransport),
            Arc::new(FixedResolver(vec![address.parse().unwrap()])),
        )
        .unwrap();

        let result = retriever
            .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
            .await;
        assert!(
            matches!(result, Err(RetrievalError::ProhibitedAddress)),
            "in-scope host resolving to {address} must be refused"
        );
    }
}

/// If ANY resolved address is prohibited the request must be refused. Accepting
/// because one address happens to be public lets an attacker with partial DNS
/// control win the race.
#[tokio::test]
async fn a_single_prohibited_address_in_the_set_refuses_the_request() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let retriever = InstitutionalRetriever::with_components(
        config(temp.path().join("downloads")),
        Arc::new(ForbiddenTransport),
        Arc::new(FixedResolver(vec![
            "93.184.216.34".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ])),
    )
    .unwrap();

    assert!(matches!(
        retriever
            .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
            .await,
        Err(RetrievalError::ProhibitedAddress)
    ));
}

// ── Redirect abuse ──────────────────────────────────────────────────────────

/// Every redirect target must be re-validated exactly as the first hop was.
#[tokio::test]
async fn hostile_redirect_targets_are_refused() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    for (location, why) in common::BLOCKED_REDIRECT_TARGETS {
        let retriever = retriever(
            temp.path().join(format!("dl-{}", location.len())),
            ScriptedTransport::new(vec![
                TransportResponse {
                    status: 302,
                    content_type: None,
                    location: Some((*location).to_string()),
                    body: Vec::new(),
                },
                // If validation is skipped this second response would be used.
                pdf_response(),
            ]),
        );

        let result = retriever
            .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
            .await;
        assert!(
            result.is_err(),
            "redirect must be refused ({why}): {location}"
        );
    }
}

/// A redirect loop must terminate at the configured bound.
#[tokio::test]
async fn redirect_chains_are_bounded() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    let hops: Vec<TransportResponse> = (0..12)
        .map(|index| TransportResponse {
            status: 302,
            content_type: None,
            location: Some(format!("https://{PROXY_HOST}/hop-{index}")),
            body: Vec::new(),
        })
        .collect();

    let retriever = retriever(temp.path().join("downloads"), ScriptedTransport::new(hops));
    assert!(matches!(
        retriever
            .retrieve(&jar, proxy_url("/start"), &source_url(), None, None)
            .await,
        Err(RetrievalError::RedirectLimit)
    ));
}

/// A redirect with no `Location` must be an error, not a silent success.
#[tokio::test]
async fn redirect_without_location_is_rejected() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let retriever = retriever(
        temp.path().join("downloads"),
        ScriptedTransport::new(vec![TransportResponse {
            status: 302,
            content_type: None,
            location: None,
            body: Vec::new(),
        }]),
    );

    assert!(matches!(
        retriever
            .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
            .await,
        Err(RetrievalError::InvalidRedirect)
    ));
}

// ── Response validation ─────────────────────────────────────────────────────

/// Content-Type is a claim by the server; the magic number is the evidence.
/// Every hostile body must be refused even when labelled as a PDF.
#[tokio::test]
async fn hostile_bodies_are_refused_even_when_labelled_pdf() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    for (index, (why, body)) in common::hostile_bodies().into_iter().enumerate() {
        let root = temp.path().join(format!("dl-body-{index}"));
        let retriever = retriever(
            root.clone(),
            ScriptedTransport::new(vec![TransportResponse {
                status: 200,
                content_type: Some("application/pdf".to_string()),
                location: None,
                body,
            }]),
        );

        let result = retriever
            .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
            .await;
        // The security property is that the body is REFUSED and nothing is
        // written. The exact error class is deliberately not pinned: an HTML
        // body is usually an expired-session login page, and the implementation
        // is free to classify that more precisely than `NotPdf` so the caller
        // knows to re-authenticate instead of retrying. Over-specifying here
        // would block that improvement.
        assert!(
            result.is_err(),
            "body must be refused ({why}), got a success"
        );
        assert!(
            !root.exists() || fs::read_dir(&root).unwrap().count() == 0,
            "nothing may be written for a refused body ({why})"
        );
    }
}

/// A valid PDF body served under a non-PDF content type must still be refused:
/// both signals have to agree.
#[tokio::test]
async fn non_pdf_content_types_are_refused() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    for (index, content_type) in common::BLOCKED_CONTENT_TYPES.iter().enumerate() {
        let retriever = retriever(
            temp.path().join(format!("dl-ct-{index}")),
            ScriptedTransport::new(vec![TransportResponse {
                status: 200,
                content_type: Some((*content_type).to_string()),
                location: None,
                body: common::valid_pdf_bytes(),
            }]),
        );

        assert!(
            retriever
                .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
                .await
                .is_err(),
            "content type must be refused: {content_type}"
        );
    }
}

/// The size cap must be enforced on the streamed body, and nothing may be
/// written when it trips.
#[tokio::test]
async fn oversized_responses_are_refused_and_write_nothing() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let root = temp.path().join("downloads");

    let mut oversized = common::valid_pdf_bytes();
    oversized.resize(256 * 1024 + 1, b'A');

    let retriever = retriever(
        root.clone(),
        ScriptedTransport::new(vec![TransportResponse {
            status: 200,
            content_type: Some("application/pdf".to_string()),
            location: None,
            body: oversized,
        }]),
    );

    assert!(matches!(
        retriever
            .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
            .await,
        Err(RetrievalError::ResponseTooLarge)
    ));
    assert!(
        !root.exists() || fs::read_dir(&root).unwrap().count() == 0,
        "an oversized response must leave nothing on disk"
    );
}

/// 401/403 must be reported as an authorization problem, distinctly from a
/// malformed download.
#[tokio::test]
async fn unauthorized_statuses_are_reported_as_such() {
    let temp = private_temp();
    let jar = real_jar(&temp);

    for status in [401u16, 403] {
        let retriever = retriever(
            temp.path().join(format!("dl-{status}")),
            ScriptedTransport::new(vec![TransportResponse {
                status,
                content_type: Some("text/html".to_string()),
                location: None,
                body: b"<html>denied</html>".to_vec(),
            }]),
        );

        assert!(
            matches!(
                retriever
                    .retrieve(&jar, proxy_url("/paper.pdf"), &source_url(), None, None)
                    .await,
                Err(RetrievalError::Unauthorized)
            ),
            "HTTP {status} must report Unauthorized"
        );
    }
}

// ── Filename and path confinement ───────────────────────────────────────────

/// A caller-supplied filename must never escape the download root.
#[tokio::test]
async fn hostile_filenames_never_escape_the_download_root() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let root = temp.path().join("downloads");

    let canary_target = temp.path().join("escaped.pdf");

    for (hostile, why) in common::HOSTILE_FILENAMES {
        let retriever = retriever(root.clone(), ScriptedTransport::new(vec![pdf_response()]));
        let result = retriever
            .retrieve(
                &jar,
                proxy_url("/paper.pdf"),
                &source_url(),
                None,
                Some(hostile),
            )
            .await;

        if let Ok(paper) = result {
            // If it was accepted, it must have been sanitised into the root.
            let written = Path::new(&paper.path).canonicalize().unwrap();
            let canonical_root = root.canonicalize().unwrap();
            assert!(
                written.starts_with(&canonical_root),
                "filename escaped the root ({why}): {hostile:?} -> {}",
                written.display()
            );
            fs::remove_file(&written).ok();
            fs::remove_file(&paper.provenance_path).ok();
        }

        assert!(
            !canary_target.exists(),
            "filename wrote outside the root ({why}): {hostile:?}"
        );
    }
}

/// An absurdly long filename must be refused or truncated, never passed
/// through to the filesystem where it would error opaquely.
#[tokio::test]
async fn overlong_filenames_are_refused() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let retriever = retriever(
        temp.path().join("downloads"),
        ScriptedTransport::new(vec![pdf_response()]),
    );

    let overlong = common::overlong_filename();
    let result = retriever
        .retrieve(
            &jar,
            proxy_url("/paper.pdf"),
            &source_url(),
            None,
            Some(&overlong),
        )
        .await;

    assert!(matches!(result, Err(RetrievalError::UnsafeFilename)));
}

/// A second retrieval that would land on the same path must not overwrite the
/// first. Downloads are evidence; silently replacing one is data loss.
#[tokio::test]
async fn existing_downloads_are_never_overwritten() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let root = temp.path().join("downloads");

    let first = retriever(root.clone(), ScriptedTransport::new(vec![pdf_response()]));
    let paper = first
        .retrieve(
            &jar,
            proxy_url("/paper.pdf"),
            &source_url(),
            Some("10.1234/same"),
            None,
        )
        .await
        .expect("first retrieval succeeds");

    fs::write(&paper.path, b"%PDF-1.7\nORIGINAL").unwrap();

    // A separate retriever avoids the rate limiter; the destination collides.
    let second = retriever(root.clone(), ScriptedTransport::new(vec![pdf_response()]));
    let result = second
        .retrieve(
            &jar,
            proxy_url("/paper.pdf"),
            &source_url(),
            Some("10.1234/same"),
            None,
        )
        .await;

    assert!(
        matches!(result, Err(RetrievalError::DestinationExists)),
        "a colliding destination must be refused"
    );
    assert_eq!(
        fs::read(&paper.path).unwrap(),
        b"%PDF-1.7\nORIGINAL",
        "the existing file must be untouched"
    );
}

// ── Rate limiting and concurrency ───────────────────────────────────────────

/// The anti-bulk-crawl control: a rapid second retrieval on the same retriever
/// must be refused.
#[tokio::test]
async fn rapid_second_retrieval_is_rate_limited() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let retriever = retriever(
        temp.path().join("downloads"),
        ScriptedTransport::new(vec![pdf_response(), pdf_response()]),
    );

    retriever
        .retrieve(
            &jar,
            proxy_url("/one.pdf"),
            &source_url(),
            Some("10.1234/one"),
            None,
        )
        .await
        .expect("first retrieval succeeds");

    let second = retriever
        .retrieve(
            &jar,
            proxy_url("/two.pdf"),
            &source_url(),
            Some("10.1234/two"),
            None,
        )
        .await;

    assert!(
        matches!(second, Err(RetrievalError::RateLimited)),
        "a rapid second retrieval must be rate limited"
    );
}

/// Exactly one retrieval may be in flight. Concurrency would defeat the
/// interval limiter entirely.
#[tokio::test]
async fn concurrent_retrieval_is_refused_as_busy() {
    let temp = private_temp();
    let jar = real_jar(&temp);
    let retriever = retriever(
        temp.path().join("downloads"),
        ScriptedTransport::slow(
            vec![pdf_response(), pdf_response()],
            Duration::from_millis(300),
        ),
    );

    let source = source_url();
    let (first, second) = tokio::join!(
        retriever.retrieve(
            &jar,
            proxy_url("/one.pdf"),
            &source,
            Some("10.1234/one"),
            None
        ),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            retriever
                .retrieve(
                    &jar,
                    proxy_url("/two.pdf"),
                    &source,
                    Some("10.1234/two"),
                    None,
                )
                .await
        }
    );

    assert!(first.is_ok(), "the first retrieval should complete");
    assert!(
        matches!(second, Err(RetrievalError::Busy)),
        "an overlapping retrieval must be refused as Busy, got {second:?}"
    );
}

// ── Configuration hardening ─────────────────────────────────────────────────

/// Limits are safety controls, so a configuration that disables them must be
/// refused at construction rather than honoured.
#[test]
fn unsafe_configurations_are_refused() {
    let root = PathBuf::from("/tmp/paper-search-test-unused");

    let cases: Vec<(&str, RetrievalConfig)> = vec![
        (
            "no allowed hosts leaves the target set unbounded",
            RetrievalConfig {
                allowed_hosts: Vec::new(),
                ..config(root.clone())
            },
        ),
        (
            "zero redirects is unusable",
            RetrievalConfig {
                max_redirects: 0,
                ..config(root.clone())
            },
        ),
        (
            "excessive redirects allow chain abuse",
            RetrievalConfig {
                max_redirects: 50,
                ..config(root.clone())
            },
        ),
        (
            "unbounded response size",
            RetrievalConfig {
                max_response_bytes: usize::MAX,
                ..config(root.clone())
            },
        ),
        (
            "zero rate limit interval disables anti-crawl protection",
            RetrievalConfig {
                minimum_interval: Duration::ZERO,
                ..config(root.clone())
            },
        ),
        (
            "unbounded hourly limit disables anti-crawl protection",
            RetrievalConfig {
                hourly_limit: usize::MAX,
                ..config(root.clone())
            },
        ),
        (
            "zero hourly limit",
            RetrievalConfig {
                hourly_limit: 0,
                ..config(root.clone())
            },
        ),
    ];

    for (why, candidate) in cases {
        assert!(
            candidate.validate().is_err(),
            "configuration must be refused: {why}"
        );
    }

    assert!(
        config(root).validate().is_ok(),
        "the baseline test configuration must be valid"
    );
}
