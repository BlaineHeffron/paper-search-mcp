//! Adversarial tests for the zero-secret institutional link handoff.
//!
//! This is the pre-existing `get_institutional_access_url` path — the default
//! route, and the only one that involves no stored session at all. It must stay
//! safe as the session subsystem grows around it, so these are regression locks
//! on properties that hold today, not aspirations.
//!
//! Owned by the security reviewer. Every assertion here is a security property;
//! if one starts failing, that is a finding to investigate, not a test to relax.

mod common;

use paper_search::access::{InstitutionalAccess, InstitutionalAccessError};
use reqwest::Url;

fn access() -> InstitutionalAccess {
    InstitutionalAccess::new(
        "Example University".to_string(),
        "https://proxy.example.edu/login".to_string(),
        "url".to_string(),
    )
    .expect("proxy configuration is valid")
}

/// Schemes that smuggle behaviour past a transport-layer check must never
/// produce a link. `data:` and `javascript:` are the interesting ones: both
/// parse cleanly as URLs, so only an explicit scheme check stops them.
#[test]
fn rejects_non_http_schemes() {
    let access = access();
    for scheme_url in [
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "javascript:alert(1)",
        "data:application/pdf;base64,JVBERi0=",
        "ftp://example.edu/paper.pdf",
        "gopher://example.edu:70/1",
        "dict://127.0.0.1:11211/stat",
        "mailto:someone@example.edu",
    ] {
        let result = access.access_link(scheme_url);
        assert!(
            matches!(
                result,
                Err(InstitutionalAccessError::UnsupportedTargetScheme)
                    | Err(InstitutionalAccessError::InvalidTargetUrl(_))
            ),
            "scheme should be refused: {scheme_url}"
        );
    }
}

/// Garbage input must produce an error, never a partially-formed link that a
/// user might click.
#[test]
fn rejects_unparseable_targets() {
    let access = access();
    for bad in ["", "   ", "not a url", "://missing-scheme", "https://"] {
        assert!(
            access.access_link(bad).is_err(),
            "unparseable target should be refused: {bad:?}"
        );
    }
}

/// A proxy login endpoint is operator configuration. A malformed one must fail
/// at construction rather than yielding a broken link later.
#[test]
fn rejects_invalid_proxy_configuration() {
    for bad_proxy in [
        "",
        "not a url",
        "file:///tmp/login",
        "javascript:alert(1)",
        "ftp://proxy.example.edu/login",
    ] {
        let result = InstitutionalAccess::new(
            "Example University".to_string(),
            bad_proxy.to_string(),
            "url".to_string(),
        );
        assert!(
            result.is_err(),
            "invalid proxy configuration should be refused: {bad_proxy:?}"
        );
    }
}

/// The target must survive as an exactly-encoded query parameter. If encoding
/// is lossy or the target escapes into the proxy URL's own structure, the user
/// lands somewhere other than the paper they asked for.
#[test]
fn target_is_encoded_not_interpolated() {
    let access = access();
    // Characters that would break out of a naively-interpolated query string.
    let hostile_target = "https://publisher.example/article?a=1&b=2#frag";
    let link = access
        .access_link(hostile_target)
        .expect("https target is accepted");

    let parsed = Url::parse(&link.access_url).expect("access url is a valid URL");
    assert_eq!(parsed.host_str(), Some("proxy.example.edu"));
    assert_eq!(parsed.scheme(), "https");

    let round_tripped = parsed
        .query_pairs()
        .find(|(key, _)| key == "url")
        .map(|(_, value)| value.into_owned())
        .expect("url parameter is present");
    assert_eq!(
        round_tripped, hostile_target,
        "target must round-trip exactly through query encoding"
    );

    // The `&b=2` in the target must not have become a sibling parameter of the
    // proxy URL — exactly one parameter, and no stray `b`.
    assert_eq!(parsed.query_pairs().count(), 1);
    assert!(parsed.query_pairs().all(|(key, _)| key == "url"));
}

/// A target cannot redirect the handoff to a different proxy host. The proxy
/// comes from operator configuration and must be the authority every time.
#[test]
fn target_cannot_change_the_proxy_host() {
    let access = access();
    for target in [
        "https://evil.test/paper.pdf",
        "https://proxy.example.edu.evil.test/paper.pdf",
        "https://evil.test/?next=https://proxy.example.edu",
    ] {
        let link = access.access_link(target).expect("https target parses");
        let parsed = Url::parse(&link.access_url).expect("valid URL");
        assert_eq!(
            parsed.host_str(),
            Some("proxy.example.edu"),
            "proxy host must come from configuration, not from the target: {target}"
        );
    }
}

/// The link result is serialized straight into an MCP response, so it is LLM
/// context. A target carrying `user:password@` must be refused outright rather
/// than propagated — otherwise the password lands in the model's context and in
/// whatever transcript that context is written to.
#[test]
fn credentials_in_a_target_are_refused() {
    let access = access();

    for hostile in [
        "https://someone:hunter2@publisher.example/paper.pdf",
        "https://someone@publisher.example/paper.pdf",
    ] {
        match access.access_link(hostile) {
            Err(_) => {}
            Ok(link) => {
                // If a future change chooses to strip rather than reject, the
                // credential must still not survive into the response.
                let serialized = serde_json::to_string(&link).expect("link serializes");
                common::assert_no_secrets(
                    &serialized,
                    "institutional access link",
                    &["hunter2", "someone"],
                );
            }
        }
    }
}

/// Plaintext HTTP must not be offered as an institutional route: the session
/// cookie the user is about to establish would cross the network in the clear.
#[test]
fn plaintext_http_targets_are_refused() {
    let access = access();
    assert!(
        access
            .access_link("http://publisher.example/paper.pdf")
            .is_err(),
        "an http target must be refused; the resulting session would be unencrypted"
    );
}

/// The proxy login endpoint is operator configuration and must be https.
#[test]
fn plaintext_http_proxy_configuration_is_refused() {
    assert!(
        InstitutionalAccess::new(
            "Example University".to_string(),
            "http://proxy.example.edu/login".to_string(),
            "url".to_string(),
        )
        .is_err(),
        "an http proxy login endpoint must be refused"
    );
}

/// Whatever else changes, the response must keep telling the caller that a
/// human has to authenticate, and must not imply the server handles credentials.
#[test]
fn response_states_that_authentication_is_user_mediated() {
    let access = access();
    let link = access
        .access_link("https://doi.org/10.1103/PhysRevA.1.1")
        .expect("https target is accepted");

    assert!(link.interactive_authentication_required);
    assert_eq!(link.access_type, "institutional_browser_handoff");
    assert!(
        link.note.to_lowercase().contains("does not receive")
            || link.note.to_lowercase().contains("credential"),
        "note must state the credential boundary"
    );
}

/// The serialized link is LLM-visible by construction. Nothing resembling a
/// session, cookie, or token may appear in it.
#[test]
fn serialized_link_carries_no_session_material() {
    let access = access();
    let link = access
        .access_link("https://doi.org/10.1103/PhysRevA.1.1")
        .expect("https target is accepted");
    let serialized = serde_json::to_string(&link).expect("link serializes");

    common::assert_no_secrets(&serialized, "institutional access link", &[]);
    let lowered = serialized.to_lowercase();
    for forbidden in [
        "cookie",
        "set-cookie",
        "session=",
        "bearer",
        "authorization",
    ] {
        assert!(
            !lowered.contains(forbidden),
            "serialized link must not mention {forbidden}"
        );
    }
}

/// A very long target must not panic or be silently truncated into a different
/// URL. Either outcome — clean error or exact round-trip — is acceptable;
/// silent corruption is not.
#[test]
fn overlong_target_is_handled_without_corruption() {
    let access = access();
    let long_target = format!("https://publisher.example/{}", "a".repeat(60_000));

    match access.access_link(&long_target) {
        Ok(link) => {
            let parsed = Url::parse(&link.access_url).expect("valid URL");
            let round_tripped = parsed
                .query_pairs()
                .find(|(key, _)| key == "url")
                .map(|(_, value)| value.into_owned())
                .expect("url parameter present");
            assert_eq!(
                round_tripped, long_target,
                "long target must round-trip exactly or be rejected outright"
            );
        }
        Err(_) => {}
    }
}
