//! Shared adversarial test vectors for the institutional access subsystem.
//!
//! Deliberately free of any dependency on the crate under test: these are the
//! attack corpus, owned by the security reviewer, and they must stay valid even
//! as the implementation is refactored. Test files pair them with whatever the
//! implementation exposes.
//!
//! Every vector here is a *negative* case unless the name says otherwise. If a
//! change to the implementation makes one of these pass, that is a finding, not
//! a test to update.

#![allow(dead_code)]

// ── SSRF: hosts and addresses that must never be reachable ──────────────────

/// Literal addresses that must be rejected by the address validator.
///
/// The IPv6 entries at the end are the ones implementations usually miss: a
/// validator that only pattern-matches IPv4 text, or that checks the v6 form
/// without unwrapping an embedded v4, lets every one of them through.
pub const BLOCKED_ADDRESSES: &[(&str, &str)] = &[
    ("127.0.0.1", "IPv4 loopback"),
    ("127.1", "loopback, 32-bit shorthand"),
    ("127.0.0.1.", "loopback with trailing root dot"),
    ("0.0.0.0", "unspecified / this-host"),
    ("0177.0.0.1", "loopback, octal encoded"),
    ("2130706433", "loopback, decimal-integer encoded"),
    ("0x7f000001", "loopback, hex encoded"),
    ("10.0.0.1", "RFC1918 private"),
    ("10.255.255.255", "RFC1918 private, upper bound"),
    ("172.16.0.1", "RFC1918 private, lower bound of /12"),
    ("172.31.255.255", "RFC1918 private, upper bound of /12"),
    ("192.168.1.1", "RFC1918 private"),
    ("169.254.1.1", "link-local"),
    (
        "169.254.169.254",
        "cloud instance metadata — the classic SSRF prize",
    ),
    ("100.64.0.1", "CGNAT shared address space"),
    ("192.0.0.1", "IETF protocol assignments"),
    ("192.0.2.1", "TEST-NET-1 documentation range"),
    ("198.18.0.1", "benchmarking range"),
    ("224.0.0.1", "multicast"),
    ("239.255.255.250", "SSDP multicast"),
    ("255.255.255.255", "limited broadcast"),
    ("240.0.0.1", "reserved / class E"),
    ("::1", "IPv6 loopback"),
    ("::", "IPv6 unspecified"),
    ("fc00::1", "IPv6 unique local"),
    ("fd00::1", "IPv6 unique local"),
    ("fe80::1", "IPv6 link-local"),
    ("ff02::1", "IPv6 multicast"),
    (
        "::ffff:127.0.0.1",
        "IPv4-mapped loopback — must unwrap and re-check",
    ),
    (
        "::ffff:10.0.0.1",
        "IPv4-mapped private — must unwrap and re-check",
    ),
    (
        "::ffff:169.254.169.254",
        "IPv4-mapped metadata — must unwrap and re-check",
    ),
    ("::ffff:7f00:1", "IPv4-mapped loopback in hex form"),
    ("64:ff9b::127.0.0.1", "NAT64 embedding loopback"),
    ("64:ff9b::169.254.169.254", "NAT64 embedding metadata"),
    ("2002:7f00:0001::", "6to4 embedding loopback"),
    ("2002:a00:1::", "6to4 embedding RFC1918"),
    // IPv4-COMPATIBLE IPv6 (deprecated ::/96). Distinct from the IPv4-MAPPED
    // form above: `to_ipv4_mapped()` unwraps only `::ffff:0:0/96` and returns
    // None for these, so a validator built on it lets them through. `to_ipv4()`
    // unwraps both.
    (
        "::127.0.0.1",
        "IPv4-compatible loopback — not caught by to_ipv4_mapped",
    ),
    ("::169.254.169.254", "IPv4-compatible metadata address"),
    ("::10.0.0.1", "IPv4-compatible RFC1918"),
    ("::7f00:1", "IPv4-compatible loopback in hex form"),
];

/// Embedded-IPv4 forms that are real but that we have accepted as residual risk
/// rather than blocked. Listed so the gap is recorded rather than forgotten; no
/// test asserts on these.
pub const KNOWN_UNBLOCKED_V6_FORMS: &[(&str, &str)] = &[
    (
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "Teredo 2001::/32 embeds an IPv4 server address",
    ),
    (
        "64:ff9b:1::7f00:1",
        "RFC 8215 local-use NAT64 prefix beyond the well-known one",
    ),
];

/// Addresses that are publicly routable and must be allowed by the address
/// validator, so that over-broad denial is caught too. A validator that blocks
/// everything trivially passes the negative corpus above.
pub const ALLOWED_ADDRESSES: &[&str] = &[
    "1.1.1.1",
    "8.8.8.8",
    "129.79.1.1", // Indiana University public space
    "2606:4700:4700::1111",
];

/// URLs that must be rejected before any network activity occurs.
pub const BLOCKED_URLS: &[(&str, &str)] = &[
    (
        "http://example.edu/paper.pdf",
        "plaintext http is never allowed",
    ),
    ("ftp://example.edu/paper.pdf", "non-http scheme"),
    ("file:///etc/passwd", "file scheme — local file read"),
    ("file://localhost/etc/passwd", "file scheme with authority"),
    (
        "gopher://example.edu:70/1",
        "gopher — classic SSRF protocol smuggling",
    ),
    ("dict://127.0.0.1:11211/stat", "dict — memcached probing"),
    (
        "data:application/pdf;base64,JVBERi0=",
        "data URI bypasses all transport checks",
    ),
    ("javascript:alert(1)", "javascript scheme"),
    ("https://example.edu:8080/paper.pdf", "non-443 port"),
    (
        "https://example.edu:22/paper.pdf",
        "non-443 port — SSH probing",
    ),
    ("https://127.0.0.1/paper.pdf", "loopback literal"),
    ("https://[::1]/paper.pdf", "IPv6 loopback literal"),
    (
        "https://169.254.169.254/latest/meta-data/",
        "metadata service",
    ),
    ("https://localhost/paper.pdf", "loopback by name"),
    (
        "https://user:pass@example.edu/paper.pdf",
        "embedded credentials in URL",
    ),
    (
        "https://example.edu@evil.test/paper.pdf",
        "userinfo confusion — real host is evil.test",
    ),
    (
        "https://example.edu\t.evil.test/p.pdf",
        "tab injection in host",
    ),
    (
        "https://example.edu\u{0000}.evil.test/p.pdf",
        "NUL injection in host",
    ),
];

// ── Redirect abuse ──────────────────────────────────────────────────────────

/// `Location` values that must be refused when returned by a redirect hop.
/// Re-validation must be identical to first-hop validation; a common bug is
/// validating only the initial URL and then trusting the chain.
pub const BLOCKED_REDIRECT_TARGETS: &[(&str, &str)] = &[
    (
        "http://proxy.example.edu/paper.pdf",
        "https downgrade mid-chain",
    ),
    ("https://127.0.0.1/paper.pdf", "redirect into loopback"),
    (
        "https://169.254.169.254/latest/meta-data/",
        "redirect into metadata service",
    ),
    ("file:///etc/passwd", "scheme change to file mid-chain"),
    (
        "https://evil.test/paper.pdf",
        "redirect off the confined host set",
    ),
    ("//evil.test/paper.pdf", "protocol-relative redirect"),
    (
        "https://proxy.example.edu.evil.test/p.pdf",
        "suffix confusion on the confined domain",
    ),
    (
        "https://evil.test/?next=proxy.example.edu",
        "confined host appears only in the query",
    ),
];

// ── Filename sanitization / path confinement ────────────────────────────────

/// Filenames that must never produce a path outside the download root, and must
/// never yield an empty or dot-only name.
pub const HOSTILE_FILENAMES: &[(&str, &str)] = &[
    ("../escape.pdf", "parent traversal"),
    (
        "../../../../etc/cron.d/pwn",
        "deep traversal to a privileged location",
    ),
    ("..%2fescape.pdf", "URL-encoded traversal"),
    ("..%252fescape.pdf", "double-encoded traversal"),
    (
        "....//escape.pdf",
        "traversal surviving naive '..' stripping",
    ),
    ("..\\escape.pdf", "windows-style traversal"),
    ("/etc/passwd", "absolute path"),
    ("//etc/passwd", "absolute path, doubled separator"),
    ("~/.ssh/authorized_keys", "home-relative expansion"),
    ("$HOME/.bashrc", "shell variable in a filename"),
    ("paper\u{0000}.pdf", "embedded NUL truncation"),
    ("paper\n.pdf", "newline — log injection and shell confusion"),
    ("paper\r\n.pdf", "CRLF injection"),
    (".", "dot"),
    ("..", "dot-dot"),
    ("", "empty name"),
    ("   ", "whitespace-only name"),
    (".hidden.pdf", "leading dot creates a hidden file"),
    ("CON", "windows reserved device name"),
    ("paper.pdf.", "trailing dot"),
    ("paper.pdf ", "trailing space"),
    (
        "\u{202e}fdp.gpj",
        "right-to-left override — display spoofing",
    ),
    ("a/b/c.pdf", "nested separators"),
];

/// A name longer than any sane filesystem component limit (255 bytes on ext4).
pub fn overlong_filename() -> String {
    format!("{}.pdf", "A".repeat(4096))
}

// ── request_id validation ───────────────────────────────────────────────────

/// Values that must be refused by `request_id` validation before the string is
/// ever joined onto a path. Completion both reads and deletes through this id,
/// so a traversal here is an arbitrary-file-delete primitive.
pub const HOSTILE_REQUEST_IDS: &[(&str, &str)] = &[
    ("..", "parent directory"),
    ("../../../../etc/passwd", "traversal"),
    ("..%2f..%2fetc%2fpasswd", "encoded traversal"),
    ("/etc/passwd", "absolute path"),
    ("", "empty"),
    (".", "current directory"),
    ("a/b", "embedded separator"),
    ("a\u{0000}b", "embedded NUL"),
    ("../\u{202e}", "traversal plus bidi override"),
    (
        "ABCDEF0123456789ABCDEF0123456789",
        "uppercase hex — must not be silently downcased",
    ),
    ("g0000000000000000000000000000000", "non-hex character"),
    ("0123456789abcdef", "correct alphabet, too short"),
    (
        "0123456789abcdef0123456789abcdef0",
        "correct alphabet, too long",
    ),
    (
        "0123456789abcdef0123456789abcde\u{0301}",
        "combining mark — unicode normalization",
    ),
];

/// Shape of a well-formed request id, for the positive control.
pub const VALID_REQUEST_ID: &str = "0123456789abcdef0123456789abcdef";

// ── Response body validation ────────────────────────────────────────────────

/// A minimal but structurally valid PDF. The only positive control in this file.
pub fn valid_pdf_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"%PDF-1.7\n");
    v.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    v.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n");
    v.extend_from_slice(b"%%EOF\n");
    v
}

/// Bodies that must be rejected even when served with `Content-Type: application/pdf`.
/// Content type is a claim by the server; the magic number is the evidence.
pub fn hostile_bodies() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "html login page — the expired-session case, must not be saved as a PDF",
            b"<!DOCTYPE html><html><body><form action=\"/login\">SSO</form></body></html>".to_vec(),
        ),
        (
            "html access denied",
            b"<html><body>Access denied: not licensed</body></html>".to_vec(),
        ),
        ("empty body", Vec::new()),
        ("shorter than the magic number", b"%PD".to_vec()),
        (
            "magic number present but not at offset zero",
            b"\n\n%PDF-1.4\n".to_vec(),
        ),
        (
            "magic number preceded by html",
            b"<html><!--%PDF-1.4--></html>".to_vec(),
        ),
        ("ELF executable", b"\x7fELF\x02\x01\x01\x00".to_vec()),
        ("zip / office document", b"PK\x03\x04\x14\x00".to_vec()),
        ("gzip", b"\x1f\x8b\x08\x00".to_vec()),
        (
            "shell script with a shebang",
            b"#!/bin/sh\nrm -rf /\n".to_vec(),
        ),
        (
            "postscript, adjacent format but not a PDF",
            b"%!PS-Adobe-3.0\n".to_vec(),
        ),
        (
            "utf-8 BOM before the magic number",
            b"\xef\xbb\xbf%PDF-1.4\n".to_vec(),
        ),
    ]
}

/// Content-Type headers that must not be accepted for a PDF download.
pub const BLOCKED_CONTENT_TYPES: &[&str] = &[
    "text/html",
    "text/html; charset=utf-8",
    "application/xhtml+xml",
    "text/plain",
    "application/json",
    "image/png",
    "application/x-msdownload",
    "multipart/mixed; boundary=x",
];

// ── Secret redaction ────────────────────────────────────────────────────────

/// A canary cookie value. Any test that produces output — a status result, a
/// retrieval result, an error string, a `Debug` rendering, a log line — asserts
/// this substring is absent. Distinctive enough that a match cannot be chance.
pub const COOKIE_CANARY: &str = "CANARY_SeSsIoN_c0okie_v4lue_do_not_leak";

/// A Netscape-format cookie file containing the canary, for round-trip and
/// redaction tests. Tab-separated, as the format requires.
pub fn netscape_cookie_file(domain: &str, expiry_epoch: i64) -> String {
    format!(
        "# Netscape HTTP Cookie File\n\
         # This is a generated test fixture. Not a real session.\n\
         {domain}\tTRUE\t/\tTRUE\t{expiry_epoch}\tezproxy\t{canary}\n\
         {domain}\tTRUE\t/\tTRUE\t{expiry_epoch}\tezproxyl\t{canary}_2\n",
        domain = domain,
        expiry_epoch = expiry_epoch,
        canary = COOKIE_CANARY,
    )
}

/// Malformed Netscape cookie files that must be rejected without panicking and
/// without echoing their content back in an error.
pub fn malformed_cookie_files() -> Vec<(&'static str, String)> {
    vec![
        ("empty file", String::new()),
        (
            "comments only",
            "# nothing here\n# still nothing\n".to_string(),
        ),
        ("too few fields", "example.edu\tTRUE\t/\n".to_string()),
        (
            "non-numeric expiry",
            "example.edu\tTRUE\t/\tTRUE\tnot_a_number\tk\tv\n".to_string(),
        ),
        (
            "expiry overflowing i64",
            "example.edu\tTRUE\t/\tTRUE\t99999999999999999999\tk\tv\n".to_string(),
        ),
        (
            "negative expiry",
            "example.edu\tTRUE\t/\tTRUE\t-1\tk\tv\n".to_string(),
        ),
        (
            "out-of-scope domain — must be filtered, not imported",
            format!(
                "evil.test\tTRUE\t/\tTRUE\t9999999999\tsteal\t{}\n",
                COOKIE_CANARY
            ),
        ),
        (
            "leading-dot domain that is a suffix-confusion attempt",
            format!(
                ".example.edu.evil.test\tTRUE\t/\tTRUE\t9999999999\tsteal\t{}\n",
                COOKIE_CANARY
            ),
        ),
        (
            "embedded NUL",
            "example.edu\tTRUE\t/\tTRUE\t9999999999\tk\tv\u{0000}x\n".to_string(),
        ),
        (
            "CRLF injection in a cookie value",
            "example.edu\tTRUE\t/\tTRUE\t9999999999\tk\tv\r\nSet-Cookie: evil=1\n".to_string(),
        ),
        (
            "absurdly long single line",
            format!(
                "example.edu\tTRUE\t/\tTRUE\t9999999999\tk\t{}\n",
                "A".repeat(1 << 20)
            ),
        ),
    ]
}

// ── Ciphertext tampering ────────────────────────────────────────────────────

/// Mutations of a sealed store that must all fail authentication rather than
/// yielding plaintext. AEAD makes these cheap to guarantee; the point of the
/// test is that the AAD actually binds what it claims to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tamper {
    /// Flip a bit in the ciphertext body.
    FlipCiphertextBit,
    /// Flip a bit in the authentication tag.
    FlipTagBit,
    /// Flip a bit in the nonce.
    FlipNonceBit,
    /// Truncate the sealed blob.
    Truncate,
    /// Replace the whole file with unrelated bytes.
    Garbage,
    /// Zero-length file.
    Empty,
    /// Downgrade the declared format version — must not select a weaker path.
    DowngradeVersion,
    /// Re-label the institution the blob claims to belong to. Must fail because
    /// the institution id is bound as additional authenticated data.
    SwapInstitutionAad,
}

pub const ALL_TAMPERS: &[Tamper] = &[
    Tamper::FlipCiphertextBit,
    Tamper::FlipTagBit,
    Tamper::FlipNonceBit,
    Tamper::Truncate,
    Tamper::Garbage,
    Tamper::Empty,
    Tamper::DowngradeVersion,
    Tamper::SwapInstitutionAad,
];

// ── Filesystem permission fixtures ──────────────────────────────────────────

/// Directory modes that must cause a fail-closed refusal rather than a silent
/// repair. Silent repair is worse than refusal: it erases the evidence that
/// something tampered with the store.
pub const UNSAFE_DIR_MODES: &[(u32, &str)] = &[
    (0o777, "world-writable"),
    (
        0o775,
        "group-writable — the mode ~/.paper-search ships with",
    ),
    (0o755, "world-readable"),
    (0o750, "group-readable"),
    (0o770, "group-writable"),
];

/// File modes that must cause a fail-closed refusal on load.
pub const UNSAFE_FILE_MODES: &[(u32, &str)] = &[
    (0o666, "world-writable"),
    (0o664, "group-writable"),
    (0o644, "world-readable"),
    (0o640, "group-readable"),
    (0o604, "world-readable via other"),
];

/// The only acceptable modes.
pub const SAFE_DIR_MODE: u32 = 0o700;
pub const SAFE_FILE_MODE: u32 = 0o600;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Assert a rendered string carries no secret material. Takes the canary plus a
/// caller-supplied extra list so callers can add their own generated secrets.
///
/// Panics with the *context* and never with the offending text, so the canary
/// cannot end up in CI logs by way of a failure message.
pub fn assert_no_secrets(rendered: &str, context: &str, extra: &[&str]) {
    if rendered.contains(COOKIE_CANARY) {
        panic!("{context}: output contains the cookie canary value");
    }
    for needle in extra {
        if !needle.is_empty() && rendered.contains(needle) {
            panic!("{context}: output contains secret material");
        }
    }
}

/// Assert a URL rendered for logs or provenance carries no query or fragment.
/// SSO chains put one-time tokens there (CAS `ticket`, some SAML bindings), so
/// "provenance without tokens" is only true if these are stripped.
pub fn assert_url_redacted(rendered: &str, context: &str) {
    if rendered.contains('?') {
        panic!("{context}: rendered URL retains a query string");
    }
    if rendered.contains('#') {
        panic!("{context}: rendered URL retains a fragment");
    }
    for token in ["ticket=", "SAMLResponse=", "code=", "state=", "id_token="] {
        if rendered.contains(token) {
            panic!("{context}: rendered URL retains an SSO token parameter");
        }
    }
}
