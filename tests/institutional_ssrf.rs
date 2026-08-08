//! Adversarial SSRF tests for institutional retrieval.
//!
//! Owned by the security reviewer. These attack the address validator directly
//! with the full corpus in `tests/common`, including the IPv6 forms that embed
//! an IPv4 address — the ones a validator built only on textual IPv4 matching,
//! or only on `to_ipv4_mapped()`, silently lets through.

mod common;

use paper_search::institutional::retrieval::is_prohibited_ip;
use std::net::IpAddr;

/// Every address in the blocked corpus must be refused.
///
/// Failures are collected and reported together: one run should tell you the
/// whole gap, not just the first hole.
#[test]
fn all_prohibited_addresses_are_blocked() {
    let mut escaped = Vec::new();

    for (literal, why) in common::BLOCKED_ADDRESSES {
        // Some corpus entries are alternate textual encodings (octal, decimal,
        // hex shorthand) that `IpAddr::from_str` deliberately refuses. Those are
        // rejected earlier, at URL parsing, so they are not this validator's
        // job. Only entries that parse as an address are its responsibility.
        let Ok(address) = literal.parse::<IpAddr>() else {
            continue;
        };
        if !is_prohibited_ip(address) {
            escaped.push(format!("  {literal} — {why}"));
        }
    }

    assert!(
        escaped.is_empty(),
        "these addresses were NOT blocked by the SSRF validator:\n{}",
        escaped.join("\n")
    );
}

/// The validator must not be trivially correct by blocking everything: a
/// denylist that refuses all traffic passes the negative corpus and breaks the
/// product. Publicly routable addresses must still be allowed.
#[test]
fn publicly_routable_addresses_are_allowed() {
    for literal in common::ALLOWED_ADDRESSES {
        let address: IpAddr = literal.parse().expect("corpus address parses");
        assert!(
            !is_prohibited_ip(address),
            "{literal} is publicly routable and must not be blocked"
        );
    }
}

/// Called out separately from the bulk test because these are the specific
/// bypasses that motivated the requirement. IPv6 has several ways to express an
/// IPv4 address, and each must be unwrapped and re-checked against the IPv4
/// rules rather than pattern-matched in its IPv6 form.
#[test]
fn ipv6_forms_embedding_ipv4_are_unwrapped_and_rechecked() {
    let cases = [
        // IPv4-mapped, ::ffff:0:0/96
        ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
        ("::ffff:10.0.0.1", "IPv4-mapped RFC1918"),
        ("::ffff:169.254.169.254", "IPv4-mapped cloud metadata"),
        // IPv4-compatible, ::/96 — NOT unwrapped by `to_ipv4_mapped()`
        ("::127.0.0.1", "IPv4-compatible loopback"),
        ("::169.254.169.254", "IPv4-compatible cloud metadata"),
        ("::10.0.0.1", "IPv4-compatible RFC1918"),
        // NAT64, 64:ff9b::/96
        ("64:ff9b::127.0.0.1", "NAT64 loopback"),
        ("64:ff9b::169.254.169.254", "NAT64 cloud metadata"),
        // 6to4, 2002::/16
        ("2002:7f00:0001::", "6to4 loopback"),
        ("2002:a00:1::", "6to4 RFC1918"),
    ];

    let mut escaped = Vec::new();
    for (literal, why) in cases {
        let address: IpAddr = literal.parse().expect("address parses");
        if !is_prohibited_ip(address) {
            escaped.push(format!("  {literal} — {why}"));
        }
    }

    assert!(
        escaped.is_empty(),
        "embedded-IPv4 IPv6 forms escaped the validator:\n{}\n\
         Each must be unwrapped to its IPv4 address and re-checked. \
         `to_ipv4_mapped()` handles only ::ffff:0:0/96; `to_ipv4()` also \
         handles the IPv4-compatible ::/96 form.",
        escaped.join("\n")
    );
}

/// The cloud metadata endpoint is the single highest-value SSRF target on any
/// hosted machine. Given its own test so a regression is unmissable.
#[test]
fn cloud_metadata_endpoint_is_blocked_in_every_form() {
    for literal in [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "::169.254.169.254",
        "64:ff9b::169.254.169.254",
    ] {
        let address: IpAddr = literal.parse().expect("address parses");
        assert!(
            is_prohibited_ip(address),
            "cloud metadata endpoint reachable as {literal}"
        );
    }
}

/// IPv6 ranges that carry no embedded IPv4 but are still non-public.
#[test]
fn native_ipv6_private_ranges_are_blocked() {
    for literal in [
        "::1",     // loopback
        "::",      // unspecified
        "fc00::1", // unique local
        "fd00::1", // unique local
        "fe80::1", // link-local
        "ff02::1", // multicast
    ] {
        let address: IpAddr = literal.parse().expect("address parses");
        assert!(is_prohibited_ip(address), "{literal} must be blocked");
    }
}

/// Boundary check on each IPv4 range: the addresses just inside a prohibited
/// block must be blocked, and the ones just outside must not be. Off-by-one
/// errors in range arithmetic are the classic way a denylist develops a hole.
#[test]
fn ipv4_range_boundaries_are_exact() {
    let inside = [
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
        "169.254.0.0",
        "169.254.255.255",
        "100.64.0.0",
        "100.127.255.255",
        "127.0.0.0",
        "127.255.255.255",
        "0.0.0.0",
        "0.255.255.255",
        "224.0.0.0",
        "255.255.255.255",
    ];
    for literal in inside {
        let address: IpAddr = literal.parse().expect("parses");
        assert!(is_prohibited_ip(address), "{literal} must be blocked");
    }

    // Immediately outside each prohibited block — these are real public space.
    let outside = [
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "1.0.0.0",
        "223.255.255.255",
    ];
    for literal in outside {
        let address: IpAddr = literal.parse().expect("parses");
        assert!(
            !is_prohibited_ip(address),
            "{literal} is public space and must not be blocked"
        );
    }
}
