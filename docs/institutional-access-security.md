# Institutional Access — Threat Model and Security Design

Status: design of record for the browser-mediated institutional authentication and
authorized PDF retrieval subsystem in `paper-search`.

Audience: the operator running this MCP server, and any reviewer auditing the
credential boundary.

This document states what is protected, what is *not* protected, and which
capabilities are implemented versus deferred. Where a control is not implemented,
it says so rather than implying coverage.

---

## 1. What this subsystem does

After a user completes their university login and MFA **in a real browser**,
`paper-search` can reuse the resulting institutional web session to retrieve
**individually requested** licensed papers.

It does not, and must not:

- accept or store a university username, password, OTP, or MFA token;
- read the user's everyday browser cookie or credential database;
- bypass DRM, CAPTCHAs, MFA, access controls, or paywalls the user's institution
  does not license;
- crawl, enumerate, or bulk-download from publishers.

Institutional access is a **fallback**. The open-access path (arXiv, Unpaywall,
Europe PMC, DOAJ, …) and the zero-secret link handoff tool
(`get_institutional_access_url`) are tried first and are unchanged by this work.

---

## 2. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Institutional session cookies | Bearer-equivalent. Anyone holding them acts as the user against the proxy and every licensed publisher behind it. | Encrypted store under `PAPER_SEARCH_DATA_DIR` |
| Store encryption key | Decrypts the above. | OS secret service (gnome-keyring / `org.freedesktop.secrets`) |
| University credentials & MFA factors | Account takeover, not merely library access. | **The user's browser only. Never in scope for this system.** |
| Retrieved PDFs | Licensed content; redistribution violates publisher terms. | Under the configured download root |
| Session metadata (institution, domains, expiry) | Low sensitivity; safe to surface. Stored as authenticated **cleartext** in the envelope header, since it is the AEAD's additional authenticated data. | Store envelope header; reported in status |

The credentials row is the important one. The design's central claim is that a
compromise of `paper-search` costs the user a **revocable library session**, never
their university account.

---

## 3. Trust boundaries

```
 ┌──────────────────────────────────────────────────────────────┐
 │ USER + BROWSER    credentials, MFA, IdP session              │
 │  ── never crosses downward ─────────────────────────────────┐│
 └───────────────────────┬──────────────────────────────────────┘
                         │ user-initiated, out-of-band
 ┌───────────────────────▼──────────────────────────────────────┐
 │ USER'S MANUAL EXPORT                                         │
 │ the human writes a Netscape cookie file to a fixed 0600 path │
 │ inside a 0700 staging directory the server named. No agent   │
 │ and no `paper-search` code participates in this step.        │
 └───────────────────────┬──────────────────────────────────────┘
                         │ file on disk, path only
 ┌───────────────────────▼──────────────────────────────────────┐
 │ MCP SERVER  reads the staged file, scope-filters, seals it   │
 │ under a keyring-held key, deletes the plaintext; later       │
 │ decrypts in memory for ONE bounded fetch                     │
 └───────────────────────┬──────────────────────────────────────┘
                         │ metadata only — counts, domains, expiry
 ┌───────────────────────▼──────────────────────────────────────┐
 │ LLM CONTEXT   ** NO SECRET MATERIAL, EVER **                 │
 └──────────────────────────────────────────────────────────────┘
```

Two boundaries carry the whole design:

**B1 — credentials never descend past the browser.** Enforced structurally: no
code path anywhere accepts a password or OTP.

**B2 — secrets never ascend into LLM context.** Enforced structurally, not by
redaction: the secret type has no `Serialize` implementation, so a cookie value
in an MCP result is a compile error rather than a review finding.

Redaction-based approaches were rejected. Redaction fails open — one forgotten
field and the secret ships. Absence of a serializer fails closed.

---

## 4. Architectures considered

Both collaborators modelled these independently and converged on the same answer.

### 4.1 Architecture A — persistent browser profile driven over CDP

A dedicated non-default browser profile is kept alive; retrieval is brokered
inside that browser.

Advantages: cookies never enter our address space; `HttpOnly`, `SameSite`,
partitioned and JS-bound sessions all work; SAML/Shibboleth redirect chains and
JS interstitials are handled natively by a real browser.

Why it is **not** the primary design:

- **The debugging channel is a full-compromise primitive.** `--remote-debugging-port`
  exposes total browser control — cookie exfiltration and arbitrary script
  execution as the authenticated user — to any local process, and historically to
  remote pages via DNS rebinding against `127.0.0.1`. Adding that channel is a
  *worse* exposure than the one we set out to close. Only `--remote-debugging-pipe`
  (file-descriptor based, no socket) is acceptable, and Firefox has no equivalent.
- **A resident authenticated browser under LLM influence amplifies indirect prompt
  injection.** Fetched page content could steer navigation while carrying the
  user's institutional identity.
- **At-rest protection is unverifiable.** We cannot reliably prove what a given
  Chromium build did with the profile. On Linux its cookie key comes from the same
  secret service we use — no better than our own store, and not attestable.
- Deterministic offline testing is impractical; a browser dependency is heavy.

### 4.2 Architecture B — browser handoff to an encrypted, scoped cookie jar

The user authenticates in a browser and hands off only the cookies within the
configured institutional scope. The server scope-filters them, seals them under a
keyring-held key, and writes the store, then decrypts in memory for a single
bounded `reqwest` fetch.

Advantages: the browser need not stay open; SSRF, redirect, size and content
controls are ordinary auditable Rust; every control is testable offline.

Accepted limitations — stated plainly, not designed around:

- An HTTP client cannot reproduce JS-bound, device-bound, or partitioned sessions.
  Some publishers will simply not work this way. The correct response is to fall
  back to the link handoff tool, not to escalate capability.
- A stored cookie is replayable by anyone who obtains both the ciphertext and the
  keyring key.

### 4.3 Variants rejected outright

| Variant | Verdict |
|---|---|
| User pastes cookie values into an MCP tool argument | **Disqualified.** Tool arguments and results *are* LLM context by construction. Violates B2 directly. Also disqualified in "opaque blob" form. |
| Loopback endpoint the browser POSTs cookies to | Not feasible. Browsers do not release cross-site cookies to `127.0.0.1`; it would require shipping an extension. |
| Parsing the user's real Chromium/Firefox cookie SQLite DB | **Forbidden.** This is browser-credential-database scraping. Not implemented under any flag. |

### 4.4 Reconciled decision

Architecture **B**. The store and the retriever are written so that neither
depends on how the cookies arrived — the sealed jar is the only thing they see —
which is what keeps every control testable offline. To be precise about what
exists today: there is **no acquisition trait or plugin interface**. There is one
implemented path, the staged file import below, and M2 is a future design seam
that could be added without touching the store or the retriever.

- **M1 — staged file import (implemented; always available, no new dependencies).**
  `start_institutional_session` creates a 0700 staging directory containing a
  randomly-named request and tells the user the **exact** path to write to. The
  user exports a Netscape-format cookie file there out-of-band and calls
  `complete_institutional_session` with only the `request_id`. No filesystem path
  and no cookie value is ever supplied by the caller.
  A server-chosen fixed destination was chosen over accepting an arbitrary import
  path specifically because completion both reads *and deletes* the file: an
  attacker-chosen path would have been an arbitrary-file-read oracle and an
  arbitrary-file-delete primitive.
- **M2 — dedicated ephemeral browser profile via CDP over `--remote-debugging-pipe`
  (design seam only; NOT implemented).** Reading *our own* purpose-built profile
  through a supported API would not be credential-database scraping. It is not
  built: the store and retriever are deliberately independent of how cookies were
  acquired, so it can be added without touching either. Nothing in the shipped
  system launches, drives, or requires a browser process.

Architecture A remains a documented seam. It is **not implemented**.

---

## 5. Adversaries and controls

### T1 — A malicious or prompt-injected LLM tries to exfiltrate the session

The realistic and primary threat. The LLM drives the tools, and page content it
reads may be attacker-authored.

- Secret type has no `Serialize`; cookie values in a tool result do not compile.
- `Debug` renders `<redacted>`; no `Display`.
- No tool accepts or returns cookie material in any encoding.
- The login and the cookie export are performed by the user, out-of-band; no
  agent and no `paper-search` code takes part in them. **This is not a separate
  companion process, and it does not mean cookie values never reach the server.**
  `complete_institutional_session` reads the staged file into the MCP server's
  memory in order to scope-filter and seal it, then zeroizes. What holds is
  narrower and is the property that matters: cookie values never appear in a tool
  argument or a tool result, so they never enter LLM context.
- Retrieval returns metadata only. PDF bytes are never echoed into context, which
  also denies a prompt-injection channel through document content.
- Every logged and reported URL is reduced to scheme + host + path.

### T2 — SSRF via a crafted target URL

The LLM chooses URLs; those URLs may originate in attacker-controlled text.

- HTTPS only, port 443 only, at **every hop**.
- Resolve, validate every resolved address, then **pin** it for the request.
  Validating and then letting the HTTP client re-resolve is a DNS-rebinding hole;
  pinning is what actually closes it.
- Denied: loopback, `10/8`, `172.16/12`, `192.168/16`, `169.254/16` (including the
  `169.254.169.254` cloud-metadata address), `100.64/10`, `0.0.0.0/8`, multicast,
  broadcast, reserved, `::1`, `fc00::/7`, `fe80::/10`.
- IPv6 forms that embed IPv4 — `::ffff:0:0/96` mapped, `64:ff9b::/96` NAT64,
  `2002::/16` 6to4 — are unwrapped and the embedded v4 re-checked. Checking only
  the v6 form is a bypass.
- **Host confinement.** Under EZProxy the rewritten host is a subdomain of the
  proxy host, so every hop must fall within the configured proxy's registrable
  domain or an explicit operator-configured publisher allowlist. This is the
  strongest single control here: it bounds reachable hosts to the user's own
  library infrastructure.

### T3 — Redirect abuse

- Manual redirect handling, maximum 5 hops, full re-validation at each.
- Cookies are never attached across a registrable-domain change.
- Provenance records host, path, and status per hop — never query or fragment,
  which in CAS and some SAML bindings carry one-time tokens.

### T4 — Malicious or oversized response

- Size cap enforced on the **byte stream** as it arrives — that is the
  authoritative bound. `Content-Length`, when present and already over the limit,
  is additionally used to reject early, but it is never *trusted* as the bound: a
  server that understates or omits it still hits the streaming cap.
- `Content-Type` must be `application/pdf`, or `application/octet-stream` with a
  valid magic number.
- `%PDF-` required at offset 0, strictly.
- An HTML body means a login page or a denial: report expired/unauthorized, save
  nothing. No meta-refresh following, no JS execution.

### T5 — Path traversal and filesystem attacks on the download root

- Download root canonicalized on each persistence, immediately before the
  confinement check, so the check applies to the path actually being written.
- Filenames derived from DOI + SHA-256 by default. A caller-supplied filename is
  also accepted, but only after strict validation — parent-directory components,
  separators, NUL, control characters, leading dots and overlong names are all
  rejected, and anything else outside `[A-Za-z0-9._-]` is replaced. What is never
  used is `Content-Disposition`, which is attacker-controlled.
- Resolved parent canonicalized and asserted under the root; symlinked components
  rejected.
- Files created `create_new(true).mode(0o600)`, so a pre-placed file or symlink
  swap **errors** rather than being followed or overwritten.

### T6 — Local attacker with filesystem access

Honest limit: an attacker running **as this user** with an unlocked keyring can
obtain the session. No userspace design prevents that; it is the same footing as
the user's own browser. What is defended:

- Secrets live under `PAPER_SEARCH_DATA_DIR`, never in the repository. Startup
  refuses if that path resolves inside the git worktree.
- Secret directory 0700, secret files 0600, created with the right mode rather
  than `chmod`-ed afterward (which is a race).
- **Fail closed on read**: wrong permissions means refuse to load and report
  `insecure_permissions`. Never silently repair — silent repair hides tampering.
- `PAPER_SEARCH_DATA_DIR` itself must be 0700 and owned by the user, and so must
  the 0700 subdirectory created beneath it. Both are enforced. A group-writable
  parent would permit a rename-swap against our directory that a child-only check
  could not detect, so the parent is checked too. On this machine `~/.paper-search`
  is 0775, which means the session lifecycle is **disabled** until the operator
  runs `chmod 700` — an honest refusal rather than a silent downgrade.
- The download root must likewise be 0700 and owned by the user.
- Atomic write: temp file in the same directory at 0600, fsync, rename, fsync dir.
- Never accept cookie material through argv or environment — both are readable via
  `/proc/PID/environ` and shell history.

### T7 — Bulk downloading / terms-of-service violation

Not a confidentiality threat but a real risk to the user's library account, and an
LLM loop can cause it without malice.

- A global lock permits exactly one retrieval in flight.
- Minimum interval between fetches, plus a per-hour ceiling.
- One explicitly requested paper per call. No crawl, enumerate, or batch entry point.
- Institutional access is a fallback, so open-access routes absorb most traffic.

### T8 — Stale or over-broad sessions

- Per-institution and per-domain scoping; out-of-scope cookies are dropped at import.
- Expired entries dropped on load.
- Cookies with no explicit expiry get a bounded maximum TTL. Proxy sessions are
  short-lived; an indefinite session cookie is a liability.
- Explicit deletion tool removes ciphertext and keyring entry together.

### T9 — Cryptographic failure

- XChaCha20-Poly1305, random 24-byte nonce — chosen over AES-GCM for its lack of a
  nonce-reuse cliff.
- Random 32-byte key, generated by the server during
  `complete_institutional_session` and held in the OS secret service. The key is
  never stored beside the ciphertext.
- AAD binds format version, institution id, and store purpose, so a jar cannot be
  replayed into a different scope.
- Protection is reported as one of three values: `os_keyring`,
  `os_keyring_locked`, and `os_keyring_unavailable`. **Locked** is distinguished
  because unlocking is a different operator action; a **missing key** and a
  **keyring error** are both grouped under `unavailable`, since the remedy is the
  same and the underlying platform errors cannot be told apart reliably. An
  admitted grouping is preferable to a distinction that would often be wrong.
- If the keyring is unavailable, the operation is refused and reported. **There is
  no file-backed key fallback at all** — not even opt-in. This was considered and
  deliberately dropped: fewer states, and no configuration that downgrades the
  protection.
- **No `paper-search` code path writes cookie plaintext to disk.** The one
  cleartext copy that exists is the export the *user* writes during the handoff;
  the server deletes it on success and reports it in status when it lingers.

---

## 6. Residual risks (accepted, not mitigated)

1. **Local user compromise ends the game.** An attacker executing as this user with
   an unlocked keyring gets the session. Out of scope for userspace mitigation.
2. **A stored cookie is a bearer token.** Ciphertext plus keyring key equals access.
   Mitigated only in depth: short TTLs, tight scope, easy revocation.
3. **The keyring is unlocked for the whole desktop session.** Any process of this
   user can request our key from the secret service. gnome-keyring offers no
   per-application isolation on Linux.
4. **The handoff leaves one plaintext copy on disk**, written by the user's own
   export, and the server holds plaintext cookies in memory while sealing them.
   The file is deleted on success and reported by status when it lingers, but
   deletion is an ordinary `unlink`: it is **not** a secure wipe, and on an SSD
   wear levelling means residual data may survive. Memory is zeroized after use,
   but a debugger or core dump within that window sees the values.
5. **HTTP-client sessions cannot cover every publisher.** JS-bound, device-bound,
   or partitioned sessions will fail. The fallback is the link handoff tool, by
   design — not capability escalation.
6. **Host confinement depends on operator configuration.** A misconfigured or
   overly broad publisher allowlist weakens T2's strongest control.
7. **Terms of service are enforced by rate limiting and intent, not by proof.** The
   system cannot verify that a given paper falls under the user's license. It
   retrieves only what is explicitly requested and never probes access.
8. **`Content-Length`-independent size capping still buffers up to the cap.** A
   hostile server can force allocation up to that bound per request; serialized
   retrieval keeps this to one at a time.
9. **Strict 0700 enforcement trades availability for safety.** The data directory
   and the download root must both be 0700 and user-owned, so a default 0775
   `~/.paper-search` or a conventional 0755 `~/Downloads` disables the feature
   until the operator intervenes. This is the intended trade — the failure is
   loud and documented rather than a quiet downgrade — but it is a real
   operational cost, and an operator who does not read the runbook will read it
   as a bug.
10. **A git repository anywhere above the data directory disables the feature.**
   The repo check walks ancestors looking for `.git`. Users who version-control
   their home directory (yadm, bare-repo dotfiles) have `~/.git`, which places
   the default `~/.paper-search` inside a repository and refuses it. Correct
   behaviour — secrets must not sit in a worktree — but the remedy is to move
   `PAPER_SEARCH_DATA_DIR`, not to disable the check.
11. **Revocation is local only.** Clearing the store destroys our copy of the
   session; it does not end the session at the institution. Only a browser logout
   or proxy-side expiry does that.
12. **Deprecated and exotic embedded-IPv4 forms.** Teredo (`2001:0::/32`) and
   RFC 8215 local-use NAT64 prefixes beyond the well-known `64:ff9b::/96` are not
   unwrapped. IPv4-mapped, IPv4-compatible, well-known NAT64 and 6to4 all are.
13. **The `confirmed_*` retrieval parameters are intent declarations, not
   enforcement.** The model supplies them and could always set them true. The
   controls that are genuinely enforced are host confinement, the SSRF and
   content checks, and rate limiting. The server-side open-access lookup is
   enforced only when a DOI is supplied *and* Unpaywall is configured; otherwise
   open-access-first rests on the caller's declaration alone.
14. **Rejected attempts consume rate-limit capacity.** Attempts are recorded
   before target validation. This discourages address probing, but repeated bad
   requests can temporarily deny legitimate retrievals in the same server
   process.
15. **Keeping licensed PDFs out of version control is a configuration property,
   not an enforced one.** The no-repository rule is enforced for
   `PAPER_SEARCH_DATA_DIR`, which holds secrets. It is deliberately *not*
   enforced for the download root, because storing papers alongside the project
   that cites them is a legitimate workflow and the operator is better placed to
   judge it. The consequence is that if you point the download root inside a git
   worktree, only that repository's `.gitignore` stops licensed content from
   being committed and redistributed.
   Every file this system writes there is either `*.pdf` — `safe_filename`
   guarantees the extension, so a glob on `*.pdf` cannot be sidestepped by a
   generated name — or a `*.provenance.json` sidecar. The sidecars are safe to
   track: query strings, fragments, and userinfo are stripped from every URL they
   record, so no SSO ticket or one-time token can reach git through them.
   If your download root is inside a repository, confirm the ignore rule covers
   `*.pdf` in that directory before the first retrieval.

---

## 7. Implemented vs. deferred

Verified against the implementation during joint review. Deferred items report
their unavailability at runtime rather than silently no-opping.

| Capability | Status | Requires |
|---|---|---|
| `get_institutional_access_url` (zero-secret link handoff) | Pre-existing, preserved | nothing |
| Open-access retrieval path | Pre-existing, unchanged | nothing |
| Encrypted scoped cookie store (XChaCha20-Poly1305) | Implemented | OS keyring; no fallback |
| M1 staged-file acquisition | Implemented | a manual out-of-band cookie export by the user |
| M2 ephemeral-profile CDP acquisition | **Not implemented** (seam only) | would need a live browser companion |
| Bounded authorized retrieval | Implemented | a valid stored session |
| Server-side revocation at the institution | **Not possible** | the user must log out in the browser |
| Architecture A resident CDP broker | **Not implemented** | — |
| Reading the user's real browser cookie DB | **Forbidden by design** | — |

---

## 8. Operator notes

- Secrets live under `PAPER_SEARCH_DATA_DIR` (default `~/.paper-search`), never in
  the repository. Do not relocate it into a project directory.
- **`PAPER_SEARCH_DATA_DIR` must itself be mode 0700 and owned by you — this is
  enforced, not advisory.** `~/.paper-search` is 0775 on this machine, so the
  session lifecycle is disabled until `chmod 700` is run. The download root must
  likewise be 0700.
- An OS keyring is required by default. Under SSH without a session bus, expect an
  honest `unavailable` status rather than degraded operation.
- Authentication is user-mediated. `start_institutional_session` returns a login
  URL and a destination path and **spawns nothing** — no browser, no companion
  process. The human logs in and exports the cookie file themselves.
- Sessions are short-lived by design. Repeating the login-and-export handoff is
  the normal path, not an error condition.
- **MCP servers do not hot-reload.** Any already-running client session continues
  using the previously loaded binary; restart the client to pick up changes.
