# Institutional Access — Operator Instructions

Companion to [`institutional-access-security.md`](./institutional-access-security.md),
which carries the threat model and the reasoning. This document is the runbook.

**Nothing here ever asks you for your university password, OTP, or MFA code. No
part of `paper-search` accepts them. If anything appears to ask, something is
wrong — stop and investigate.**

---

## 0. Before you start

Institutional access is a **fallback**. Try it only after the open-access path has
failed for a specific paper. Most physics literature resolves through arXiv,
INSPIRE, Europe PMC, or Unpaywall, and those routes need none of this.

Prerequisites:

| Requirement | Why | How to check |
|---|---|---|
| A working OS keyring | Holds the encryption key. There is no plaintext fallback by design. | `busctl --user list \| grep org.freedesktop.secrets` |
| `PAPER_SEARCH_DATA_DIR` outside any git repository | Keeps secrets out of version control; the session lifecycle refuses otherwise. | `echo ${PAPER_SEARCH_DATA_DIR:-$HOME/.paper-search}` |
| `PAPER_SEARCH_DATA_DIR` at mode `0700`, owned by you | **Enforced.** Session tools are disabled until this holds. | `stat -c '%a %U' ${PAPER_SEARCH_DATA_DIR:-$HOME/.paper-search}` |
| A `0700` download directory | **Enforced.** Created automatically at the default location; refused at any other mode if you override it. | `stat -c '%a' $PAPER_SEARCH_INSTITUTION_DOWNLOAD_DIR` |
| Your library's proxy login endpoint | Scopes every cookie and every network hop. | Your library's off-campus access page |
| A real browser | Authentication is user-mediated and happens only here. | — |

On this machine gnome-keyring is running and owns `org.freedesktop.secrets`, so
the keyring prerequisite is met.

---

## 1. Configuration

```bash
export PAPER_SEARCH_INSTITUTION_NAME="Indiana University Bloomington"
export PAPER_SEARCH_LIBRARY_PROXY_URL="https://proxyiub.uits.iu.edu/login"
```

That is the whole required configuration. The implementation is
institution-generic; the IU values above are an example. Any EZProxy-style
`https://<host>/login?url=<target>` endpoint works.

Everything else has a working default, verified against the code:

| Variable | Default | Bounds |
|---|---|---|
| `PAPER_SEARCH_LIBRARY_PROXY_TARGET_PARAMETER` | `url` | — |
| `PAPER_SEARCH_INSTITUTION_ALLOWED_HOSTS` | the proxy URL's host | comma-separated; bare public suffixes rejected |
| `PAPER_SEARCH_INSTITUTION_DOWNLOAD_DIR` | `<data dir>/downloads/institutional` | must be `0700`, owned by you |
| `PAPER_SEARCH_INSTITUTION_SESSION_TTL_SECONDS` | `43200` (12 h) | 60 – 86400 |
| `PAPER_SEARCH_INSTITUTION_MAX_PDF_BYTES` | `52428800` (50 MiB) | 1 KiB – 100 MiB |
| `PAPER_SEARCH_INSTITUTION_MIN_INTERVAL_SECONDS` | `30` | 1 – 3600 |
| `PAPER_SEARCH_INSTITUTION_HOURLY_LIMIT` | `10` | 1 – 60 |

Out-of-range values are clamped to the bounds rather than accepted. The redirect
limit is fixed at 5 and is not configurable.

**The download directory default lives under `PAPER_SEARCH_DATA_DIR` and is created
`0700` automatically.** Prefer it. If you override it to somewhere conventional
like `~/Downloads`, retrieval will refuse the directory unless it is `0700`.

Two rules the server enforces on this configuration:

- The proxy host must have at least two labels. A single-label value such as
  `edu` would scope your session cookies to every `.edu` host on the internet.
- **Never** put cookie material in an environment variable. Environment is
  readable through `/proc/<pid>/environ` and leaks into shell history. No
  configuration variable accepts a secret.

Verify with the `list_sources` tool: the `institutional_access` row shows whether
the proxy is configured.

---

## 2. Directory permissions — required, and enforced

**Do this before anything else, or the session tools will not work.**

```bash
chmod 700 "${PAPER_SEARCH_DATA_DIR:-$HOME/.paper-search}"
```

If you overrode the download directory, create it privately too:

```bash
mkdir -m 700 -p "$PAPER_SEARCH_INSTITUTION_DOWNLOAD_DIR"
```

Both are enforced, and both fail closed:

- **`PAPER_SEARCH_DATA_DIR` must be `0700` and owned by you.** A group- or
  world-writable parent would let another account rename our directory aside and
  substitute one of their own, which then passes every check further down. The
  server refuses rather than silently changing a directory you own.
- **The download directory must be `0700`.** An existing `~/Downloads` or
  `~/papers` at the usual `0755` will be **refused**. Use a dedicated directory
  created with `mkdir -m 700` — retrieved papers are licensed content and are
  stored accordingly.

On this machine `~/.paper-search` ships as `0775`, so **the institutional session
lifecycle is disabled until you run the `chmod` above.** This is deliberate: the
alternative is silently operating with a weaker guarantee than the documentation
claims.

---

## 3. Authenticating — the normal flow

Four tools, in order. Authentication happens in **your browser**; the server
never sees a credential.

### Step 1 — prepare

Ask for `start_institutional_session` with the DOI or publisher URL you need.
This **spawns nothing** — no browser, no background process. It creates a private
0700 staging directory and returns:

- `authentication_url` — the proxy login link to open;
- `cookie_export_path` — where to put the export;
- `request_id` — needed to finish;
- `request_expires_at` — roughly 15 minutes out.

### Step 2 — log in

Open `authentication_url` in a real browser. Complete your university login and
MFA normally. You should land on the requested resource through the proxy.

### Step 3 — export the session cookies

Out-of-band, entirely under your control. There is no companion program and no
command to run: `paper-search` takes no part in this step. Export **only** the
cookies for your proxy domain, in Netscape cookie-file format, to the exact
`cookie_export_path` you were given, then:

```bash
chmod 600 <cookie_export_path>
```

The server **refuses** the file if it is not mode `0600`, not a regular file, not
owned by you, or a symlink. This is deliberate: a readable cookie file is a
readable session.

Any cookie-export mechanism you trust works — a `cookies.txt` browser extension
or a devtools export. Choosing one is your decision; `paper-search` takes no part
in it and only ever reads the path it told you about.

> **Do not paste cookie values into chat, into a tool argument, or into any
> agent.** The only supported channel is this file. A tool that accepted cookie
> values would put them in an LLM's context, which is the exact exposure this
> whole design exists to prevent.

### Step 4 — complete

Ask for `complete_institutional_session` with the `request_id`. The server:

1. re-validates the export's ownership and permissions;
2. parses it and keeps only cookies inside your configured scope;
3. caps expiry at the configured maximum TTL;
4. generates a fresh random key, stores it in your OS keyring, and encrypts the
   cookies under it with XChaCha20-Poly1305;
5. writes the store atomically at `0600`;
6. deletes the plaintext export;
7. returns **metadata only** — counts, domains, expiry. Never values.

---

## 4. Retrieving a paper

`retrieve_institutional_pdf`, one paper per call, explicitly requested.

**Open access is tried first — but read the precondition.** When you supply a
`doi` *and* `UNPAYWALL_EMAIL` is configured, the server performs a real
open-access lookup itself and returns that URL instead of using your session.
That case is genuinely enforced server-side.

Without a DOI, or without Unpaywall configured, **no automatic check happens**
and open-access-first rests entirely on the caller's
`confirmed_open_access_unavailable` declaration — which is an assertion of intent,
not something the server verifies. Supply a DOI and set `UNPAYWALL_EMAIL` if you
want the enforced behaviour.

Applied to every request:

- HTTPS and port 443 only, on every hop;
- resolved addresses validated as publicly routable, then pinned for the request;
- every hop confined to your proxy's domain or a configured publisher allowlist;
- at most 5 redirects, fully re-validated each time;
- bounded response size and timeout;
- `Content-Type` **and** `%PDF-` magic bytes both checked;
- destination confined beneath the download root, with a strictly validated
  caller filename or a DOI/SHA-256-derived fallback, created `0600` and failing
  rather than overwriting;
- one retrieval at a time, with a minimum interval and an hourly ceiling.

You get back the path, SHA-256, size, source DOI/URL, timestamp, and a redirect
summary with query strings stripped — SSO chains carry one-time tokens there.

### If retrieval fails

| Result | Meaning | What to do |
|---|---|---|
| No session | Nothing stored | Run the flow in §3 |
| Session expired / rejected | Proxy no longer accepts it | Re-authenticate. Normal; sessions are short |
| Authenticated but not licensed | Your institution does not license this | **Stop.** Do not retry. Try interlibrary loan |
| Not a PDF | An HTML login or error page came back | Usually an expired session; re-authenticate once |
| Host not allowed | Target outside your proxy's domain | Expected for non-institutional URLs |

Retrying the "not licensed" case is the one behaviour to avoid — it looks like
paywall probing to a publisher and can get your library account flagged.

---

## 5. Checking status

`institutional_session_status` returns no secret material — state, protection
status, cookie count, domains, expiry.

| `protection` | Meaning | Action |
|---|---|---|
| `os_keyring` | Normal | none |
| `os_keyring_locked` | Keyring present but locked | Unlock it in your desktop session |
| `os_keyring_unavailable` | No secret service reachable | Common over plain SSH. Use a desktop session |

Status also reports whether a **plaintext cookie export** is still sitting on
disk, and how old it is. If it says one is present, clear it. That field is
reported in every state, including a healthy one, so a forgotten export cannot go
unnoticed.

---

## 6. Revoking

`clear_institutional_session` deletes the encrypted store, purges staged exports,
and attempts to remove the keyring key. Local filesystem state is purged and
recreated even when permissions have drifted; if the keyring entry cannot be
deleted, that is reported honestly rather than hidden — the ciphertext is already
gone, so the orphaned key is inert, but you should remove it yourself if you care.

Clearing local state does **not** end the session at your university. To do that,
log out in the browser or let the proxy session expire.

Clear when: you are finished, you are leaving the machine, the status reports
unsafe permissions or a corrupt store, or you suspect any compromise.

---

## 7. What is implemented, and what is not

| Capability | Status |
|---|---|
| Zero-secret link handoff (`get_institutional_access_url`) | Implemented, unchanged |
| Open-access retrieval | Implemented, unchanged, tried first |
| Encrypted scoped cookie store | Implemented — requires OS keyring |
| Browser-handoff acquisition via staged file export | Implemented — requires a manual out-of-band export by you |
| Bounded authorized retrieval | Implemented |
| Automated cookie capture from a managed browser | **Not implemented.** Would need a live browser companion; the design seam exists |
| Resident CDP browser broker | **Not implemented.** Rejected; see the security document |
| Reading your everyday browser's cookie database | **Never.** Forbidden by design |
| Plaintext fallback when the keyring is missing | **Never.** Reports unavailable instead |

Two capabilities need something this software cannot supply on its own: a working
**OS keyring** (no plaintext fallback exists, not even opt-in) and a **manual
cookie export** (there is no supported way to capture cookies from your everyday
browser without either scraping its credential database or shipping an extension —
the security document explains why both were rejected).

There is no `paper-search institution-login` command and no companion process.
The whole handoff is: MCP `start` → you export the file yourself → MCP `complete`.

---

## 8. Operational cautions

- **MCP servers do not hot-reload.** An already-running client keeps using the
  binary it started with. Restart the client to pick up a new build. A session
  that was running before an upgrade will not see new tools.
- **Sessions are short-lived.** Re-authenticating is the normal path, not a fault.
- **Deleting the plaintext export is a normal `unlink`.** It is not a secure
  wipe, and on an SSD, wear levelling means residual data may persist. Treat any
  export as compromised material if the disk is. No part of this system claims to
  shred anything.
- **One paper at a time, on purpose.** The rate limit is what keeps automated use
  from looking like a crawler to a publisher. Do not work around it.
- **If your download root is inside a git repository, check the ignore rule.**
  Nothing in the software stops licensed PDFs from being committed — only your
  `.gitignore` does. Every file written there is either `*.pdf` or a
  `*.provenance.json` sidecar; the sidecars are safe to track (all URLs have
  query strings and fragments stripped), but the PDFs are licensed content and
  must not be redistributed. Confirm with
  `git check-ignore -v <download dir>/test.pdf` before your first retrieval.
- **Publisher and university terms still apply.** This tool retrieves what you are
  already licensed to read. It does not bypass DRM, CAPTCHAs, MFA, or access
  controls, and it will not obtain anything your institution does not license.
- **The store is per-institution and machine-local.** It is not synced, not
  shared between projects, and not portable — the keyring key does not travel
  with the file.

---

## 9. Troubleshooting

**"storage path is not allowed"** — `PAPER_SEARCH_DATA_DIR` resolves inside a git
repository. Move it outside. Note this also triggers if you version-control your
home directory (yadm, bare-repo dotfiles), because `~/.git` then puts the default
`~/.paper-search` inside a worktree. Point `PAPER_SEARCH_DATA_DIR` somewhere
outside the repository rather than disabling the check.

**"unsafe destination" on download** — the download directory must be `0700` and
owned by you. Create it with `mkdir -m 700 -p "$PAPER_SEARCH_INSTITUTION_DOWNLOAD_DIR"`;
an existing `0755` directory such as `~/Downloads` will be refused.

**"insecure permissions"** — something changed the mode of the store directory or
file. This is a fail-closed refusal and is never repaired silently, because
silent repair would erase evidence of tampering. Inspect first, then
`clear_institutional_session` and re-authenticate.

**"cookie export is invalid"** — not Netscape format, or a malformed line. Re-export.

**"no usable cookies in the configured scope"** — the export had no cookies for
your proxy domain. Usually means the wrong domain was exported, or the login did
not complete. Check `PAPER_SEARCH_LIBRARY_PROXY_URL`.

**"authentication request is invalid or expired"** — more than ~15 minutes
elapsed. Start again.

**Keyring unavailable over SSH** — expected. The secret service belongs to a
desktop login session. Use a desktop session, or accept that institutional
access is unavailable there. There is no plaintext fallback.
