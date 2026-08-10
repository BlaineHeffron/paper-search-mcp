# paper-search

`paper-search` is a Rust MCP server for searching, retrieving, and locally indexing scientific papers. It exposes MCP tools over stdio, so agent clients can query multiple scholarly sources through one interface and optionally build a local searchable paper index.

The server uses RMCP 3 and supports MCP `2026-07-28`'s stateless discovery/request
lifecycle while retaining legacy initialize compatibility. The deterministic tool
catalog advertises a five-minute public cache lifetime to modern clients.

## Features

- Federated paper search across arXiv, INSPIRE-HEP, Semantic Scholar, OpenAlex, Crossref, Europe PMC, DOAJ, and NASA ADS, with viXra available as an opt-in source.
- Source filtering, date filtering, and sort modes for relevance, newest first, oldest first, or hybrid ranking.
- Paper metadata lookup by prefixed IDs such as `arxiv:`, `doi:`, `inspire:`, `s2:`, `ads:`, `pmid:`, `doaj:`, `vixra:`, and `openalex:`.
- Citation and reference lookup when the selected source supports it.
- Local indexing with Tantivy full-text search and LanceDB vector storage.
- Open-access PDF discovery through Unpaywall when configured.
- Browser-mediated institutional access links through a configured library proxy. Authentication and MFA remain in the user's browser; the server never accepts or stores university credentials.

## Requirements

- Rust stable
- Network access for live source queries
- Optional API keys or contact emails for higher-rate or gated sources

Some release builds require Protocol Buffers tooling because transitive dependencies compile protobuf definitions.

## Build

```sh
cargo build --release
```

For systems where OpenSSL linkage is inconvenient, build with vendored OpenSSL:

```sh
cargo build --release --features vendored-openssl
```

The binary is named `paper-search`.

## Run

The server speaks MCP over stdio:

```sh
cargo run --release
```

Most MCP clients should be configured to launch the built binary directly. A minimal client command entry looks like this:

```json
{
  "command": "paper-search",
  "args": []
}
```

If you run from a checkout instead of an installed binary, use `cargo run --release` as the command and pass no additional arguments unless your client requires a shell wrapper.

## Configuration

Configuration is read from environment variables.

| Variable | Purpose |
| --- | --- |
| `PAPER_SEARCH_DATA_DIR` | Directory for the local paper index. Defaults to `.paper-search` in the user's home directory. |
| `PAPER_SEARCH_SOURCES` | Optional comma-separated source allowlist, for example `arxiv,inspire,ads`. viXra is disabled by default; include `vixra` in this list to opt in. |
| `SEMANTIC_SCHOLAR_API_KEY` | Optional Semantic Scholar API key. Without it, Semantic Scholar remains enabled but rate-limited. |
| `ADS_API_KEY` | NASA ADS API key. ADS is disabled unless this is set. |
| `OPENALEX_EMAIL` | Optional OpenAlex polite-pool email. |
| `UNPAYWALL_EMAIL` | Enables the `get_pdf_url` tool through Unpaywall. |
| `PAPER_SEARCH_INSTITUTION_NAME` | Optional display name for browser-mediated institutional access. |
| `PAPER_SEARCH_LIBRARY_PROXY_URL` | Institutional proxy login endpoint, such as an EZProxy `/login` URL. Enables `get_institutional_access_url`. |
| `PAPER_SEARCH_LIBRARY_PROXY_TARGET_PARAMETER` | Query parameter used for the destination URL. Defaults to `url`. |
| `PAPER_SEARCH_INSTITUTION_ALLOWED_HOSTS` | Optional comma-separated host allowlist for the authenticated session and every retrieval hop. Defaults to the proxy URL's host. Bare public suffixes such as `edu` are rejected. |
| `PAPER_SEARCH_INSTITUTION_DOWNLOAD_DIR` | Destination for retrieved PDFs. Defaults to `<data dir>/downloads/institutional`. Must be mode `0700` and owned by you. |
| `PAPER_SEARCH_INSTITUTION_SESSION_TTL_SECONDS` | Upper bound on stored session lifetime. Default `43200` (12h), clamped to 60–86400. |
| `PAPER_SEARCH_INSTITUTION_MAX_PDF_BYTES` | Response size cap. Default `52428800` (50 MiB), clamped to 1 KiB–100 MiB. |
| `PAPER_SEARCH_INSTITUTION_MIN_INTERVAL_SECONDS` | Minimum gap between institutional retrievals. Default `30`, clamped to 1–3600. |
| `PAPER_SEARCH_INSTITUTION_HOURLY_LIMIT` | Maximum institutional retrievals per hour. Default `10`, clamped to 1–60. |
| `RUST_LOG` | Logging filter, for example `paper_search=info`. Logs are written to stderr. |

Example with ADS and Unpaywall enabled:

```sh
export ADS_API_KEY="..."
export UNPAYWALL_EMAIL="you@example.com"
export PAPER_SEARCH_SOURCES="arxiv,inspire,ads,openalex,crossref"
paper-search
```

Example enabling viXra:

```sh
export PAPER_SEARCH_SOURCES="arxiv,inspire,crossref,doaj,europepmc,semantic_scholar,openalex,vixra"
paper-search
```

## MCP Tools

`list_sources`
: Returns configured sources and whether each one is available.

`search_papers`
: Searches enabled sources, deduplicates results, and applies ranking. Supports `query`, `sources`, `max_results`, `sort`, `date_from`, and `date_to`.

`get_paper`
: Retrieves metadata for a single paper. Pass a prefixed ID and optionally force a source.

`get_citations`
: Returns papers that cite a given paper when supported by the queried source.

`get_references`
: Returns papers referenced by a given paper when supported by the queried source.

`index_paper`
: Fetches a paper from an API source and stores it in the local index.

`index_from_query`
: Searches a source or the enabled source set, then stores the returned papers in the local index.

`search_local`
: Searches locally indexed papers using `keyword`, `vector`, or `hybrid` mode.

`search_similar`
: Finds locally indexed papers with similar vector embeddings.

`get_pdf_url`
: Looks up an open-access PDF URL for a DOI through Unpaywall. Requires `UNPAYWALL_EMAIL`.

`get_institutional_access_url`
: Creates a library-proxied browser URL from either a DOI or publisher URL. The returned URL must be opened interactively so the user can complete institutional login or MFA. No usernames, passwords, MFA tokens, or browser cookies are accepted by the MCP server.

### Authenticated institutional session (optional)

Four further tools reuse an institutional web session that **you** establish in a
real browser, so that individually requested licensed papers can be retrieved.
They are a fallback. When a `doi` is supplied and `UNPAYWALL_EMAIL` is configured,
`retrieve_institutional_pdf` performs its own open-access lookup and returns that
URL instead of using your session. Without a DOI or without Unpaywall, no
automatic check runs and open-access-first rests on the caller's declaration.

`start_institutional_session`
: Returns a proxy login URL and a private staging path. Spawns nothing.

`complete_institutional_session`
: Takes only a `request_id`. Reads the cookie file you exported, keeps only cookies
  in scope, encrypts them with XChaCha20-Poly1305 under a key held in your OS
  keyring, and deletes the plaintext. Returns metadata only.

`institutional_session_status`
: State, scope, expiry, keyring protection, and whether a plaintext export is
  lingering. Never returns cookie names or values.

`clear_institutional_session`
: Deletes the local ciphertext, staged exports, and the keyring key.

`retrieve_institutional_pdf`
: Retrieves one explicitly requested paper. HTTPS/443 only, SSRF-validated and
  pinned addresses, bounded redirects and response size, content-type plus
  `%PDF-` magic-byte validation, path confinement, and one-at-a-time rate limiting.

**Requirements and limits.** An OS keyring is required — there is no plaintext
fallback. `PAPER_SEARCH_DATA_DIR` and the download directory must both be mode
`0700` and owned by you, and the data directory must not be inside a git
repository; all are enforced and fail closed. Cookies are never accepted through
a tool argument, an environment variable, or a command line — the only channel is
a file you export yourself.

This does not bypass DRM, CAPTCHAs, MFA, access controls, or paywalls your
institution does not license, and it does not read your browser's cookie database.

Read before enabling:

- [Threat model and security design](docs/institutional-access-security.md) —
  architectures considered, controls, and the residual-risk list.
- [Operator instructions](docs/institutional-access-operations.md) — setup, the
  login/export/complete flow, troubleshooting, and what is *not* implemented.

For Indiana University Bloomington, the configuration documented by IU Libraries is:

```sh
export PAPER_SEARCH_INSTITUTION_NAME="Indiana University Bloomington"
export PAPER_SEARCH_LIBRARY_PROXY_URL="https://proxyiub.uits.iu.edu/login"
paper-search
```

Then request an access link with either a DOI:

```json
{
  "doi": "10.1103/PhysRevLett.47.979"
}
```

or a publisher URL:

```json
{
  "url": "https://journals.example.org/article/123"
}
```

Open the resulting `access_url` in a browser and complete the university-controlled login flow. This tool deliberately does not automate authenticated bulk downloads. After a lawful browser download, place the PDF in the audit repository's local source cache and record its provenance and checksum.

## Search Examples

Search all enabled sources:

```json
{
  "query": "black hole thermodynamics",
  "max_results": 10,
  "sort": "relevance"
}
```

Search ADS only:

```json
{
  "query": "JWST high redshift galaxies",
  "sources": ["ads"],
  "max_results": 5,
  "sort": "date_desc"
}
```

If `ADS_API_KEY` is not set, ADS appears as disabled in `list_sources` and ADS-only searches return no results.

Search recent arXiv papers:

```json
{
  "query": "quantum error correction",
  "sources": ["arxiv"],
  "date_from": "2026-01-01",
  "sort": "hybrid",
  "max_results": 20
}
```

## Local Indexing

The local index stores fetched paper metadata for repeatable keyword, vector, and hybrid searches. By default, embeddings are deterministic mock embeddings derived from paper text, which keeps the server lightweight and testable.

An optional `onnx` feature provides SPECTER2 embedding support in the codebase, but the server's current indexing path uses the default deterministic embedding helper.

## Development

Format and test before submitting changes:

```sh
cargo fmt --check
cargo test
```

Run with logs while debugging:

```sh
RUST_LOG=paper_search=debug cargo run
```

## Release

Tagged releases beginning with `v` trigger the release workflow, which builds archives for Linux, macOS, and Windows targets.
