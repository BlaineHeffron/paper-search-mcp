# paper-search

`paper-search` is a Rust MCP server for searching, retrieving, and locally indexing scientific papers. It exposes MCP tools over stdio, so agent clients can query multiple scholarly sources through one interface and optionally build a local searchable paper index.

## Features

- Federated paper search across arXiv, INSPIRE-HEP, Semantic Scholar, OpenAlex, Crossref, Europe PMC, DOAJ, viXra, and NASA ADS.
- Source filtering, date filtering, and sort modes for relevance, newest first, oldest first, or hybrid ranking.
- Paper metadata lookup by prefixed IDs such as `arxiv:`, `doi:`, `inspire:`, `s2:`, `ads:`, `pmid:`, `doaj:`, `vixra:`, and `openalex:`.
- Citation and reference lookup when the selected source supports it.
- Local indexing with Tantivy full-text search and LanceDB vector storage.
- Open-access PDF discovery through Unpaywall when configured.

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
| `PAPER_SEARCH_SOURCES` | Optional comma-separated source allowlist, for example `arxiv,inspire,ads`. |
| `SEMANTIC_SCHOLAR_API_KEY` | Optional Semantic Scholar API key. Without it, Semantic Scholar remains enabled but rate-limited. |
| `ADS_API_KEY` | NASA ADS API key. ADS is disabled unless this is set. |
| `OPENALEX_EMAIL` | Optional OpenAlex polite-pool email. |
| `UNPAYWALL_EMAIL` | Enables the `get_pdf_url` tool through Unpaywall. |
| `RUST_LOG` | Logging filter, for example `paper_search=info`. Logs are written to stderr. |

Example with ADS and Unpaywall enabled:

```sh
export ADS_API_KEY="..."
export UNPAYWALL_EMAIL="you@example.com"
export PAPER_SEARCH_SOURCES="arxiv,inspire,ads,openalex,crossref"
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
