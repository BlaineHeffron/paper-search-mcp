# paper-search

Rust MCP server for federated scholarly search and local paper indexing.

## Invariants

- Keep stdout protocol-only; diagnostics belong on stderr.
- Degrade each source honestly when credentials, rate limits, or capabilities are unavailable.
- Search hits and metadata are leads, not proof. Never fabricate abstracts, identifiers, citations, or full text.
- Default deterministic embeddings are test/index helpers, not scientific semantic evidence.
- Preserve prefixed identifier and source-specific behavior across tool changes.

## Verification

- Run `cargo fmt --check` and `cargo test`; use `cargo build --release` for release-path changes.
