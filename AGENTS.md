# paper-search

Rust MCP server for federated scholarly search and local paper indexing.

## Minimize code

Ship the feature with the fewest lines. Do not add parallel scopes, policy layers, wrappers, or helpers unless an existing path cannot do the job. Prefer deleting and reusing over extending. Extra code is extra bugs and extra maintenance.

## Invariants

- Keep stdout protocol-only; diagnostics belong on stderr.
- Degrade each source honestly when credentials, rate limits, or capabilities are unavailable.
- Search hits and metadata are leads, not proof. Never fabricate abstracts, identifiers, citations, or full text.
- Default deterministic embeddings are test/index helpers, not scientific semantic evidence.
- Preserve prefixed identifier and source-specific behavior across tool changes.

## Verification

- Run `cargo fmt --check` and `cargo test`; use `cargo build --release` for release-path changes.
