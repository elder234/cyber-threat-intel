# sqlx Offline Metadata Directory

This directory exists to satisfy the `SQLX_OFFLINE=true` environment variable
set in the Dockerfile. Because the codebase uses sqlx's runtime `query()` and
`query_as()` functions (not the compile-time `query!()` / `query_as!()` macros),
no offline query metadata files are required.

If compile-time checked queries (`query!`, `query_as!`) are introduced in the
future, run `cargo sqlx prepare` against a live database to populate this
directory with the necessary `query-*.json` files.
