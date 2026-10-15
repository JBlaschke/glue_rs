# Lua helper checks (L01)

Install both exact runtime families with one command:

```sh
scripts/install-lua-helpers.sh /absolute/install/prefix
/absolute/install/prefix/bin/glue-lua54 --describe
/absolute/install/prefix/bin/glue-lua55 --describe
```

The installer selects Cargo features internally and stages both builds before
installation. Helpers are discovered from explicit directories, normally the
packaging launcher's directory, without PATH search. A distribution includes
only the chosen helper.

`crates/glue-runtime-lua/tests/helper.rs` executes the existing linked Lua
source/resource corpus in each helper process, checks exact descriptor/bytes,
validates int64/float64, rejects the other runtime declaration before entry,
contains a raised Lua error, and executes/mismatch-checks C01 compact archives.

```sh
cargo test -p glue-runtime-lua --locked
cargo test -p glue-runtime-lua --no-default-features --features lua55 --locked
```

Local implementation evidence: macOS arm64, Rust/Clippy 1.88.0, linked Lua
5.4.9 and 5.5.1. Linux x86_64 and Linux arm64 helper execution remains a target
evidence requirement. These focused checks do not constitute an extraction trace
or final signing-policy acceptance.
