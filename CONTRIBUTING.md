# Development

Start each implementation step on a feature branch prefixed `codex/` (or another
explicitly requested prefix). Keep `main` as the reviewed baseline. Stack a new
branch on the previous feature commit when a step depends on work that has not
been merged. Record the branch, commit, tests and outstanding evidence in
`docs/progress.md`. Do not merge a milestone just to advance its label.

The checked-in toolchain is Rust 1.88.0. Build-time dependencies may be fetched;
the resulting application must not fetch or extract payloads at execution time.

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

If a package-manager installation shadows Rustup's shims (as on the initial
development Mac), place Rustup's shims first in `PATH` before running these
commands. `rustup run` alone does not control every Cargo subprocess's executable
lookup. Check both `rustc --version` and `cargo clippy --version`.

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

Tests should exercise contract boundaries and observable behavior. Archive/parser
tests run on the local host. Platform/runtime gates require the native runners
and traces described in `docs/fixtures.md`. Never replace missing target evidence
with a cross-compilation result or a host runtime that was not declared.

`PLAN.md` is the design baseline. Add a short decision record before changing
shared APIs or any interpretation of the no-extraction constraint.
