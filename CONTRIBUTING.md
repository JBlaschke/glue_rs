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

If a package-manager installation shadows Rustup (as on the initial development
Mac, where `cargo` on `PATH` is Homebrew Rust 1.99 and `~/.cargo/bin` holds no
Rustup shims), place the pinned toolchain's own `bin` directory first in `PATH`
before running these commands. `rustup which cargo` resolves it through
`rust-toolchain.toml`. `rustup run` alone does not control every Cargo
subprocess's executable lookup. Check both `rustc --version` and
`cargo clippy --version`; both must report 1.88.0. Clippy from a newer
toolchain fails `-D warnings` on lints that do not exist in 1.88.0, which is a
toolchain mismatch rather than a project regression.

```sh
export PATH="$(dirname "$(rustup which cargo)"):$PATH"
```

Tests should exercise contract boundaries and observable behavior. Archive/parser
tests run on the local host. Platform/runtime gates require the native runners
and traces described in `docs/fixtures.md`. Never replace missing target evidence
with a cross-compilation result or a host runtime that was not declared.

New evidence directories commit only their README, inventories and a
`bundle.json` pointer; the traces, archives and logs are published as a release
asset with `scripts/retain-evidence.sh` and restored with
`scripts/fetch-evidence.sh`. See
[decision 0030](docs/decisions/0030-evidence-retention.md).

`PLAN.md` is the design baseline. Add a short decision record before changing
shared APIs or any interpretation of the no-extraction constraint.

For new MVP work, take one bounded assignment from
[`docs/plans/mvp-tasks.md`](docs/plans/mvp-tasks.md), respecting its dependencies
and shared-file ownership. Use the handoff template there. Historical A/G task
labels are not the current dispatch order. Do not promote fixture success into
general package/runtime support without the new product acceptance checks.
