# Status review, 15 October 2026

An independent review of the implementation log against `PLAN.md`, prepared
by Claude (Fable 5.1) at the request of the repository owner. The reviewed
state is feature commit `5eddf01` on `codex/a7-python-native-package-imports`,
merged into `main` as `232b1f3` through PR #25. This is a point-in-time
assessment. It is not a decision record and changes no contract.

## Scope and method

- Read `PLAN.md`, `docs/progress.md`, `docs/fixtures.md`, decisions 0028 and
  0029, the fixture and evidence READMEs for the reviewed branch, and the
  complete code diff of the branch against `main`, excluding evidence files.
- Re-ran the portable checks on macOS arm64 instead of relying on the log.
- Verified the reviewed branch's evidence checksums and replayed one retained
  Linux trace through its committed checker.
- Exercised the product CLI end to end with the linked Lua fixture.
- Did not run the Podman GNU Linux arm64 cell. Linux results were checked by
  replay only.

## Verified results

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked`, Rust 1.88.0 | 505 passed, 0 failed |
| Same, Homebrew Rust 1.99 | 505 passed, 0 failed |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --locked -- -D warnings`, Rust 1.88.0 | clean |
| Same, Rust 1.99 | fails on lints that do not exist in 1.88 |
| `shasum -a 256 -c artifacts.sha256` in the branch's evidence directory | 378 of 378 match |
| `scripts/check-linux-python-native-packages-trace.py` on the retained `host-host` trace | pass |
| `glue build`, `glue doctor`, `glue run` on `fixtures/lua-linked`, macOS arm64 | expected output, exit 0 |

Toolchain note. On the development Mac, `cargo`, `rustc` and `cargo-clippy`
on PATH resolve to Homebrew Rust 1.99 although `rust-toolchain.toml` pins
1.88.0, and `~/.cargo/bin` contains no rustup shims, so the PATH advice in
`CONTRIBUTING.md` has no effect there. Prepending
`~/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin` selects the pinned
toolchain. The Clippy failures under 1.99 are a toolchain mismatch, not a
regression.

## The reviewed change

The branch adds the `stock-pbs-native-packages` profile. Three native
children of an archive source package are imported through stock
`ExtensionFileLoader`. Their origins are retained `/proc/self/fd/N` aliases,
the profile supplies zero inittab registrations, the byte callback is scoped
to the three declared names, and image bases, exports and relocation slots are
rechecked around each loader call. The C boundary is unchanged. The change
matches decision 0029 and no correctness problem was found in the diff.

## Position against the plan

### What is working

- Process discipline is real: one decision record per step, complete syscall
  traces, hostile mutations of the trace checkers, and no relaxation of the
  no-extraction rule or silent provider fallback anywhere inspected.
- Python has both providers proven against the real PBS runtime: bundled from a
  sealed memfd and explicit host. Source applications, resource streams,
  `.dist-info` metadata, unmodified upstream wheels and the build-time
  commands `python-template`, `python-host` and `build-python` are genuine
  product paths rather than fixtures.
- Lua 5.4 and 5.5 run end to end on macOS and GNU Linux arm64, with native
  Lua closures on GNU Linux arm64.

### Where the work has drifted

1. **Platform breadth.** The plan's dispatch was A0, then A1, A2 and A3
   concurrently, then a frozen native contract, then A5 through A9. In
   practice A2 Windows and FreeBSD never started. A1 macOS stopped at a probe
   on 9 October with acceptance evidence incomplete: no full trace and no
   Developer ID signing. Every Linux result is arm64 because the cell is
   Podman on an arm64 Mac, so Linux x86_64, a named initial release target,
   has no execution evidence. The log records a preference to complete Python
   before Node. That explains A8, but not the platform gates, which the plan
   treats as the decision point for everything else. By the project's own
   accounting G0, G1 and G2 remain open.

   | Measure | Value |
   | --- | --- |
   | Merged PRs | 25 |
   | Merged PRs belonging to A7 Python | 19 |

2. **Native support is fixture-shaped.** Only source-only and metadata
   applications accept arbitrary inputs. The three native profiles are closed
   registries keyed by application ID, and `glue-runtime-python` compiles
   fixture application bytes in with `include_bytes`. "Native modules
   supported" today means three reviewed shared objects and one dependency.
   The log names third-party wheels as the next step. That jump is larger
   than any step so far: the ELF admission in `crates/glue-native/src/elf.rs`
   rejects TLS, IFUNC, REL relocations and search paths, which real wheels
   need, along with `libstdc++` and larger dependency graphs. The plan wanted
   the required-versus-optional native feature set frozen against a
   representative corpus after G1, and that has not happened.

   | Measure | Value |
   | --- | --- |
   | Fixture directories referenced from crate code | 10 |
   | Profile kinds in the Python registry | 12 |
   | Lines of Rust and C in `glue-runtime-python` | about 16,000 |

3. **Per-step cost is growing superlinearly.** Each step reruns every
   historical fixture and commits a multi-megabyte evidence bundle. The
   reviewed step reran 22 historical native cases beside its 11 new ones.

   | Measure | Value |
   | --- | --- |
   | Working tree under `docs/evidence` | 480 MB |
   | `.git` directory | 289 MB |
   | Tracked files that are evidence | 14,441 of 14,849 |

   At this rate the repository becomes hard to clone within weeks. Git LFS,
   or an out-of-tree evidence store with only hashes in-tree, is worth
   deciding now rather than after history rewriting becomes painful.

4. **No continuous integration.** There is no workflow directory. Every
   check runs by hand on one Mac and in its Podman cell. G6 and the plan's
   "native OS runners" requirement both presume CI.

5. **The Python crate is large and repetitive.** Twelve profile kinds carry
   parallel admission logic. Generalizing to arbitrary native packages will
   probably require consolidating them first.

## Remaining work, in plan order

1. **Rebalance toward G1 before more A7 depth.** A Python host provider on
   macOS arm64 is the cheapest high-value probe: PBS ships macOS artifacts and
   the Mach-O spike already has MAP_JIT and signing groundwork. Then complete
   A1 tracing and signing, stand up a real Linux x86_64 cell, start the
   Windows PE spike on a Windows machine, and decide the FreeBSD producer.
   These are the feasibility questions the plan says must be answered first.
2. **Freeze the native capability contract, A5.** Pick one real C extension
   and one dependency-heavy package and decide required versus optional ELF
   features before writing general wheel admission.
3. **A9 workers.** Only a synthetic codec and controller ledger exist.
   Launcher re-execution, inherited pipes and `glue.call` in Lua and Python
   are needed before G4 can move.
4. **A8 Node.** Nothing exists yet. It is the largest single unknown:
   embedding real Node and V8 JIT on signed macOS.
5. **A10 distribution.** Standalone executable, signing, size budgets and CI.
6. **Hygiene.** Thirty merged local branches can be pruned, evidence storage
   needs a policy, and `CONTRIBUTING.md` should name the actual rustup
   toolchain directory.

## Decisions this review asks for

- Direction: continue down the A7 third-party-wheel path the log proposes, or
  rebalance toward the platform gates first. This review recommends the
  latter.
- Evidence storage: keep committing bundles to Git, or move them out of tree.
- CI: add the portable checks on the pinned toolchain now, leaving trace
  fixtures manual.
