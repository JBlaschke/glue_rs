# Linux arm64 sealed-memfd observation

Captured on 2026-10-08 from clean commit
`447a339a25bc78abcfa057325d48cf7cc3bca979` on `codex/a3-linux-memfd-probe`.
The Mac host ran `sh scripts/run-linux-memfd.sh` using Rust 1.88.0 first in PATH.
The script supplied the recorded container image by immutable local image ID,
disabled container networking, mounted the source read-only and placed build
outputs in tmpfs. [Exact inner commands](commands.sh), [source identity](source-commit.txt),
[clean state](source-status.txt) and [source/lockfile hashes](source.sha256) are retained.

The observed cell used Linux `7.1.4-200.fc44.aarch64`, glibc `2.36-9+deb12u10`,
GCC `12.2.0-14+deb12u1`, Rust/Clippy 1.88.0 and strace `6.1-0.1`, with 4 KiB
pages and `vm.memfd_noexec=0`. The resulting image ID was
`62812c4a0e15bc750ddd6ec68d2a19f8815a14b60d520e201a911e2e29f40abe`.
[Environment](environment.txt), [image ID](image-id.txt).

Both ordinary disk loading and archive loading returned function result 42,
exported data 7 and constructor count 1, including repeated loading. Archive
execution used two anonymous memfds with all four seals (`0xf`). Compiler-produced
shared-library files were removed before the traced archive run.
[Baseline output](baseline.stdout.txt), [probe output](probe.stdout.txt),
[native dependency metadata](module.dynamic.txt).

The full child syscall trace passed the narrow fail-closed checker. The only
payload writes target the two annotated memfds; its only filesystem-file write
is the exact 164-byte PASS diagnostic to the external stdout evidence sink.
There are no stderr writes, named payload creation, failed mutation attempts,
shared filesystem mappings or unapproved copy/async I/O calls in this observation.
Both native executions exited 0. [Complete trace](probe.trace.txt),
[checker result](trace-check.txt), [probe status](probe.exit-status.txt),
[baseline status](baseline.exit-status.txt).

All 80 Rust workspace tests and warnings-denied Clippy passed in this Linux cell.
The same 80 Rust tests, formatting and Clippy passed on macOS arm64. The 15
adversarial trace-policy tests passed on the Mac host.
[Linux tests](workspace-tests.txt), [Linux Clippy](workspace-clippy.txt),
[trace-policy tests](trace-policy-tests.txt).

The generated archive SHA-256 is
`13ee70fc4c22619be4045450fc896f8840c76ef4b0d46be9d1efd95e2a283c8d`.
Binary/archive and native input hashes are retained; the binary payloads remain
under ignored `target/evidence/linux-memfd/run-1WK1VHOs` on the development host.
The compiled standalone native inputs and probe binary were ephemeral container
build outputs. [Artifact hashes](artifacts.sha256), [native input hashes](native-inputs.sha256).

This is positive evidence for the fixed C fixture on this cell. It proves no
actual language runtime startup, other platform/architecture, stricter memfd
policy, minimum kernel version or general ELF compatibility. The Debian package
repository is moving; the recorded image is an observed environment, not a
byte-reproducible producer. G0 and G1 remain open.
[Scope and remaining work](../../decisions/0004-linux-memfd-probe.md).
