# Controlled Linux memfd fixture

Status: experimental feasibility evidence on one Linux arm64 cell. G0 and G1
remain open. The probe is a separate workspace binary in `spikes/linux-memfd`;
it does not provide a general ELF backend or enable language execution.

## Mechanism and contract

The fixture packages two real ELF shared libraries as stored archive resources.
The main library calls an archived dependency and libc `strlen`, exports data,
and has a constructor. The probe verifies the archive contract and both hashes,
then checks ELF64 little-endian headers, host machine, segment ranges and the
absence of writable executable load segments before loading either image.
This preflight is deliberately narrower than a full ELF dependency or relocation
validator. Matching CRC/SHA cannot make a structurally invalid image acceptable.

Each payload is copied into a `memfd_create` object with `MFD_EXEC`, close-on-exec
and sealing enabled. The probe applies and checks WRITE, GROW, SHRINK and SEAL
seals. The dependency is opened first through `/proc/self/fd` with
`RTLD_NOW | RTLD_GLOBAL`; the main library uses `RTLD_NOW | RTLD_LOCAL`.
Descriptors and loaded handles remain pinned for process lifetime. Fixed C ABI
calls and data access are private to this fixture; no generic symbol API escapes.

Linux documents memfd backing as anonymous memory, with no linked filesystem
file. This is the anonymous-object route permitted by `PLAN.md`, rather than a
named temporary file. [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

The GNU loader supplies relocation, constructor execution and existing-library
identity for this fixture. Global symbol publication helps resolve the archived
dependency, but broader namespace/alias rules remain to be designed.
[dlopen](https://man7.org/linux/man-pages/man3/dlopen.3.html)

Executable memfd policy is an explicit host prerequisite. `MFD_EXEC` failure
ends the probe with an error; no extraction or flag fallback exists. The kernel
documents namespace-dependent `vm.memfd_noexec` policy. Its stricter settings
have not been exercised here.
[kernel memfd policy](https://docs.kernel.org/userspace-api/mfd_noexec.html)

The provisional schema requires a language component. Its Lua provider is
explicitly marked `unacquired-fixture-scaffold`; those fictional host paths are
never opened and the source is never evaluated. This does not establish Lua,
Python, Node or provider compatibility.

## Harness and evidence boundary

`sh scripts/run-linux-memfd.sh` vendors locked Cargo inputs, builds the observed
Linux test image, and uses a read-only, network-disabled Podman container with
build output in tmpfs. The harness compiles both libraries and a normal disk
`dlopen` baseline, verifies SONAME/DT_NEEDED and absence of RPATH/RUNPATH, and
compares the function result, exported data and repeated-load constructor count.
It deletes compiler-produced `.so` files before tracing archive execution.

The traced child has a single process and uses `strace -f -yy -e trace=all`.
The checker accepts only a small explicit syscall set and rejects unknown or
incomplete calls, including failed filesystem mutation attempts. Writes are
restricted to the two annotated fixture memfds and the recorded stdout/stderr
sinks. Shared mappings of filesystem files, copy/async I/O and subprocesses are
rejected. Both memfds must report all four seals and the process must exit 0.
This checks the observed fixture; it is not a sandbox for arbitrary native code.

Evidence includes the parent commit and dirty state, source and lockfile hashes,
exact harness, container image identity, kernel/compiler/libc/strace versions,
native input/binary/archive hashes, test and Clippy logs, baseline stdout/stderr,
probe stdout/stderr/exit status and the complete runtime trace. Capture happens
outside the traced child. Build-time artifacts and evidence files are allowed.

The base image is pinned by manifest digest; strace and the Rust component are
version pinned. Debian package repositories still move, so rebuilding the test
image is not a byte-reproducible producer. Preserve the resulting image identity
and package versions with each observed run.

## Remaining acceptance work

The target's Linux 6.3/glibc 2.36/4 KiB prerequisites are provisional; executing
on a newer kernel does not validate those minimum versions. No Linux x86_64,
FreeBSD, Windows or signed macOS native execution is established by this cell.
The probe's external runtime prerequisites include the GNU dynamic loader,
libc, libgcc_s, procfs and executable memfd support. The approved product
system-library profile remains a G0 task.

Missing imports, unsupported relocations, cycles, TLS, callbacks, weak/versioned
symbols, unwinding, unload semantics and arbitrary ABI profiles remain open.
Actual bundled/host Python, Lua and Node startup and their identity checks are
required before G1 can close. Retain the no-extraction constraint in every
subsequent feature branch.
