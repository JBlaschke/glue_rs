# Explicit Linux CI trace environment

Status: selected for the native hosted Linux MVP acceptance run. This changes
the test host policy, not the packaged runtime or the extraction oracle.

`strace` observes kernel syscalls, but cannot observe requests written into
an io_uring submission queue. The extraction oracle therefore rejects a
successful asynchronous I/O setup that lacks a decoder. Selected newer Node
runtimes use such queues on the hosted x86_64 kernel, while the local ARM64
kernel already refuses setup. An environment variable is insufficient to
disable every queue used by the selected libuv versions.

The CI wrapper `fixtures/mvp/trace_environment.c` installs `no_new_privs` and
a seccomp filter before executing the case or benchmark driver. It returns
`ENOSYS` for native `io_uring_setup`, `io_uring_enter`, `io_uring_register`,
`io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents` and
`io_pgetevents`. All other native syscalls are allowed by this filter, including
ordinary file creation and writes, so negative extraction controls remain
meaningful. Other syscall ABIs are rejected; x86_64 also rejects the x32 ABI.
An installation error aborts before executing the requested command.

Linux inherits this policy through fork, clone and exec. CI applies it to the
entire case/benchmark process tree: stock reference, builder, included launcher,
trace controls, and all 1/32-rank measurements. Network isolation still comes
from `unshare --net`. The filter is not installed by `glue` and is not part of
the distribution manifest or payload.

This policy is **not a security sandbox** and its acceptance results do not
prove behavior on an unrestricted host with asynchronous kernel I/O available.
They prove the selected runtime's normal syscall fallback under the explicit
recorded CI environment. Full unrestricted-host acceptance requires observing
and decoding asynchronous filesystem activity, or another complete capture
mechanism. The extraction oracle and its fail-closed asynchronous-I/O rule are
unchanged. This scope also applies to benchmark results obtained in this run.

CI retains the helper source, executable, compiler command, independent probe
JSON and SHA-256 identities. The probe records the actual pre-policy
`io_uring_setup` result, then requires every blocked syscall to return `ENOSYS`
in the parent and a fork+exec child, with inherited filter/no-new-privileges
state and successful ordinary file I/O. On x86_64 it additionally executes x32
and i386 compatibility syscall probes. A successful pre-policy setup followed
by filtered `ENOSYS` demonstrates the policy changed an available path; an
already-blocked setup is labelled explicitly. Native ARM64 supports local
mechanics tests only and does not substitute for native x86_64 execution.

The evidence verifier rechecks the probe and retained hashes before the CI
summary can pass. Prior failed receipts remain unchanged. Frozen budget
selection and review remain separate from this environment policy.

The kernel's [seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
describes syscall filtering, ABI checks, `no_new_privs`, and inheritance across
fork/clone/exec, and explicitly distinguishes filtering from a complete sandbox.
