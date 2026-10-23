# V02: validate Linux proof errno values independently of the replay host

Status: accepted. The execution policy and captured evidence stay unchanged.

Replaying the retained x86_64 acceptance evidence on macOS exposes a checker
bug: `trace_environment.check_proof` compares captured Linux errno values against
the importing host's `errno.ENOSYS`. Linux records 38; this Mac supplies 78.
Validate the two supported Linux ABIs, x86_64 and aarch64, against their explicit
Linux value 38, including the x86 x32/i386 guard results. Reject other requested
architectures. The [Linux UAPI definition](https://raw.githubusercontent.com/torvalds/linux/v6.17/include/uapi/asm-generic/errno.h)
and retained native source/proof establish the value; a caller-provided expected
errno or host-dependent fallback must not override it.

Keep all other proof, source/helper identity and manifest checks. Do not change
the C filter, execution policy, stored proof, native measurements or acceptance
requirements. Add portable serialized-proof and file-checker regressions to the
existing test script, preserving its native Linux controls and explicit skips.
Invoke that script in portable baseline CI so macOS tests the read-only Linux
replay route. No new native execution claim follows from portable fixtures.
