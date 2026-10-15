# Normalized Darwin open intent units

This is a first semantic unit for the future Darwin R02 decoder. It classifies
already normalized `open` / `openat` requests and provides independent owned
native controls. It does not decode DTrace arguments, establish trace
completeness, resolve paths or descriptors, or grant full-trace acceptance.
Every decision contains `full_trace_acceptance: false`; both acceptance and raw
capability adapter APIs unconditionally reject.

The source definitions are Apple's installed macOS 26.5 SDK:

- `usr/include/sys/fcntl.h`: access modes, creation/truncation/append flags,
  event-only descriptors and Darwin `AT_FDCWD = -2`.
- `usr/include/sys/syscall.h`: distinct `open`, `openat`, nocancel, extended,
  guarded and protected syscall numbers. Distinct variants are unsupported here.
- `usr/include/sys/_types/_o_sync.h`, `_o_dsync.h`, `sys/_types.h` and
  `sys/syslimits.h`: sync bits, 16-bit `mode_t`, and 1024-byte pathname limit.

`abi.json` records the inspected values. The preparation script compiles
`open-control.c` against this SDK, compares its actual `--describe` output
exactly with that file, and retains the exact build argv and SDK header SHA256s.
This proves agreement with the build SDK, not a running guest's kernel ABI.
Native syscall-provider slot/sign/return/errno behavior still needs actual guest
captures; no argument positions or Darwin return conventions are inferred from
Linux or from these unit records.

The normalized JSONL record has exactly these keys:

```json
{"revision":1,"protocol":"darwin-normalized-open-unit-v1","origin":"synthetic-unit","operation":"openat","flags":16777985,"mode":384,"path_hex":"6f7574707574","dirfd":-2,"result":-1,"error":2}
```

`origin` is `synthetic-unit` or `owned-control-self-report`. `flags` is an unsigned
32-bit C-normalized value, `mode` an unsigned 16-bit value, and `dirfd` is null
for `open`, or a nonnegative int / Darwin `AT_FDCWD` for `openat`. Path bytes are
nonempty lowercase hex, at most 1023 bytes, excluding the C terminator. No path
resolution or trusted object identity follows from them. `result` and `error`
are canonical libc `syscall()` return/errno values: a nonnegative descriptor and
zero error, or -1 and a positive error. They are not raw kernel/DTrace returns.
The decoder never uses success or failure to erase attempted write intent.

Write access, `O_CREAT`, `O_TRUNC` or `O_APPEND` yields a write request, even
`O_RDONLY | O_CREAT`, and even when the request failed. Unknown bits and known
but unmodeled flags reject as unsupported. Invalid access mode 3 also rejects.
`O_EVTONLY` is represented as an event-access request, not an ordinary read
descriptor; its combination with write access is unsupported. It never erases
creation/truncation/append intent. A read/event request is only a statement about
the supplied flags: it does not prove a regular file, harmless device open,
safe returned FD or complete execution. No application-output exception exists.

Build a copy-ready, strictly ad-hoc-signed native control on macOS arm64:

```sh
sh fixtures/mvp/macos-trace/open-intent/prepare-controls.sh /new/absolute/open-toolkit
```

The guest needs neither Python nor CLT to execute the native control. Preparation
needs host `python3` and the installed 26.5 SDK. The executable links only system
libSystem and has a minimum deployment version of 11.0. Verify its actual copied
guest signature and execution separately; build metadata is not guest evidence.

Use a **new owned control directory for each mode**. Native preparation creates
the marker and two controlled 20-byte files before tracing. Run only this
reviewed fixture against those directories; it is not a sandbox for arbitrary
input or a concurrent hostile writer. Its five-second alarm bounds execution.
It checks the marker/content and rejects linked or nonregular inputs before
mutating the fixed controlled filenames.

```sh
/toolkit/open-control --prepare /new/owned/read-only
/toolkit/open-control --run read-open /new/owned/read-only
```

Modes: `read-open`, `event-only`, `readwrite-open`, `append-open`,
`denied-write-open`, `readonly-create`, `truncate-open`, `create-unlink`,
`openat-dirfd`, `openat-fdcwd`. The denied request targets a missing parent inside
the owned directory. `create-unlink` writes the controlled bytes then unlinks
them; `readonly-create` really creates an empty file with read-only access.
`openat-dirfd` uses a real returned directory descriptor, and `openat-fdcwd`
uses an absolute controlled pathname with the actual SDK `AT_FDCWD` constant.

Stdout contains normalized self-reports for the selected direct open requests;
stderr contains the control result and read/write/unlink counts. These are not
kernel observations or a complete syscall transcript: preflight/stdio/close and
other calls occur too. Trace the entire fixture with the capability controller
to inspect actual guest records. The current producer copies only named `open`
paths and does not decode `openat`, so its captures still cannot become an R02
pass. Spawn actions and other write routes remain explicit full-decoder gaps.

On the host, inspect retained stdout units with:

```sh
python3 fixtures/mvp/macos-trace/open-intent/open_intent.py --input /retained/target.stdout
python3 fixtures/mvp/macos-trace/open-intent/test_open_intent.py -v
```

Exit 0 means supported unit records were classified, including prohibited write
requests; inspect the `no_output_policy` field. Unsupported/malformed units and
`--acceptance` exit 1. Input is a singly linked regular file bounded to 1 MiB, 256
records and 8 KiB per line. Tests use synthetic records plus actual standalone
owned host controls, not fabricated native traces. Guest capture calibration,
full process/thread/call lifecycle, path/FD provenance and alternate mutation
routes remain prerequisites for a full oracle.
