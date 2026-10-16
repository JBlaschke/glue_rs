# Fixed bootstrap wire v1: pure data only

This module serializes exact 256-byte status and 64-byte GO records and validates
at most three status records. It opens no FDs, allocates no memory and performs
no process, credential, signal, clock, exec, collector or VM operation. It never
grants bootstrap or full Darwin acceptance. See the
[contract decision](../../../../docs/decisions/mvp-r02-bootstrap-wire.md) for all
offsets, enums and canonical relationships. Host struct layouts are not wire data.

`bootstrap_wire.h` exposes fixed-size-array `bw_status_encode`/`bw_go_encode`,
exact-length/context-bound decode functions and `bw_state_init/push/finish`.
Return `BW_OK` means only data validity within this contract. Every other return
rejects. Encode outputs are fully cleared on failure, except NULL output which
cannot be written. Decode outputs are fully cleared on failure. Output spans
must be the complete fixed size; all non-NULL objects/spans require valid size,
alignment, lifetime and nonoverlapping storage. State is initialized only by
`bw_state_init` and not modified by callers between calls. The API is not a
memory-safety boundary against hostile pointers or caller mutation.

The expected binding names the caller's controller, known unreaped child and
exact consumed-request digest. The codec cannot establish these identities.
READY validates equal nonzero real/effective IDs, primary-first unique groups
and the exact numeric five-FD shape. It does not compare these observations to
actual requested IDs/groups/cwd/signal policy. A full parent/reader must perform
those comparisons before GO. Digests and cwd numeric metadata, including zero
values, are opaque observations, not path/kernel/ownership authority. The caller
must reject native-width overflow before converting into the C model.

Mutation bits are only the `tc` credential-helper attempt and `td` nonkeep
cleanup-helper close-attempt. They do not describe earlier stdio duplication or
later GO-reader closure. ERROR phase restrictions prevent claims of future
helper attempts. After accepted READY these flags are fixed in every later
record. All ERROR records prevent launch regardless of flags.

The state validator accepts only START→READY0/ERROR0, READY→ATTEMPT1/ERROR1,
ATTEMPT→ERROR2. ERROR is terminal. Any malformed, wrong-binding, out-of-order
or extra record permanently poisons state. The first protocol fault and first
reported ERROR are retained separately; the last accepted record is available
as `state.last`. Raw stream retention belongs to the caller.

`bw_state_finish` seals the stream and returns only:

- `BW_END_INCOMPLETE` for START or READY;
- `BW_END_REPORTED_ERROR` for the reported failure;
- `BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR` after ATTEMPT;
- `BW_END_INVALID` for poisoned/invalid state.

The third classification never proves exec success. Repeated EOF classification
is idempotent; any later record poisons state. There is no acceptance API and no
EOF, clock, trace, liveness or IO-completion shortcut. Status and GO codecs do
not perform stream reads or establish EOF themselves.

Run ordinary native pure-data controls:

```sh
python3 fixtures/mvp/macos-trace/bootstrap-wire/test_bootstrap_wire.py -v
GLUE_BOOTSTRAP_WIRE_SANITIZE=1 python3 fixtures/mvp/macos-trace/bootstrap-wire/test_bootstrap_wire.py -v
```

The Python harness compiles only the two C files and runs bounded data controls.
It does not compile or execute any bootstrap/target fixture. Golden vectors
were built independently with Python `struct.pack` using the decision offsets;
C encoding must match every byte and C decoding must accept those independent
bytes unchanged. Six vectors cover READY, ATTEMPT, three ERROR phases and GO.
The controls additionally cover all header/reserved/observation bytes, hostile
input lengths, binding/enum/numeric/group/FD limits, stage/reason/flag/errno/detail
relationships, output clearing, all legal paths, first-failure retention, extra
records, sealed EOF and permanent poison. Sanitizer mode adds ASan and UBSan.
Native Mac/Linux pure-control evidence does not calibrate privileged guest
bootstrap, libproc, endpoint ownership, helper integration or the full oracle.
