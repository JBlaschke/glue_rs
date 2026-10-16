# Fixed owned-bootstrap status and GO wire v1

Status: frozen pure-codec contract before implementation. Base `64a4dd2`;
branch `codex/mvp-r02-bootstrap-wire`. This component does no I/O, allocation,
process, credential, signal, clock, exec or tracing operation. It never grants
bootstrap or full Darwin acceptance. Request/child ownership and actual execution
remain independently established by a later caller.

All integers use unsigned network/big-endian encoding except signed detail.
Never serialize padded host structs. Status is exactly 256 bytes:

| Offset | Field |
| --- | --- |
| 0 | eight literal bytes `GLUEBS01` |
| 8 | u16 version 1 |
| 10 | u16 kind READY=1, EXEC_ATTEMPT=2, ERROR=3 |
| 12 | u32 length 256 |
| 16,20 | u32 controller PID, child PID |
| 24 | 32-byte opaque request SHA256 |
| 56,60,64,68 | u32 sequence, stage, errno, mutation flags |
| 72,76,80,84 | u32 observed real/effective UID, real/effective GID |
| 88 | u32 group count |
| 92 | sixteen u32 ordered group slots, ending at155 |
| 156,164 | u64 opaque observed cwd device, inode |
| 172 | five u32 kept FD numbers, ending at191 |
| 192 | 32-byte opaque signal-policy SHA256 |
| 224,228 | u32 reason; i32 detail (-1 means none) |
| 232 | 24 reserved zero bytes |

GO is exactly64 bytes: magic `GLUEGO01` at0; u16 version1 at8; u16 length64
at10; u32 controller/child at12/16; request SHA256 at20; twelve zero bytes at52.
Both record families require PIDs1..2147483647, distinct, and exact expected
controller/known unreaped child/request bindings when decoding. Digests and cwd
numeric metadata are opaque, including zero values, not kernel/path authority.

Stages are closed: NONE=0, REQUEST=1, PROCESS_GROUP=2, SIGNALS=3, STDIO=4,
CREDENTIALS=5, CWD=6, DESCRIPTORS=7, READY_IO=8, GO_IO=9, GO_VALIDATE=10,
GATE_CLOSE=11, MASK_RESTORE=12, EXEC=13. Reasons are closed: NONE=0, ARGUMENT=1,
RANGE=2, SYSCALL=3, MISMATCH=4, OWNERSHIP=5, SIGNAL_POLICY=6, CAPACITY=7,
DUPLICATE=8, MISSING_KEEP=9, EOF=10, EXTRA=11, TIMEOUT=12, SHORT=13,
UNSUPPORTED=14, ADAPTER=15, REPLACEMENT=16, SET_ID=17. No arbitrary stage/reason
codes or reason-to-stage authorization inference is permitted.

Mutation bits have numeric values1 credential-attempt and2 descriptor-helper
close-attempt; all other bits reject. These identify the two setup primitives,
not every later gate close. Before CREDENTIALS, credential-attempt is forbidden;
at CREDENTIALS it may be absent or present. CWD and later require it. Before
DESCRIPTORS the descriptor-attempt bit is forbidden; at DESCRIPTORS and later
it is optional, because an exact keep set can need no closes. Once READY has
been accepted, flags are fixed for every later record: both setup primitives
precede READY, so later records cannot clear or invent their attempted bits.

READY has sequence0, NONE stage/reason, errno0, detail-1 and credential-attempt.
Real/effective UIDs and GIDs are equal and nonzero, through2147483647. There
are1..16 unique ordered groups through2147483647, primary GID first; explicitly
selected supplementary0 is valid. Unused slots are zero. Kept numbers are
exactly0,1,2 then two distinct controls in3..2147483647.

EXEC_ATTEMPT has sequence1, EXEC stage, NONE reason, errno0, detail-1 and
credential-attempt. Every observation byte72..223 is zero. ERROR has a nonzero
closed reason, a known nonzero stage, detail-1 or0..2147483647, and known flags.
Only SYSCALL carries positive errno1..2147483647; all other reasons require0.
ERROR observation bytes72..223 are zero. Setup ERROR sequence0 permits
REQUEST..READY_IO; after-READY ERROR sequence1 permits GO_IO..MASK_RESTORE;
after-attempt ERROR sequence2 permits only EXEC. Other relationships reject.

The state validator binds an expected context and accepts only START→READY0
or ERROR0; READY→ATTEMPT1 or ERROR1; ATTEMPT→ERROR2. ERROR is terminal. At most
three records are accepted. Any malformed, wrong-binding, out-of-order or extra
record poisons state permanently, retaining the first protocol fault and any
first reported ERROR. EOF seals state: START/READY are incomplete; ERROR reports
failure; ATTEMPT means only ended without a reported exec error. No EOF result
proves exec success. A record after sealed EOF poisons state. Repeated EOF
classification is idempotent; it is not a clock/trace/liveness assertion.

The C models are not wire layouts. Encode outputs are fixed-size caller-owned
arrays and are cleared before validation; decode outputs are fully cleared on
failure. Exact input lengths are checked before reading fields. All non-NULL
objects/spans must have valid size/alignment, stable lifetime and nonoverlapping
storage; callbacks and untrusted memory are outside this allocation-free API.
Native observations wider than the model must be range-checked by the caller
before conversion. Detail uses a wide signed C value so encoding can reject
values outside the canonical i32 range without truncation. Other wire u32
fields additionally reject values outside the tighter declared semantic bounds.

Controls will use independent golden bytes, hostile lengths/headers/enums,
observation canonicality, binding and phase failures, poison/first-error/EOF
semantics, ordinary Mac/Linux compile/run and injected sanitizer controls.
These are pure data tests and never call recorded/native bootstrap operations.
