# Pure owned-bootstrap request and READY comparison

16 October 2026. Bounded R02 dependency, not a launcher or acceptance gate.

The future nontracing diagnostic needs a canonical request and a comparison of
its declared observations with READY before any GO. Implement these pure C
operations in a new `fixtures/mvp/macos-trace/bootstrap-request` directory.
Do not change the collector, raw readers, shared CI, native privilege/admission
helpers or existing BW wire format. No IO, process, signal, credential, filesystem,
clock, exec, hashing, allocation or callback operation occurs in this dependency.

## Canonical GLUENR01 request

All fields use big endian fixed bytes, never C struct layout. Header208:

| Offset | Field |
| --- | --- |
| 0 | Magic8 GLUENR01 |
| 8,10 | u16 version1, header-length208 |
| 12,16 | u32 exact total length, closed fixture1 context-probe |
| 20,24,28 | u32 UID, GID, group count |
| 32..95 | Sixteen u32 groups; unused slots zero |
| 96,100 | u32 signal-policy1, stdio-policy1 |
| 104 | u32 release1 SEND_GO or2 SIMULATED_PROVIDER_FAILURE |
| 108 | u32 maximum-live-FDs4096 |
| 112,116 | u32 attempt-ms1..10000, cleanup-ms1..2000 |
| 120,124 | u32 argv-template1, environment count0 |
| 128..159 | Selected catalog SHA256 bytes |
| 160,168 | u64 intended admitted cwd device/inode |
| 176,180 | u32 executable/cwd byte lengths |
| 184..207 | Reserved zero24 |

The tail contains exactly executable bytes then cwd bytes, without NUL, padding,
other arguments or extra bytes. Total <=16384; each path1..4095 bytes; components
<=255; absolute paths only, with no NUL, empty/dot/dot-dot component or trailing
slash. Cwd alone may equal `/`; executable may not. Bytes above127 are retained
without Unicode normalization; this is lexical validation, not path resolution.

Use tc's pure credential validator: UID/GID1..2147483647, groups1..16, unique,
primary first and each0..2147483647. Explicit supplementary0 is valid. BR also
requires unused group slots zero. Models retain wide scalar values to reject
host-side overflow before wire narrowing. Catalog digest and cwd numeric metadata
are opaque declarations, including zero; codec validity is not catalog admission
or kernel identity. Closed selectors reject unknown versions/profiles/modes.

Fixture/template1 derives exactly `[admitted_exe, "--request-sha256",
derived_lowercase_64hex]` AFTER hashing the consumed request. It has no arbitrary
argv or self-referential digest field. Actual derived argv is a future runner
observation. Future fixtures need a new reviewed closed schema.

## Pure API and lifetime

`br_request_encode(request,out[16384],written,error)` clears the fixed full output
and sets written0 before validation; success sets the exact length. Only that
prefix is serialized; the remaining output stays zero. `br_request_decode(bytes,
length,out,error)` clears the whole output and accepts only exact bounded input.
Decoded path spans borrow the caller's stable immutable input bytes. It allocates
nothing and does not add NUL terminators. Later native storage must copy/add them
before fork; no mutable request is reparsed in the child.

All objects/spans are valid, stable and nonoverlapping for each call. Fixed output
capacity is16384; error storage is mandatory. NULL and hostile input lengths are
rejected before input reads. The host model is trusted accessible C storage,
not an interface to invalid pointers or arbitrary memory aliasing.

The pure codec does NOT calculate/attest a SHA256. A future native Darwin parent
must hash the exact canonical snapshotted consumed bytes internally using system
CommonCrypto before constructing the BW binding. No second SHA implementation or
Linux OpenSSL dependency is introduced. Independent Python struct/hashlib golden
vectors pin exact bytes and their expected digests as a test oracle only.

## Full declared READY comparison

`br_ready_compare(request,context,status,error)` validates the request, expected
context and canonical BW status/binding, requires READY0, and compares all four
IDs, ordered groups/count/unused slots, intended cwd dev/ino, exact kept numbers,
signal-policy digest and both helper-attempt flags exactly3. Context supplies
caller-selected BW controller/known-unreaped-child/request-digest binding,
uint64 kept FDs exactly0/1/2 and distinct controls3..2147483647, and the expected
canonical signal-policy digest. Existing BW encoding/decoding supplies canonical
status checks; BR does not fork a second wire validator.

Native-width conversion/range checks precede building this context. The future
runner must establish protected cwd and endpoint provenance and derive the actual
request digest itself. Supplying matching forged declarations/context is not
ownership/authentication. Signal-policy1 means verified DFL/no-altstack/all-
blocked at READY and a declared empty final mask after GO; it never means the
empty mask was installed at READY. Raw sigset_t padding is not hashed.

Success means declared READY observations match, not permission to launch,
proof of credentials/kernel objects or a GO decision. Result vocabulary retains
separate no-GO-attempt versus possibly-released outcome and uses BW EOF results:
incomplete, reported error, invalid protocol or attempt-without-reported-exec-
error. Any attempted/failed late GO may already release the child; never replay.
EOF never proves exec. No full-acceptance or exec-success API is added.

## Dependencies, future admission and verification

Base4e592954 integrates reviewed tc/td/te/BW/BIO. This component calls only pure
tc validation and BW codecs. Source pins/descriptions in the read-only proposal
remain byte-equivalent to the integrated primitives:
`/private/tmp/glue-darwin-nontracing-bootstrap-proposal-20261016`, proposal SHA256
9899bcf6f520312d9eb4a7acc8d66ca0893306fffa00f86121b29c8696e93a08.

Native admission/runner remains deferred: one exact reviewed context-probe build,
compiled catalog/build/source identities and explicit system-dyld/libSystem-only
policy, with a separately prepared protected root-owned nonwritable no-symlink
component tree and explicit ACL/mount/provisioning invariant. No general Mach-O
parser is duplicated. Fresh fstatx filesec alone is insufficient: require populated
OWNER/GROUP/MODE presence/get/equality before ACL absence because the pinned libc
can falsely return0 after early realloc failure. Mutable `/tmp` executables,
two matching hashes and an operator boolean do not establish protected exec.

Tests must independently construct golden bytes; cover every closed selector,
reserved/extra/truncated/oversized input, wide model values, credentials/unused
slots, path/component bounds, output clearing/canaries, exact borrowed spans and
round-trip canonical output. Mutate every READY observation and context/binding,
including valid BW but mismatched requested observations. Run pure C controls
natively on Mac/Linux plus sanitizer controls. These checks perform no native
credential transition, target execution, tracing, VM/security or privilege work.
