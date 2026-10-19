# Pure owned-bootstrap request

This C dependency validates/serializes one closed canonical diagnostic request and
compares every declared READY observation before any future runner could choose
GO. It contains no IO, fork/exec, filesystem/admission, native credential/signal
operation, callback, allocation, hashing or acceptance API. The collector/raw
readers are unchanged. The [decision](../../../../docs/decisions/mvp-r02-bootstrap-request.md)
freezes the208-byte big-endian GLUENR01 header and exact executable+cwd tail.

`br_request_encode` requires a fixed16384-byte output, written-count and error.
It clears the whole output/written count before validation. Success returns only
the canonical prefix length; the unused suffix remains zero.
`br_request_decode` rejects hostile lengths before reading input, clears output
on failure, and returns spans borrowing the original immutable wire bytes. All
C objects/spans must be accessible, stable and nonoverlapping. No terminators
are supplied; future native snapshot storage must provide them before fork.

Credentials reuse tc's pure validator; unused group slots must additionally be
zero. Closed fixture/template1 means the context-probe with argv derived after
request hashing as `[exe,"--request-sha256",lowercase64hex]`. No variable argv
or environment is serialized. Paths are absolute lexical byte spans with bounded
nonempty components and no NUL/dot/dot-dot/trailing slash (cwd `/` is allowed).
Unicode bytes are preserved without normalization. These checks do not prove
permissions, symlink resolution, protected fixture/catalog provenance, current
cwd identity, endpoint objects or any privileged transition.

`br_ready_compare` first validates the request/context and reuses BW codecs for
canonical status/binding checks. It requires READY and exact four IDs, ordered
groups/count/unused slots, cwd device/inode, five keep numbers, signal-policy
hash and helper-attempt flags3. Expected topology contains0/1/2 and two distinct
controls3..INT32_MAX, supplied in uint64 fields to reject native narrowing.
A valid BW record can still mismatch the request. Conversely forged matching
request/context/READY objects are not authenticated: the native parent must
establish provenance and compute its request SHA256 internally over exact bytes.

The signal digest is an opaque caller-selected context field for a declared
DFL/no-altstack/blocked-READY/empty-final-mask policy. It does not report the final
empty mask installed at READY. Request catalog digest and dev/ino similarly
remain opaque, including zero. No pure hashing implementation is duplicated:
future Darwin runner uses CommonCrypto, and independent test goldens use Python
struct/hashlib. Supplying a digest here is not proof it hashes this request.

Future result vocabulary keeps GO-not-attempted versus possibly-released apart.
BW EOF only classifies incomplete/reported error/invalid protocol/attempt without
reported exec error. EOF never proves successful exec. This component neither
sends GO nor admits any executable; native protected-path/ACL/mount/provisioning
and process/cleanup code remain deferred. In particular an executable under
`/tmp` is not approved by successfully decoding its pathname.

Run ordinary pure controls (no application/probe/privileged target execution):

```
PYTHONDONTWRITEBYTECODE=1 python3 fixtures/mvp/macos-trace/bootstrap-request/test_bootstrap_request.py -v
PYTHONDONTWRITEBYTECODE=1 BR_TEST_CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
  python3 fixtures/mvp/macos-trace/bootstrap-request/test_bootstrap_request.py -v
```

The11 groups cover independent struct/hashlib golden bytes/digests, exact borrowed
span lifetime and revalidation after changed input, every truncated input length,
unknown/reserved/oversized selectors, every-byte rejected-or-canonical mutations, model overflow, credentials/group0/order/
unused slots, raw-byte path/component bounds, output clearing/canaries, every
READY observation, canonical wrong record kinds, bindings and topology widths.
The test compiler requires a local C compiler and links only owned sources;
it executes an allocation-free pure-control binary, never a fixture launcher.
Native Mac and offline Linux compile controls and sanitizer checks establish only
this data-contract behavior, not the combined future bootstrap or full R02/M2.
