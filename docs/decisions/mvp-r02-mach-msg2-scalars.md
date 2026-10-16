# Observe packed Mach-message scalars without inferring effects

Status: bounded diagnostic observation. Full Darwin R02 acceptance stays false.

Add a `mach-msg2/observe_msg2.py` capture/toolkit API which invokes
`call-pairing/pair_calls.py` itself. Caller-supplied timelines, validation tokens
or normalized units cannot enter this native-evidence API. Retain the complete
paired result, its source/toolkit/receipt identities and every raw frame; each
selected message also retains all eight entry words and its one opaque return
word. The API may observe zero messages: the six v8 `tree` profiles did not enable
the Mach provider, so zero is explicitly not an absence or coverage verdict.

Packing follows public Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`, retained in the independently reviewed
Mach assessment (manifest SHA256
`4d3207010288577d61042902eafaccd7ae45d016016449a1f300b32a2d098dd5`).
These sources are a candidate LP64/arm64 contract, not attestation of the guest
kernel's exact installed source. The local SDK used to check scalar typedefs is
27.0, while the actual calibration guest is macOS 26.6.2 / Darwin 25.6 arm64.
The supporting SDK's `arm/_types.h:41` defines the unsigned-int natural type
(SHA256 `4f0bde85f9a41cc7d30fff22ebd7e8f4eb206a55a926eda012a2e7481e3524fa`),
and `mach/arm/vm_types.h:96` aliases it to `natural_t` (SHA256
`4256065e3413a8a506492ff4e4c46596076a56e44db7c850efbc832c8b12fbb1`).
The source's timeout cast therefore keeps low32 under this arm64 contract;
the raw64 word and high32 remainder are retained alongside it.

- [mach_traps.h:470–484](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/mach_traps.h#L470)
  gives the eight argument words. Its retained SHA256 is
  `32b236d9cd26bd284c3b2b563b61cea3b943049e5abad5641d2de9d6929e0bac`.
- [mach_msg.c:931–1048](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_msg.c#L931)
  splits packed low/high 32-bit fields, casts the signed message ID and timeout,
  and constructs the send header from those arguments. Its retained SHA256 is
  `85a96ee426f6a2efb5eb12b5747e77315091d22ea330a26a88abf67883569609`.
- [message.h:143–194,1045–1088,1497–1510](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/message.h#L143)
  defines the three five-bit disposition fields, COMPLEX, option flags and the
  userspace packing macro. Its retained SHA256 is
  `ad64b7b413b42e196dc43a54a5978aa049b9133db1fe9369893f12ad4718c615`.

Decode raw pointer/options; header bits and send size; remote/local names;
voucher name and both raw/signed message ID; descriptor count and receive name;
receive size and priority; and timeout raw word with its low32 source-cast value
and high32 remainder. Preserve residual header/option bits without assigning
semantics. Decode SEND/RECEIVE/KOBJECT_CALL as requested bits only. Do not validate
kernel applicability, message size/count consistency or dispositions as rights.
VECTOR is unsupported and rejects: its counts and buffer interpretation differ
and the vector array was not captured. Unknown scalar shapes/flags retain only
their packed values with semantics explicitly unresolved.

No memory at the pointer is read. A header copied from that address would not
replace the packed header; neither it nor entry-time bytes prove what the kernel
consumed. Bodies, descriptor contents, replies, RPC result codes, port/object
generations and operation completion/effects remain unobserved. A zero trap
result is retained without classifying success, a harmless RPC or rollback of
an earlier send when receiving fails. Message IDs never select an effects
allowlist, and numeric port names never establish object identity.

In particular, [ipc_policy.c:897–902](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/ipc_policy.c#L897)
explicitly allows KOBJECT_CALL to message queues when
`CSR_ALLOW_KERNEL_DEBUGGER` permits the SIP-off compatibility path. Its retained
SHA256 is `161a01701b634adc21607969d417d2a54f5e15c6f6f57eea4b2521a0e09e2309`.
The owned calibration guest had SIP disabled. The bit cannot prove destination
type; this caveat applies even before the missing message and port provenance.

Bound selected messages to 4,096 in addition to the pairing API's limits. Tests
must pass malformed and rebuilt-hash captures through the public API, cover all
packed field boundaries, signed IDs, timeout truncation, residual bits, vector
rejection and provenance failures. Replay the seven complete immutable v8 tree
captures without changing bytes or executing captured programs. Every output
retains `full_trace_acceptance=false`; the acceptance API and CLI always reject.
