# Darwin capability descriptor layout revision

Status: accepted for capability framing after the instrumented v4 BEGIN
callback. This decision does not establish full Darwin tracing or R02 acceptance.

The capability producer places `watched[...]` assignments before its BEGIN,
create, start and exec-success trace fields, and after its exit trace fields.
Apple's pinned [DTrace compiler](https://github.com/apple-oss-distributions/dtrace/blob/4e57fe5c4dcf71e455817e7f26fc1f68e6eb4fe2/lib/libdtrace/common/dt_cc.c#L1329-L1337)
represents an expression statement as `DTRACEACT_DIFEXPR` (action 1) with a
zero-sized void result. The pinned [XNU descriptor export](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/dtrace/dtrace.c#L17922-L17954)
retains these actions. V3 callbacks rejected their first record without retaining
its layout; v4 added bounded diagnostics and kept that rejection strict. Actual
guest `glue-mvp-guest-native-v4-vEYsWITo/cases/open/errors.jsonl` (SHA256
`31a152acd3de98e22092ee826aff63663adbb4245586d816410590aa2e851c5e`)
identifies a six-record BEGIN: action 1, size 0, offset 12, then five action-1,
size-8 records at 16, 24, 32, 40 and 48. Other lifecycle layouts remain source
predictions until the new nine-case guest capture exercises them.

Use receipt revision 2 and protocol `darwin-capability-raw-v2` for the revised
transport. Each event adds the actual `record_bytes` and exactly five
`header_record_indexes`. Preserve every original descriptor, including zero-sized
assignment records with empty `hex`. The consumer and independent source-matched
reader must validate an exact generated layout before decoding the header.

All actions are 1. BEGIN (kind 1), create (4), start (5) and exec-success (7)
require exactly six descriptors, with the zero-sized assignment at index 0 and
header at indexes 1–5. Exit (6) requires six descriptors, with header at 0–4 and
the zero-sized assignment at 5. No other kind permits a zero-sized descriptor.
END and other lifecycle kinds require five records; BSD/Mach entry require 13,
BSD return 10, and open-path/Mach return 6. All scalar payload records are
exactly eight bytes. The named-open string record is exactly 1024 bytes, matching
the explicit `strsize` option and the kernel's string-record allocation; it
remains raw bytes. Scalar payloads begin at offset 16 and advance by eight bytes;
the string starts at 56. Total probe bytes are exactly 56 for five-scalar layouts,
120 for BSD/Mach entry, 96 for BSD return, 64 for Mach return, and 1080 for
named-open path.

Select a candidate using profile, provider, probe name and exact descriptor
count before reading a kind. The named-open entry probe has separate kind-2
(13 records) and kind-14 (6 records) clauses. Require the decoded kind to match
the selected layout, retain the existing PID bound, validate generated zero
details, and match nonbuiltin probe IDs and complete descriptor tuples against
the retained inventory. BEGIN/END use their exact builtin descriptors.

Check every offset and size against `record_bytes <= 8192` before a memory read.
Payload records must be ordered and nonoverlapping. Zero-record offsets must
match the calibrated generated layout, not a generic skip rule. The inspected
[XNU layout routine](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/dev/dtrace/dtrace.c#L11136-L11199)
starts with a 12-byte record header: a leading zero-width assignment is expected
at offset 12, followed by an eight-byte-aligned first payload at 16; a trailing
assignment after five scalar fields is expected at 56. BEGIN was confirmed by
v4; other lifecycle placements await v5 guest evidence. Unexpected placement,
action, width, count, profile or provider fails capture with bounded diagnostics.

Tests must cover all 17 kinds, both named-open clauses, exact zero positions,
empty zero bytes, offset/alignment bounds, wrong action/count/header/kind,
inventory/profile mismatches and every prior schema/hash/footer control. Require
an actual new guest open capture, then the nine owned lifecycle cases, retaining
failures unchanged. V1 evidence remains immutable. Both APIs and CLIs continue
to reject full R02 acceptance unconditionally; this revision provides no syscall,
FD, path, process-generation, mutation or complete-coverage interpretation.
