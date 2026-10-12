# Bounded worker messages (A9)

Status: experimental version 0, 12 October 2026.

`glue-ipc` defines the value/message codec and a controller-side connection
ledger for future launcher-owned workers. A separate Rust fixture exchanges
messages with a synthetic child over actual anonymous pipes. The product
launcher does not yet start workers, and no Python, Lua or Node binding uses
this protocol. G4 remains open. The A9 assignment explicitly permits synthetic
workers after the existing A0/A4 contracts.

## Framing and budgets

Every frame has the following 16-byte header, followed by exactly one payload:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `GLUEIPC` followed by a zero byte |
| 8 | 2 | Little-endian protocol version, currently 0 |
| 10 | 2 | Reserved flags, currently 0 |
| 12 | 4 | Little-endian payload length, excluding the header |

There is no negotiation or resynchronization. Reject other magic, versions,
flags, zero-length payloads and oversized declarations before allocating or
reading the body. A failed frame or transport operation ends the connection.
An EOF before a header's first byte is a clean framing EOF; partial headers,
partial bodies and truncated fields are errors. A decoder consumes precisely
one frame, and an in-memory decode rejects trailing bytes. A writer validates
the complete message before its first transport write. Partial writes and
interrupted operations are handled; flushing remains the caller's responsibility.

The default payload budget is 1 MiB, with 256 KiB per UTF-8 string, 1 MiB per
byte string, depth 32, 16,384 value nodes and 4,096 members per list/map. Depth
counts a root value as one, and nodes include containers. Keys and message
fields consume string/frame budgets; they do not count as value nodes. Limits
are validated before I/O. Absolute ceilings are 16 MiB per payload, depth 64,
65,536 nodes and 16,384 container members. Container counts must fit both their
node budget and the minimum bytes still available before construction. There
is no allocation proportional to an unchecked declared field length or count.
These budgets bound one message; a future supervisor must also bound queued
bytes and apply pipe backpressure across connections.

## Values

All numeric fields use little-endian encoding. Strings and byte strings have
a four-byte unsigned byte count followed by their bytes. Strings are strict
UTF-8; empty strings and embedded zero bytes are allowed in values and map keys.

| Tag | Value | Payload after tag |
| --- | --- | --- |
| 0 | Null | None |
| 1 / 2 | False / true | None |
| 3 | Signed integer | Eight-byte two's-complement `i64` |
| 4 | Unsigned integer | Eight-byte `u64` |
| 5 | Float | Eight-byte IEEE binary64; finite values only |
| 6 | String | Length and UTF-8 bytes |
| 7 | Bytes | Length and arbitrary bytes |
| 8 | List | Four-byte item count, then values |
| 9 | Map | Four-byte pair count, then string key/value pairs |

Map keys must increase strictly in lexicographic UTF-8 byte order; duplicate
and out-of-order keys reject. Signedness is retained even for small positive
integers, and floats preserve negative zero. NaN and infinities reject in this
initial profile. No implicit integer conversion or truncation is permitted.
Future JavaScript bindings must use tagged integer values and BigInt when a
magnitude exceeds the exact Number range, including unsigned values through
`2^64 - 1`; BigInt alone cannot preserve the signed/unsigned tag. Lua also needs
an explicit representation for unsigned values outside its signed integer
range. These are requirements on future bindings, not cross-language evidence.

## Messages and connection order

Identifiers are 1..128 ASCII letters, digits, dots, underscores or hyphens,
encoded using the ordinary string field. IDs are nonzero unsigned 64-bit
integers. Each connection serves one selected component and archive.

| Tag | Message | Payload after tag |
| --- | --- | --- |
| 0 | Hello | Component identifier, raw 32-byte archive SHA-256 |
| 1 | Request | ID, method identifier, timeout, argument value |
| 2 | Response | ID, result value |
| 3 | Error | ID, error-code identifier, message string |
| 4 | Cancel | ID |
| 5 | Shutdown | None |
| 6 | Stopped | None |

Timeout uses a zero tag for no deadline, or a one tag followed by a nonzero
four-byte remaining duration in milliseconds. Other tags reject. The future
supervisor must measure elapsed time with its own monotonic clock, stop work
when required, and handle an unresponsive worker. This codec does not implement
those actions or promise that a runtime can be interrupted safely.

The worker begins with Hello. The controller checks its expected component and
archive digest before issuing requests. This digest identifies an input; it
does not authenticate a peer or prove that the worker loaded that input. The
future launcher must transfer and verify the selected archive/provider itself.

After Hello, the controller sends requests with strictly increasing IDs.
Results may arrive out of order. The ledger retains only pending IDs, bounded
by a caller-selected cap of 1..4096. A rejected local backpressure check does
not reserve the ID, so the unsent request can be retried after a slot frees.
Completed IDs cannot be reused, without retaining an unbounded completed-ID
history. After `u64::MAX`, the connection cannot accept another request.

Cancel records intent and retains the pending slot. Exactly one Response or
Error completes that ID, whether completion or cancellation wins the race.
Duplicate cancellation and unknown/duplicate terminal IDs reject. A controller
must omit cancellation once it has observed completion; a future worker-side
ledger still needs to define a stale Cancel that crossed a terminal response
in the opposite pipe. Wire encoding alone does not resolve this transport race.

Shutdown stops new requests and enters draining. Existing requests still need
terminal results, and the controller may cancel them while draining. The worker
sends Stopped only after draining and finalization. EOF without Stopped is an
incomplete lifecycle, even when framing EOF was clean. A future supervisor must
also inspect exit status and handle crashes. Sending controller-only messages
from the worker, worker-only messages from the controller, repeated Hello or
premature Stopped rejects. The ledger requires codec-validated messages and
records outgoing messages immediately before transport; a failed send ends the
connection instead of rolling back a possibly partial write.

## Transport fixture and remaining work

`fixtures/worker-protocol` is a Rust test helper, not a language worker or
deployment dependency. Its stdin/stdout are reserved for the synthetic protocol,
and ordinary diagnostics use stderr. Future product workers require dedicated
inherited anonymous-pipe descriptors/handles, keeping protocol traffic separate
from application stdin/stdout/stderr. Anonymous-pipe inheritance on Windows,
launcher re-execution, archive identity transfer, provider acquisition, runtime
bindings, worker-side cancellation races, queue budgets, real deadlines,
crash propagation and end-to-end mixed-language execution remain pending.

The tests cover independent byte vectors, malformed frames, field/container
budgets, fragmented/interrupted I/O, precise EOF behavior and the controller
ledger. The subprocess fixture covers values, error results, cancellation and
acknowledged shutdown over real pipes on the observed Mac/Linux cells. It does
not establish Windows/FreeBSD execution or the no-extraction behavior of future
runtime workers. No existing runtime, loader, manifest or CLI profile changes.
