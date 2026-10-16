# Darwin capability session enabling bindings

The source-matched capability reader already checks each record's descriptor,
clause layout and retained probe inventory. Those checks alone let a rebuilt
synthetic stream swap enabled-probe IDs (EPIDs) between otherwise valid phases,
or introduce a fresh EPID for a clause midway through a capture.

For one `inspect_capability` session, bind each observed EPID to its immutable
static signature: probe ID, provider/module/function/name, event kind, probe
byte total, explicit header indexes, and every record's action/size/offset.
Changing any signature member rejects the session. Separately bind each
`(kind, probe ID)` to one EPID. This reviewed generated program is compiled and
enabled once per collector handle, with one clause per such pair; its generic
open-entry and named path-copy clauses have distinct kinds and EPIDs. A new
EPID for an already observed pair also rejects. Per-call timestamp, CPU, PID,
TID, detail, numeric values and raw byte hex are not enabling identity.

Run these checks after strict per-event validation and before ledger updates
or timeline export. Both maps belong to the current inspection, with no state
shared between captures. Each map admits at most 8192 observed enablings. This
is an explicit diagnostic resource limit, not a kernel provider completeness
claim; a larger session rejects rather than dropping identities or weakening
the inverse binding. Tests exercise the boundary using a small patched limit,
not a large allocation.

The raw protocol schema and exported summary stay unchanged. This is a stricter
transport consistency check, not a new Darwin ABI decoder. Historical captures
retain their source-matched frozen readers. A separate replay may apply this
binding check to already validated historical raw exports without rewriting
those bytes or claiming new native execution. Event gaps, counts, identities,
completion checks and the unconditional full-trace rejection remain intact.

Synthetic two-call controls rebuild inventory and evidence hashes, then reject
phase swaps, fresh-ID duplicates, static signature changes and enabling-limit
overflow. Valid changing call values and repeated stable enabling identities
remain accepted as transport units only. Native filesystem extraction
acceptance remains unimplemented by this capability format.
