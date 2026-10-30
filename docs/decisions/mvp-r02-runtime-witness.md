# Exact runtime launch and held-output witness

Status: accepted for bounded source implementation; native admission remains open.

Compose the reviewed fixed runtime recipe and repeated-image profiles without importing main or changing their default admission. Add a separate strict reader for the actual generic RR/RC/TL bytes, 16 MiB launcher limit and independent sibling CWD. Existing probe v1/v2 public profiles remain fixed. Actual stdin is read-only character backing from /dev/null; stdout/stderr are distinct single-link write-only regular backing, gate/status are nonblocking FIFOs.

Retain the parent's four original complete held-reference samples in their actual order (first stdout/stderr, second stdout/stderr), including complete failure prefixes. Do not reconstruct these from a match boolean or derived output summary. Keep the old helper API as a wrapper over the same private engine; the new observed entry adds no retries or weaker acceptance. All-or-none match publication remains unchanged.

Before tracing or GO the actual owned parent writes a fixed 320-byte GLUERW01 witness, binding owner/child and exact request/catalog/READY SHA256 values. It includes sample count, closed helper error fields and four complete FD/status/backing rows. Unread rows are zero, failures refuse the reader, and success requires four originals. The reader independently compares both samples and the exact child READY observations. These are trusted collector consistency facts, not native authentication, OFD identity, kernel generations, path identity, atomicity or capability authorization.

Retain actual confirmed GO prefix bytes and the actual BIO outcome and gate close outcome separately; never replace a failed/full-delivery observation with a re-encoded successful GO. Whole capture/image validation must precede any successful public result. No state-feed, native/full acceptance, provider/VM/SIP action or configured runtime proof is added by this source feature. Next are the fixed traced-runtime adapter, capability policy and native corpus/budgets.
