# Preserve read-ahead while validating archive headers

Status: approved by the integration owner for R03.

Archive validation intentionally seeks to each central/local ZIP header and
checks every declared bound and identity. Direct File access translates each
small header field into an OS read/seek. Ordinary BufReader invalidates its
buffer on absolute seeks, retaining most of that cost.

Add a reusable Read+Seek adapter with a maximum 64 KiB read-ahead buffer and a
tracked logical position. Translate absolute seeks to BufReader.seek_relative
when their offset fits i64; standard buffering retains nearby bytes and
invalidates on distant seeks. End seeks delegate normally. Failed I/O clears
the tracked position, and underlying failures propagate. No archive bytes,
validation rules, manifest schema or integrity checks change.

Use this adapter for filesystem-backed product resource readers. The bounded
buffer is per reader, independent of source-entry count; it never materializes
or extracts archive entries. Keep unbuffered and memory readers usable through
the existing generic Archive API. Measure read/seek counts before setting the
R03 cost budgets, including the 10,000-entry corpus.
