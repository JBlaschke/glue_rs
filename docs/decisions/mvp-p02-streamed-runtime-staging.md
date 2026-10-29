# Stream large PBS runtime members during build-time staging

29 October 2026. Native compatibility run `40851345339` proves that the x86
full and install-only CPython 3.13.16 archives contain a required
`lib/libpython3.13.so.1.0` of 143,259,064 bytes. The current archive materializer
rejects it because the selective reader retains at most 128 MiB in memory.
All 24 ordinary tree cases, five budgets and the other five compatibility cases
pass; arm64 passes all seven routes and complete independent replay.

Add a selected-member streaming API to the existing bounded tar validator. Share
header, path, link, checksum, payload hashing, count/size and end-padding checks
with the retained selective reader. The retained reader keeps its 128 MiB cap.
The streaming reader writes bounded chunks to caller-provided writers, never
retaining a complete native member. Existing 256 MiB member, 2 GiB tar payload
and 3 GiB decompressed-stream limits remain; the Python materializer still caps
selected staged bytes at 1 GiB and compressed input at 1 GiB.

Streaming sinks can receive bytes before the rest of the archive validates.
Callers must quarantine those outputs and discard them on every error; success
does not make individual earlier callbacks transactional. The Python builder
uses a private fresh staging directory, creates regular files exclusively and
creates validated internal aliases only after the entire inventory matches the
first pass and the original compressed input identity is rechecked. Its existing
RAII cleanup removes failed staging; nothing is published or probed from an
unvalidated stream. Preserve input bytes, selected files and file modes.

Regression controls must exercise a member larger than 128 MiB with bounded
writer chunks, retained-reader refusal, stream/aggregate/member bounds, writer
failures, malformed late archive data, missing/nonregular selection and staging
cleanup. Re-run the actual failed native archive cases after source review; do
not relax a limit, substitute stripped input, waive a case or promote the old
failed receipts. This changes build-time input handling only; deployed launchers
still never extract runtime payloads.
