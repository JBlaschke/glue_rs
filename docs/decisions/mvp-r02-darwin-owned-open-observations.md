# Observing calibrated native open frames

The eight completed v5 guest controls establish direct BSD `open` framing on
Darwin 25.6.0 arm64, macOS 26.6.2 build 25G83. The independent calibration
report has SHA256
`0b2bdbf754a93d9e80886299e5bd82d78eff1d036393568decefd82a5ecc5715`;
its original raw inputs remain in the separate Darwin evidence checkpoint.
It checked fifteen controlled calls: eight successful opens and seven ENOENT
returns. Entry and copied-path callbacks have distinct timestamps and EPIDs.

Add a real-record observation API after the source-matched capability reader.
Initially require a completed `open` profile, one owned root and one calling
thread, and this exact observed host. Pair entry, copied path and return by
PID/TID and consumer order. Preserve all three raw frames and their provenance.
Decode the signed 32-bit flags argument, zero mode, successful descriptor and
ENOENT result only when the complete raw tuple matches the calibrated contract.
Other errors, modes, threads and profiles are unsupported. Retain arbitrary
flag bits as data; a write-capable startup request is not erased or allowed.

Call the bytes a copied user pathname, not a resolved kernel pathname. Require
a NUL before the final string byte and zero trailing padding; a terminal NUL
alone cannot disambiguate truncation. Preserve the full original string record.
Never UTF-8 re-encode native-byte JSON argv when comparing pathname bytes.

This adapter is a prerequisite for the real raw decoder. It does not infer FD
objects, pathname lookup, process generations, complete syscall coverage or an
extraction policy. Its API and CLI always reject full R02 acceptance. Synthetic
boundary tests remain explicitly synthetic; actual v5/v6 replay is separate.
