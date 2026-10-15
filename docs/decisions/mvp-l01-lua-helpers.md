# Selectable Lua helper processes

Status: implemented by MVP task L01.

Keep the existing linked Lua adapter and C-owned error boundary. Build it twice,
as `glue-lua54` and `glue-lua55`, and install both with one installer command.
Cargo feature selection is internal to that installer. A helper links exactly
one Lua family. This preserves existing direct launcher routes and avoids symbol
collisions and cross-version Lua states in one process.

The packager selects a helper from explicit installation directories or its own
executable directory, probes its versioned JSON descriptor, and records the
selected executable's bytes. Execution does not search PATH. Only the selected
helper is copied into a compact distribution. The subprocess command is an
executable plus argument vector, never shell text. Descriptors identify the exact
Lua patch release, target, build ID, source identity and int64/float64 ABI.

Helpers accept both the existing archive manifest and C01's compact distribution
schema. Both reject incompatible declarations before running source. Compact
native loading is implemented separately by L03; an undeclared or unavailable
native capability never silently selects the legacy memory loader.
