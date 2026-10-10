# Installed host startup regression

These eight fresh GNU Linux arm64 captures retain the existing
[explicit host startup fixture](../../../../fixtures/python-host/README.md)
from clean implementation `9aababab78156f84628128060b64f51906bde5fe`.
The source status and diff records are empty. Image identity and compressed
replay instructions are in the [parent evidence](../README.md).

The 3,266,864-byte release launcher has SHA-256
`bc0d43be649fc4eb9b0c15720baad5e77556b37f2369ea9e68be10a82f3b27c5`.
Success and app-error use the 2,741-byte archive, SHA-256
`950ce62eaeab9eb59dbe3777b087e0428b97fbbb0fc4fddd98747de11da11d18`.
The other archives are 2,767–2,777 bytes; their exact identities are retained
in `fixture-summary.json`. The declared installation supplies the unchanged
73,563,968-byte CPython 3.13.16 library and six pinned startup sources.

| Mode | Records | Exit | Stdout / stderr bytes |
| --- | ---: | ---: | ---: |
| success | 1,718 | 0 | 111 / 0 |
| wrong-library | 1,298 | 1 | 0 / 123 |
| wrong-stdlib | 1,373 | 1 | 0 / 134 |
| missing-encodings | 1,366 | 1 | 0 / 160 |
| symlink-stdlib | 112 | 1 | 0 / 132 |
| missing-library | 169 | 1 | 0 / 146 |
| cached-bytecode | 148 | 1 | 0 / 152 |
| app-error | 1,721 | 1 | 111 / 63 |

Successful output is exactly:

```text
PASS Python=3.13.16 encodings=installed math=built-in ssl=built-in answer=42 openssl=OpenSSL 3.5.9 29 Sep 2026
```

Invalid host prerequisites reject before image mapping or initialization;
app-error prints success before its diagnostic. All eight raw captures and
compressed replays pass the unchanged installed-host policy with one PID each.
Release tests report 56 passes and Clippy succeeds.

The installation remains read-only after no-follow path checks, cache absence
checks and complete pinned library/source hashing. Source opens establish
installed `encodings`; this startup regression does not certify general host
imports, whole-stdlib identity, runtime discovery, or native extensions.
