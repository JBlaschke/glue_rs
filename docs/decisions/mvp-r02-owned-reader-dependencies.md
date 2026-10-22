# R02: bind the extended owned reader's code dependencies

Status: accepted for source integration. Native acceptance remains open.

The BSD observation and closed call-pairing extensions preserve `RawFacts` and
the old `validate_raw` transport contract, but change the reader's source hash
and introduce an eager, fixed sibling import of `syscall_contract.py`. The
complete portable baseline correctly refuses the old case-source pin. Simply
advancing that pin would leave the calibration loader's transitive code
dependency unbound.

Advance the case codec metadata and exact source controls to the reviewed
reader at `0f2051e`, SHA-256
`1d8616b51002225c8b9abf4a18940c48f01d1ef97a3f7c54e120153ca8c978ec`.
Keep the selected legacy codec definitions and complete case implementation
unchanged. Advance the calibration loader's reader/codec pins coherently.
Before importing any of its three libraries, verify all their fixed path/hash
pairs and the fixed `syscall-contract/syscall_contract.py` helper, SHA-256
`35a4229894dd0373de1b312747e8acd1a23ae2074566391e8d28855ca0624dbf`.
Missing or modified helper/library code must refuse before any `load()` call,
including when modules have already been imported. Retain each loader's existing
path checks and recheck at load. Tests use an isolated temporary source layout;
they do not modify repository code or production approval globals.

The legacy aggregate validator never parses the contract asset, so this route
does not read `contracts.json`, run the new projections or issue a state-feed
permission. Source consistency assumes the trusted source tree remains stable
during loading; it is not authentication against concurrent privileged changes.
Native source kits, preparers, registries, packet/admission identities and older
evidence remain unchanged. New source/fixture tests and a full local baseline
must pass; neither supplies native calibration or full Darwin R02 acceptance.
