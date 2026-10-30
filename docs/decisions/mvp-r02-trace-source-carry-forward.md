# Explicit carry-forward of the compiled-selector tracing source

29 October 2026. The READY-adoption branch inherits `owned_trace_backend.c` from
commit `490a8c311d553dabaf181d8b16dd6ce200c5b96e`. Its existing configured trace
registry still pins the earlier SHA256
`061a9b1fe4af126a542fb65a4f20a7179cbe5c79b4fcd2e70b5732ce14fe97ff`; the checked
source is `1437b50fec4e4f30d0292cb812010b4aaf72e6e28bb1cadbbf77186fd9474c0e`.
This discrepancy predates the READY implementation and must be admitted explicitly.

Independent source review covers the bounded compiled-selector inventory,
selector/kind completeness, duplicate and overlap rejection, exact enabled-match
count before GO, and the original attempt deadline. Root also inspects the
original change. Admit that exact checked source for the upcoming C-to-R source
registration, separately from the READY changes. No backend bytes change here.

The trace registry's 41-source roster, compile lists and literal historical proof
entries remain unchanged. The default registry retains its 34-source roster.
A new source revision is not evidence that a historical kit was built from it.
Historical kit/packet locks and artifact approvals remain bound to their own
bytes. The new object profile remains unconfigured. This decision supplies no
provider execution, native calibration, filesystem verdict or M2 acceptance.
