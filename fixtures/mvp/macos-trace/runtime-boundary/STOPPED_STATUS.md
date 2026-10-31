# Stopped-runtime lifecycle status

`rt_stopped_status` is a separate pure getter for a live stopped-runtime backend.
It returns the existing observed-prefix identity and an actual lifecycle copy,
including deadlines, binding, total outer events, operation attempts, first and
late close errors, and each writer's attempted/failed mask and retained errno.
Its common and extra phase counts remain in their explicit identity domains.

The getter does not derive success. An earlier capture error can coexist with
`resources_closed=1`; a post-close clock failure can do so too. An unsuccessful
writer close retains `resources_closed=0` and its original per-writer errno.
Closed resources without drain or END remain distinguishable from completed
drain. Native, state, exemption, quiescence and full-flags authority fields are
always false. No native provider or controller is selected by this API.

The old `rt_snapshot` ABI is unchanged and still refuses the stopped class.
The existing prefix getter and ordinary factories/options/programs are unchanged.
The new getter clears output when refusing null or a foreign class. The caller
must own a live backend, keep output non-aliased and avoid concurrent mutation.
After `rt_destroy`, use the owner's now-null pointer; never use a stale freed alias.

Focused models reuse the existing source-isolated producer fixture through a
renamed-main include. Two conditional hooks exist only in this stage's copied
test fixture: count model clock calls and observe an actual model writer close.
They permit a clock fault after the final real close, without changing production
callbacks. Each model captures actual internal lifecycle state before invoking
the new getter, checks exact copies and no backend/clock/option mutation, and
retains the observed per-writer outcomes. The injected-close-error fixture really
closes its descriptor but reports EINTR; production ownership stays unresolved,
and `rt_destroy` must refuse. Only test memory is discarded afterward. This is
not evidence of resolved production ownership or native capture acceptance.
