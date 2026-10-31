# Quiescent runtime images, version 2

`pair_runtime_images_raw()` correlates up to sixteen successful same-PID exec transitions and observed ordinary thread lifetimes from the complete original raw stream. Its fixed v2 program/factory are separate from v1. V1's public inputs, output and exactly-one-exec refusals remain unchanged. This source feature supplies pairing facts for a future compact launcher → Python/Node chain; it does not yet adopt a generic launch recipe or prove that native chain.

Use `runtime_images.LaunchEvidence` for the same six exact byte assets described in the [v1 README](README.md): request, catalog, object READY, distinct GO, EXEC_ATTEMPT and initial target artifact. The inherited canonical evidence validator still selects the existing `context-probe` catalog. Generic protected target/catalog adoption remains separate. Supplied bytes, source/recipe claims, owner PID and unreaped-child context remain trusted collector obligations, with no new admission boolean or native authentication.

## Fixed factories and complete transport

`rt_images_program()` and `rt_images_create()` select only the v2 marker:

```
/* glue-runtime-images-v2; quiescent-exec; no-process-creation */
```

The C producer and backend use private common formatting/transport paths with fixed v1/v2 factories. They do not expose a mutable profile, arbitrary D source or a completion downgrade. V1 still requires exactly one exec entry/success. V2 requires balanced, nonoverlapping entries/successes from one through sixteen. Creation/spawn, opaque Mach and the closed unsupported BSD rights/image routes are serialized before whole-session refusal. It still watches one PID; descendants are not covered. The reader additionally bounds the retained stream at 8192 phases, complete pairs at 2048, capture-local thread instances at 256 and unbound shadow contexts at 64; these finite fixture limits are not a calibrated general-runtime capacity claim.

The Python reader independently matches exact program bytes. The same private transport parser validates every physical line once, including inventory/probe identity, widths/offsets, all scalar words, enablings, PID/parent context, empty errors and full BEGIN/terminal/END. Only after exhaustion does the private initial-image stage check the original bootstrap prefix. It returns internal state at the real selected LWP start, without adding a terminal, return or footer. V2 then checks every remaining original phase before returning anything. Transport/source/iterator failures cannot return an earlier image as a successful prefix; semantic refusals retain only the completely validated raw capture.

## Images and threads

The initial bootstrap's exact gate read/EOF/once-only close and remaining-suffix EXEC_ATTEMPT writes retain all v1 checks, partial intervals and source-defined BIO retries. The initial artifact SHA and requested executable path are attached only as supplied byte identities to transition 0→1. Every later transition has `requested_path=None` and `artifact_sha256=None`; raw execve addresses are never dereferenced or promoted into pathname equality.

A later exec entry requires exactly one active user-image actor, no other active/reserved thread, no other pending ordinary call and no transition already in progress. The success boundary uses a distinct new TID, followed by process start and LWP start. A fresh exec-thread declaration, if observed, must resolve to that same new actor. A second entry, mismatched startup actor/order, failure, unresolved reservation or concurrent ordinary activity refuses.

`ThreadInstance.capture_instance` and `.generation` identify only capture-local observed lifetimes. Ordinary declaration/start/exit records create and retire those instances. A declaration binding explicitly distinguishes its subject (the declared TID in detail) from `source_actor_instance` (the creator in the original header); it does not pretend the new thread emitted its own birth record. A numeric TID can be reused only following an actual observed LWP exit, creating a different instance/generation. Image replacement and observed kernel-thread retirement are separate fields: replacement can close an old user image while its actual LWP exit remains unobserved. A uniquely identified older image-replaced thread's actual LWP exit can interleave a later startup, retiring only that non-live instance. It cannot consume or replace the new live actor's required startup records. That old actor cannot run ordinary calls, become a new generation or grant a capability merely because an exec succeeded.

An optional canonical EJUSTRETURN projection is linked uniquely to its original exec entry and retained as transition context, including when it races after new-image startup or a later image. It is not an ordinary successful pair, pending live-user call or proof of harmless effects. A duplicate/noncanonical projection or one after that old thread's observed LWP exit refuses. Exact `exit` entries can end through their same-actor process-exit context as `ProcessTerminalCall`, without inventing a successful return or interpreting the raw lifecycle detail as POSIX status. Other pending calls at LWP/process exit remain unsupported. In particular, an unclosed `bsdthread_terminate` is not silently accepted: its pinned XNU shim delegates to external pthread implementation and can return ENOTSUP; its complete terminal/effect contract is not established here.

The reader retains all original phases, raw BSD entry/return pairs, image transitions, capture-local thread instances and lifecycle bindings. Unknown ordinary BSD calls remain uninterpreted pairs, without a no-write classification. It supplies no FD/OFD identity, output sink seed, mapping policy, success-effect ordering, rights interpretation or filesystem no-extraction verdict.

## Shadow proc context

Shadow `proc:::exited` records remain explicitly **unbound** context. They do not terminate the live selected PID, retire a live actor, close an interval, satisfy an exec success or authorize state/capability. Their proc address is never mapped to an image, thread or kernel generation; a delayed event can cross later execs without inventing attribution. `unresolved_shadow_attribution` reports that limitation. Count/order never creates an image boundary. A nonshadow terminal still obeys complete live-process exit/END rules.

The pinned role is grounded independently: [proc_internal.h:215](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_internal.h#L215) defines P_REF_SHADOW=0x20; [kern_exec.c:5246–5251](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c#L5246) replaces the PID-hash proc and transfers that flag to the old proc. [kern_proc.c:2384–2394](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L2384) retries live PID lookup on a shadow. This source-defined non-live role does not interpret shadow cleanup's filesystem effects or supply native coverage calibration.

## Source and controls

Kernel source commit remains `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`. The retained [v1 source audit](README.md#exact-source-grounds) supplies exec/new-thread startup, canonical provider returns and nonreturning process exit. Additional original-byte anchors:

| Source | Ground | SHA256 |
| --- | --- | --- |
| `osfmk/kern/thread.c` | LWP exit at470; creation at1595; new-image startup at4419–4435. | `8a4d00524913a5082c8d157b33e9ed52c0899c82de371e1188b6f5c3143426e2` |
| `bsd/sys/proc_internal.h` | P_REF_SHADOW declaration. | `574ab558cfc7e2cb843014f2b000b3f7eba3c8bf210e0baefa661c232ef5e5cc` |
| `bsd/kern/kern_proc.c` | Shadow detection/live PID lookup. | `34f745a213769ffa47b4edace6e3e158f654075def1b0fe50edf97f9bf53589d` |
| `bsd/pthread/pthread_shims.c` | Thread termination dispatch and ENOTSUP branch,366–398. | `b4e9c4e1abb7410ceb59f5cd9b1208126cd81af83c8bd7a0f7a2a2c16c85fecc` |
| `bsd/kern/syscalls.master` | Thread termination declaration at542. | `7e866891439ad5b3464777d2cacc3b82fc2e7f439fb5a8686c3e6f160d5aeab5` |

Run `test_runtime_boundary.py` for the unchanged v1 controls, `test_runtime_images.py` for the new physical-stream/image/thread controls, and `test_runtime_trace_backend.py` for the native transport controls. Tests compare actual compiled v1/v2 C producers with independent templates and cover multiple/max execs, quiescence, observed generations, late projections, retirement/unknown terminal calls, unbound shadows, malformed/unsupported/later faults, single physical consumption and immutable fresh results. They do not run a provider or target.

Source snapshots and receipts remain ignored under `.evidence-local/controls/runtime-images-20261029/`. Native calibration, protected-target attestation, successful effect ordering, output capability seeding, state-feed eligibility and full trace acceptance remain false in every result.

## Fixed generic recipe transport factory

`rt_recipe_images_create` selects the same byte-for-byte version 2 program and
balanced one-to-sixteen exec transport for `TS_OWNED_RUNTIME_RECIPE` (fixture 2).
Its private closed profile fixes both choices. The existing `rt_create` and
`rt_images_create` entries remain exclusively fixture 1, with their original
version 1/version 2 program and completion behavior. A crossed fixture or anything
other than confirmed READY 1 refuses before tracing resources exist. Actual owner,
original deadlines, complete event binding, output limits and once-only cleanup
remain mandatory. All three factories clear handle/operations and return the
same unsupported error on the non-Darwin branch.

This entry supplies a later traced-runtime adapter; it does not itself compose
that adapter or relax this reader's existing probe launch-evidence contract.
Generic launch/held-output witness checking, protected deployment, native corpus
and state/capability admission remain separate. No registry or proof is added.

The injected backend controls run lifecycle, inventory, faults, ownership,
deadlines and version 2 exec limits through both fixed factories. They compare
the runtime factory's actual program with the fixed producer and exercise
factory/READY/fixture cross-refusals. `GLUE_RUNTIME_TRACE_RETAIN` keeps command
records, model binaries and source identities. SDK linking is never provider
execution; the injected executable defines every DTrace symbol itself.
