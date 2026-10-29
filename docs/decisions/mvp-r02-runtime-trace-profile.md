# Fixed runtime recipe session and image transport

Status: accepted for bounded source implementation; no native admission.

Add a separately named source-selected session/backend profile for the generic owned runtime recipe, using fixture identifier 2. The original context-probe session and both existing runtime boundary/image factories continue to require fixture identifier 1 exclusively. No public profile selector, mutable D program, target argument, admission boolean or completion downgrade is introduced.

`ts_runtime_init` shares a private initializer with `ts_init`, fixing the expected binding identifier at its public entry. The runtime object-status profile retains an exact successful READY+ATTEMPT prefix of 1024 bytes and failure prefixes through 1537 bytes; the original profile keeps its exact 512/769-byte bounds. Both retain actual owner checks, original attempt/cleanup deadlines, complete event binding, consumed provider readiness and BEGIN before GO, actual child lifecycle and once-only cleanup contracts.

`rt_recipe_images_create` selects the existing fixed version-2 image program and fixture-2 binding through a private closed profile. `rt_create` keeps the version-1 program and fixture 1; `rt_images_create` keeps the version-2 program and fixture 1. All retain confirmed complete READY, one actual owned child PID, output bounds, error/drop refusal, balanced bounded execs, resource ownership and strict cleanup. The non-Darwin factories refuse with the existing unsupported result and clear their output handles/operations.

This supplies factories for a later actual traced-runtime runner wrapper. It does not compose that wrapper, change a catalog or registry, grant a proof, run a provider/target, establish native calibration or output capabilities, or claim full runtime/MVP acceptance. Existing generic launch and parent witness adoption remain separately reviewed dependencies.

Controls must show original/new cross-refusal, exact event binding, fixed program selection, preserved image counts/limits and owner/deadline/fault/cleanup behavior. Portable and injected native-transport controls run without any provider or target execution; retained receipts distinguish that scope.
