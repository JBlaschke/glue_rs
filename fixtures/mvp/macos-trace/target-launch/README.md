# Copied source-selected launch data

`target_launch` is a pure fixed-capacity argv planner. It accepts a separately
supplied executable span and a compiled recipe containing target, literal
argument spans and an environment count. The current closed target is
`TL_AARCH64_DARWIN`; the only accepted environment count is zero. It copies the
executable and 0..15 arguments into 4096 bytes, including every terminator, and
exposes at most 16 non-NULL argv entries plus the terminating NULL and exactly
`envp={NULL}`. No allocation, syscall, callback, shell, expansion, PATH lookup or
inherited environment is involved.

The first tested compact vector is absolute glue, `run`, absolute `app.glue`,
`--`, and a literal case argument. Spaces, UTF-8 and non-UTF-8 argument bytes are
copied exactly; an empty span is an empty argument. Embedded NUL bytes refuse.
Only the executable receives path-shape validation: absolute, 2..255 bytes,
nonempty components, no `.`/`..` components and no trailing slash. This check
does not open, resolve or admit a path. A general argument can contain arbitrary
path-like text or shell metacharacters without interpretation.

The caller must provide stable, readable and nonaliasing input storage for the
call, then keep the completed plan at its original address without mutation.
Its argv pointers refer into its own fixed storage; copying or moving the struct
does not rebase them. Preparation clears the entire output before validation,
so failed preparation cannot leave an older ready plan. Input storage may change
after success because the plan retains its own bytes.

`tl_canonical` validates the plan's internal layout and returns version-one
binary bytes: domain `GLUETL` followed by zero and one, target BE64, total argc
BE32, envc BE32, and a BE32 length plus exact non-NUL bytes for every argv entry,
including argv[0]. No environment entries follow because the environment is
empty. Length framing distinguishes absent/empty arguments and boundaries.
`TL_CANONICAL_CAPACITY` is 4184 bytes, a conservative fixed bound. On failure the
supplied canonical output is cleared and its used count is zero. Canonical
validation is structural; valid invocation-byte changes produce different bytes
and require the caller's separate source/catalog identity comparison.

This helper supplies expected input data, not authorization, native executable
or CWD admission, runtime closure verification, successful execution, tracing or
MVP acceptance. The initial bootstrap-to-glue environment may be empty while
existing compact code creates a declared environment for its later Python/Node
exec. macOS host checks can also spawn `sw_vers` and a reader thread. Later
adoption requires complete lifecycle joins, a quiescent successful exec epoch
and CLOEXEC/mapping transfer; a one-exec reader does not establish that chain.
See `docs/decisions/mvp-r02-runtime-launch-recipe.md`.

Run `python3 test_target_launch.py` for eleven pure C data controls. Set
`GLUE_LAUNCH_TEST_RETAIN` to a new directory to retain compile/control argv,
statuses, streams, source hashes and the compiled control binary; failed
attempts are retained too. `GLUE_LAUNCH_SANITIZE=1` enables address and undefined
behavior sanitizers for those controls. They execute no target application,
credential transition, provider, VM or privileged bootstrap.
