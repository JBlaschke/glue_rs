# Read-only bootstrap deployment inspection

The native nontracing controller will compile a closed fixture catalog containing
the actual guest's root/Data device and filesystem IDs. Host values cannot stand
in for those guest observations. Add a small, ordinary-user Darwin inspector
before preparing that catalog. It accepts no arguments and opens only the fixed
physical directory chain `/`, `System`, `Volumes`, `Data`, `Library` with held
no-follow/CLOEXEC directory descriptors. It never executes a target, forks,
changes credentials or signal/security state, or creates a file.

Use the reviewed admission adapter's read-only metadata callback, but do not treat
its zero return alone as complete metadata. Require all three scalar population
bits and typed owner/group/mode equality, absent ACL, root owner, directory type,
no group/world write or set-ID, and the declared local APFS root/Data transition.
Record all five component device/inode/mount facts, including raw mount flags.
This is a bounded observation under a stable namespace, not protected executable
admission, provisioning provenance or an authenticated host identity.

Also record actual nonzero real/effective IDs, the unsorted kernel group vector
(bounded at 256), a derived tc-compatible boolean, kernel release, hardware model
and observation time. No account lookup, environment dump, password, current home
path or caller-supplied target identity is used. These normal-user observations
inform the later explicit request; they do not silently become a privileged
launch request or authorize any code. Linux fails unsupported before inspection.

Close every newly opened descriptor once before emitting the bounded JSON. Any
query, close or output failure invalidates the result; close/EINTR is not retried.
The consumer requires normal exit zero and a complete exact-schema JSON document.
Retain source/build hashes and original output outside Git. An observed device
profile must be reviewed for the selected guest before generating the controller
catalog; no runtime profile/path/hash override is added to the root CLI.

Native host controls check only read-only API behavior and enclosing parent state.
They are separate from a later guest run, protected fixture installation,
root-to-nonroot transition, tracing and full R02/M2. Guest SIP stays enabled.
