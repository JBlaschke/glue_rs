# Adopt fixed descriptor observations in the owned bootstrap READY path

Status: implementation decision; native trace and full extraction admission remain open.

29 October 2026. Add a source-selected `GLUE_FD_OBJECTS` runner profile, preserving
legacy public wire/IO models and default protocol behavior. Its status record is
an exact 512-byte envelope with distinct magic/version at byte zero, the existing
canonical 256-byte BW payload at offset32, five 40-byte backing/flag rows at288,
and zero reserved bytes. Only READY carries rows; rows must agree with its
binding and kept descriptors. GO also has distinct magic/version. Neither
profile detects, accepts or falls back to the other's records or partial prefixes.

The real child captures after numeric closure and signal verification, before
READY/GO, under the existing quiescent owned-child assumptions. The parent keeps
its actual stdout/stderr source references, validates the complete envelope and
request declarations, then matches observations against those held references
before trace start or any GO attempt. References remain owned through cleanup.
All IO, guards and comparisons retain the original absolute attempt deadline;
failed/late delivery is opaque, never decoded or replayed. Root-only native
admission, signal/credential policies and whole-child cleanup remain in force.

The new 512-byte IO result/API uses the same internal transfer engine while the
legacy 256-byte result and legacy accepted sizes remain unchanged. Fixed wrapper
translation units select the object profile through recorded source bytes. The
shared Python builder stays unchanged; a separate fixed, initially unconfigured
object-kit profile records its exact source roster and recipe. It admits no new
proof, kit, installation or execution. Real unprivileged gated controls and
source-isolated runner controls establish only their stated behavior.

After independently reviewed implementation commit C, a separate registration
commit R advances the two existing configured registries to C and updates only
reviewed changed source hashes. Their 34/41-source rosters, default compile lists
and literal proof entries remain unchanged. The real clean-checkout source
loaders must pass before integration. Historical kit/packet locks and approvals
remain unchanged; edited checkout files are not accepted under old source pins.

Backing observations are conditional metadata, not paths, OFD/generation IDs,
later-call bindings, native tracing acceptance or an extraction oracle. No VM,
sudo, SIP change, privileged collector or raw-evidence publication is performed.
