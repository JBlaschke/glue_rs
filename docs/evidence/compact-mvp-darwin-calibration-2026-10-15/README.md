# Owned Darwin calibration checkpoint (preliminary candidate02)

This checkpoint preserves diagnostic captures from the explicitly authorized
owned macOS test VM and their source/review identities. It is separate from the
[frozen combined MVP checkpoint](../compact-mvp-2026-10-15/README.md); that
18,588-file source inventory and its archive remain unchanged. This directory
commits narrative and hash inventories only. No evidence has been published and
there is no `bundle.json`. This version freezes the completed local v3–v8
calibration and reviewed pairing evidence. At preparation, guest SIP restoration
awaited private owner authentication in Recovery. It contains no restored-SIP
proof and does not close full Darwin R02 or M2 acceptance.

## Selection and scope

`local-evidence.sha256` selects ordinary files relative to `/private/tmp` from
these explicit owned inputs:

- `glue-mvp-macos-vm-results/glue-mvp-guest-native-v3-jWaBxiJ3`: the original
  nine-case guest calibration batch, including commands, metadata, raw transport,
  copied collector/fixture source and binaries, probe inventory and verification
  records;
- `glue-mvp-macos-vm-toolkit/reader-v2`: the five frozen reader/source files used
  to review the original protocol, retained byte-for-byte;
- `glue-dtrace-temporal-source`: the pinned public Apple libdtrace/XNU source
  investigation, source hashes and its explicit inference limits;
- `glue-guest-native-v3-independent-review-20261015`: the independent strict
  reader audit, all nine per-case rejection streams, the review driver and an
  explicitly preserved earlier review-only assertion failure log;
- `glue-darwin-native-toolkit-guest-v4`: the frozen descriptor-diagnostic source,
  compiled owned fixtures and collector, build commands, strict signature checks,
  library/load-command records and explicit provenance;
- `glue-mvp-macos-vm-results/glue-mvp-guest-native-v4-vEYsWITo`: the actual
  open-only v4 failure and its rejected descriptor, commands, metadata and copied
  toolkit bytes;
- `glue-darwin-native-diagnostics-root-test-20261016.log` and the exact
  `guest-native-v4.sh` / `guest-sip-status-v1.sh` files under the existing toolkit:
  the explicit host control log and the immutable calibration/status wrappers.
  Selecting the status wrapper does not claim it has been executed;
- `glue-guest-native-v4-independent-review-20261016`: the independent v4 audit,
  source-matched frozen reader and retained rejection streams;
- `glue-darwin-native-toolkit-guest-v5`, `glue-darwin-capability-reader-f7fc776`,
  the exact `guest-native-v5.sh` wrapper and the explicit
  `glue-darwin-native-layout-v2-root-test-20261016.log`: the frozen raw-v2
  diagnostic producer/reader and host controls;
- `glue-mvp-macos-vm-results/glue-mvp-guest-native-v5-DaKZWirY` and
  `glue-guest-native-v5-independent-review-20261016`: all nine actual v5
  diagnostics and their frozen independent transport/ABI review;
- `glue-guest-native-v5-validated-timelines-20261016` and
  `glue-darwin-source-contract-v5-review-final-20261016`: the independent frozen
  strict-reader exports and read-only source-contract observations, all retaining
  false acceptance and the failed spawn status;
- `glue-darwin-capability-reader-e3274dd`: the frozen target-aware raw-v3 reader;
- `glue-darwin-owned-open-observer-1408f3a`: the final independently reviewed
  bounded owned-open observer, its source-matched reader/fixtures, controls and
  direct-open diagnostic replay outputs;
- `glue-darwin-native-toolkit-guest-v6` and the exact `guest-native-v6.sh`
  wrapper: the frozen target-aware lifecycle producer;
- `glue-mvp-macos-vm-results/glue-mvp-guest-native-v6-rYilzb7D`: all nine
  actual raw-v3 guest diagnostic attempts;
- `glue-guest-native-v6-independent-review-20261016-complete`: the completed
  audit of all nine original v6 attempts, including the retained initial partial
  review and final failure/identity findings;
- the explicit `glue-portable-darwin-followup-{macos,linux-arm64}-20261016.log`
  files and `glue-portable-darwin-followup-tests-20261016.sh`: the named portable
  unit-control logs and exact driver, selected singly;
- `glue-darwin-capability-reader-7135bca`: the exact immutable seven-file
  reader/source snapshot for the session-binding change;
- `glue-darwin-enabling-bindings-replay-20261016`: the session-binding
  consistency replay of the original v5 records against the new reader invariant;
- `glue-darwin-native-toolkit-guest-v7-final` and
  `glue-darwin-native-toolkit-guest-v8`, plus the exact `guest-native-v7.sh` and
  `guest-native-v8.sh` wrappers: the frozen raw-v4 producers. The earlier
  unpublished v7 toolkit is explicitly excluded;
- `glue-mvp-macos-vm-results/glue-mvp-guest-native-v7-Wq3BfdSd` and
  `glue-mvp-macos-vm-results/glue-mvp-guest-native-v8-dTVgGgQl`: all original
  guest attempts from both raw-v4 batches;
- `glue-guest-native-v7-independent-review-20261016`: the completed v7 audit,
  retaining seven validated exports and two failed-open rejection streams;
- `glue-guest-native-v8-independent-review-20261016`: the completed final
  audit and all nine source-matched validated exports;
- `glue-darwin-capability-reader-729bfea` and
  `glue-darwin-capability-reader-v8-729bfea-d4e9e93`: the frozen raw-v4 readers
  with source-matched v7 and v8 producer bytes respectively;
- `glue-darwin-syscall-contract-source-9be06a1`: the exact seven-file source
  snapshot needed to replay the selected lookup-only source observations offline;
- `glue-darwin-v8-open-observer-review-20261016`: the final source-matched
  observer review, two actual v8 replay outputs and historical documentation
  snapshots retained as reviewed;
- `glue-darwin-mach-msg2-assessment-20261016`: the bounded read-only Mach
  assessment, pinned Apple source bytes, exact source hashes and original
  packed-word observations;
- the explicit `glue-portable-darwin-final-{macos,linux-arm64}-20261016.log`,
  `glue-darwin-shadow-exit-native-tests-final.log` and
  `glue-darwin-open-drain-native-tests-final.log` files: the final named portable
  and host-native unit controls, selected singly;
- `glue-darwin-calibration-preflight-replay-20261016`, its exact standalone
  Python verifier and command log: the read-only preflight and its original
  1,329-file source-inventory snapshot. It predates this proof selection and
  does not observe SIP restoration;
- `glue-darwin-call-pairing-evidence-20261016` and
  `glue-darwin-pairing-independent-review-20261016`: the frozen raw-v4
  call-pairing source, 17 unit controls, seven whole-capture replays and the
  independent review, preserving unmatched entry records without invented returns;
- the exact `glue-darwin-call-pairing-root-{macos,linux-arm64}-20261016.log`,
  `glue-portable-darwin-pairing-tests-20261016.sh` and
  `glue-portable-darwin-pairing-{macos,linux-arm64}-20261016.log` files:
  the reviewed pairing and seven-suite portable controls;
- the three explicit `glue-darwin-calibration-root-{restore-candidate-01,
  replay-candidate-01-macos,replay-candidate-01-linux-arm64}-20261016.log`
  files and `glue-darwin-candidate01-linux-replay-20261016.sh`: independent
  preliminary-candidate restoration/replay proofs, selected without restored
  payload trees.

The frozen selection contains 1,372 ordinary files / 29,762,443 bytes. Its source
inventory SHA-256 is
`45bc7dfbe3cdd7b10711e8bc6589d55b3d44589d5af0180d57015c5437ead263`.
A later restoration-proof checkpoint will use a separate version and output
root. There is no broad copy of temporary directories, guest disk images,
credentials or unrelated private data.
Original capture and toolkit bytes are not rewritten. Absolute paths inside
receipts and traces retain their original logical meaning after restoration.

## Observations

The v3 batch records Darwin 25.6.0 / macOS 26.6.2, arm64, in an owned VirtualMac2,1
VM. Its authenticated `csrutil status` output records SIP disabled for the
explicitly approved calibration. Earlier SIP-enabled failures remain historical
diagnostics in the separate combined checkpoint. The physical host security
policy was not changed by this work.

All nine v3 capture attempts failed validation. Each reports two probe callbacks
but retains only event number two, because the first callback incremented the
counter and rejected its descriptor before writing a raw event. This is a
collector framing failure and a raw consumer-index gap, not a passed trace.
The independent audit reproduced all nine strict reader rejections for the
consumer-index gap and verified the originals remained 154 files / 706,241
bytes with aggregate identity
`a145c55a955d23b537b00713ee891c2dde8a9adfb0ba23aa0ed1e677bdcc25bc`.
Its audit passed; the captures remain failed. The review JSON SHA-256 is
`19a8d2d282adb40506ed9b7ad9e1fffe711e9370faf47076400439d0494a9161`.
The next retained event is either an END or a syscall entry. The compiler/go
phase succeeded and the retained probe inventory is 41,458 bytes; zero drops or
DTrace fault callbacks do not repair the missing event.

The source investigation identifies a supported explanation: the collector's
BEGIN clause assigns `watched[root]=1` before tracing its five uint64 values.
Apple's compiler represents an expression statement as a zero-sized DIF
expression action, while the kernel exports descriptors for such actions.
The existing consumer requires the first five descriptor sizes to equal eight,
so a leading assignment descriptor would reject this real BEGIN event. The
first rejected descriptor was not recorded in v3; this remains an inference
until fresh descriptor evidence confirms it. The same kind of assignment occurs
in create/start/exec-success and exit clauses. The primary-source commit
identities and exact source hashes are retained in the investigation record;
they are not claimed byte-identical to the guest's installed library/kernel.

These are bounded transport/calibration diagnostics. They do not implement the
complete Darwin syscall decoder, inherited descriptor/process-tree model or
adversarial extraction oracle, and cannot close R02 or M2 acceptance.

The actual v4 open-only capture remained failed with `header-width`. Its
retained `layout-error` identifies `dtrace:::BEGIN`, six descriptors and a
56-byte enabled-probe record. The leading DIF-expression descriptor has size
zero and offset 12; the five eight-byte descriptors follow at offsets 16, 24,
32, 40 and 48. This confirms the expected layout for this specific guest/owned
program. It does not repair the original v3 capture or establish a complete
Darwin decoder. The retained library diagnostics record explicit aborts during
work and drain; they must not be discarded as successful completion.

The independent v4 audit verified all 66 original files / 335,421 bytes remained
unchanged, aggregate
`0a0b4db386216cbded4add9816a8d2a78f1baf27717638f686f4122f124317a0`.
Its review JSON SHA-256 is
`ef652fb903ef94ee01e577a1d8b83a5aff9ae76dfbe430376a7d813b1538787b`.
An audit pass confirms the identities and failed observation, not capture success.

The host's ten v4 diagnostic controls passed on root integration `7ad6fce`
(producer commit `3b44dce`), as recorded in the selected control log. These unit
controls and signature checks are separate from the failed actual guest capture.

The frozen v4 diagnostics toolkit comes from commit `3b44dce`. Its collector
SHA-256 is
`f059cfeb8b05faa2d47e0cf3d5bb15fa66a745c83d9bc31f907168d4749749a4`;
its source/fixture manifest SHA-256 is
`4095226277b76cb19ec150ecb4a0f6ba4a1104c0a31b90e1dabdffaac8fbbbd3`.
Preparing and signing these bytes alone is not guest capture evidence.

The v5 producer comes from `281f1dd4c7d92db0241bd9f30e324968d2a10613` and the
strict raw-v2 reader from `f7fc776`. The collector SHA-256 is
`5559686c2d24d3b3d71e21de0e2ef84d9169355c723dd3bc8bdfbf12e96da200`;
the producer manifest SHA-256 is
`2cf1a9ef0c830b402dc0fe2d5bb40f3464d566aebc152261dd91540adfdc1d52`.
The independent frozen reader manifest SHA-256 is
`b820a634bcf286d081f394d8bee3e563bac40e6f39ef654570c61d4c85f4a68e`.
Twelve host native controls passed in the selected v5 control log on root
integration `980392f`; those controls are not guest trace acceptance.

The v5 batch retained eight captures with a drained root and one failed
`spawn-open` capture. All nine are transport-consistent in the independent
review, but none grants full acceptance. In the failed spawn case,
`proc:::exit` fired in the parent thread while a child exited. The collector
mistook the current probe PID for the target and stopped watching the live
parent, losing later syscall coverage. This is a genuine coverage failure, not
an inferred delayed child exit. The independent review preserves the guest
logical path's `DakZWirY` spelling and the host export's `DaKZWirY` spelling;
no captured string was rewritten to reconcile them. The frozen v5 review JSON
SHA-256 is `fd812e332ca2cc67f53b36aea296e0bf2b3a6d130b9017fc178e59585e214c0e`;
its bounded direct-open ABI review SHA-256 is
`0b2bdbf754a93d9e80886299e5bd82d78eff1d036393568decefd82a5ecc5715`.

The v6 toolkit changes lifecycle capture to an explicit `proc:::exited` target.
Its collector SHA-256 is
`f7134cede9e7f05dc5de74c188b4ed3d17d8ca406b620e7004af096a98048a54`;
its manifest SHA-256 is
`59c1d516910a07e756a03c4aebf3aa8625769e881d5a87e31b9cfcf21e3166bf`.
The frozen raw-v3 reader manifest SHA-256 is
`71e90f365ebc30952104ede0c1fce81d32b9a776ad253f84a7d991a38c936fbc`.
The actual v6 batch records successful open/returns capture exits and failed
exits for the seven process-tree/Mach cases. The original outcomes are retained;
the completed independent audit confirms the native batch failed. Four process
stdout files exceed their original footer identities, consistent with children
writing after premature finalization; strict transport rejects these records.
The remaining per-event binding checks do not repair identity or completion.
The audit retained all 154 original files / 885,211 bytes unchanged, aggregate
`f00d7bc3ab00ec5fc21cd11e6800305738931abb52d34408098e62a948b1a695`.
Its findings SHA-256 is
`a30000479e2d785bcfbe3e93bd64f61343dc5435d1c59fee1aceef2fac473fdf`;
the completed audit manifest SHA-256 is
`5c14de12cebd400c79cd0a2570a0e4757fab62d4ad88ca2977332032e33bd430`.
The pre-exec-context target-retirement explanation remains a source hypothesis
until independently calibrated; raw lifecycle object fields remain opaque.
Prepared toolkit bytes alone do not establish successful capture or coverage.

The selected validated v5 timeline manifest SHA-256 is
`db6c2d5d9494751432152b81a1c67cd1bf43ff746b2d98026cf1f892175270d5`.
The source-contract observation reports every case incomplete: direct-open
path-byte records remain uninterpreted and process/Mach cases expose unsupported
routes. Its review JSON SHA-256 is
`60cc23285fc5c81a4c47cbf8c220b50470f3561a7b858fb13a3ab044683d6f3a`.
It does not supply transport attestation or a complete extraction verdict.
The source-contract implementation is retained in feature commit
`9be06a17e5ae6e6a329147f9da4e6d983dd51520`; its 18 controls and exact 161-declaration
source audit passed, independently reviewed. The immutable source-snapshot
manifest SHA-256 is
`f80029e64436f7c1c81433b0fccc8b4ad2445ce228b2e81dc509d79dceb95159`.

The selected owned-open observer freeze includes 13 independently reviewed
controls and actual v5 open/returns replays of seven and eight whole calls. Its
SOURCE.json SHA-256 is
`865e2ff6e7840efdbde0514965768e6cea62be6d0bcef5b379f940a85a97618a`;
its manifest SHA-256 is
`d1e6852d2d4b9652a2ec1dbcf3fa039193719ea59f41db3beab064b18e5139fa`.
This bounded observer preserves false full-trace acceptance. It does not supply
other syscall decoders, complete lifecycle/FD state or an extraction oracle.

The selected enabling-binding replay applies reader commit `7135bca` to events
already validated by the frozen raw-v2 reader. All nine original v5 sessions
passed the added session-consistency invariant, with the original failed
`spawn-open` status preserved. Its historical statement that v6 was awaiting
capture records the replay time, not a rewritten account of later guest work.
The replay does not execute retained binaries or grant full-trace acceptance.
The matching reader snapshot is copied directly from commit
`7135bca7c221701c4a0e1c3b7d500983c36c8c99`; its reader SHA-256 is
`d44806d874e8750ae6453054406e8bc4da64f464b1325c9fc00cd559aabdeb8f`,
SOURCE.json SHA-256 is
`7c80dcc1f5c008b4bb044581509b283b2069e530d4b4253b6280369801713bd4`,
and manifest SHA-256 is
`f37db497aa2cf43197bf5f92040bf47151f275f715219ed89cbe13e2e39bb5ee`.

The selected portable follow-up logs record 126 macOS controls passing and
124 Linux arm64 controls passing, with two Darwin-compiler controls skipped on
Linux. They exercise portable unit boundaries on source `4177ab9`; they are
separate from native guest capture and do not establish Darwin R02 acceptance.

The final v7 toolkit comes from source `a401d49`; its manifest SHA-256 is
`7eb3840bc4e209fde8cbe831ef49f61aab6f54d6df140f8d246d02d0accc6175`.
The actual v7 batch retained seven process-tree captures and two failed open
captures. The v7 independent audit preserves those outcomes and its manifest
SHA-256 is
`8c52a86fadd6d07c98cb4f9889f7a52dc7705449519e6363c07318707f8370c0`.
The v8 toolkit from `d4e9e93` guards terminal-tree drain checks by
profile; its manifest SHA-256 is
`da165c2b357b4a19e1d988025f2da1fdd2b26a6a477a67dd490bc5605b621c5a`.
The original v8 status table records nine successful capture exits. The final
independent audit confirms all nine capabilities captured and source-matched
transport consistent. It preserves all original bytes and false full-trace
acceptance. Its findings SHA-256 is
`c14b24662f390336b0deb1a5d82d8ead0a1cd4c873f93e6132878a97c143604a`;
its complete audit manifest SHA-256 is
`3359b5b4061b09e63854e7a8285b8fe1e860e54de7f358722b17c44a1e113e6e`.
The bounded audit observes 17 controlled open pairs (nine successful input
opens and eight ENOENT controls) and 21 target-exited records: eight shadow
objects and 13 nonshadow terminal records. Those selected records calibrate
the candidate shadow flag and target layout; they do not establish general
pointer generations, all syscall coverage or a complete filesystem oracle.
The raw-v4 reader manifest SHA-256 is
`13d7a1b2741100d141de17818b354801137e190aa6eceaa8345a0d5cbb1a4072`;
the source-matched v8 reader manifest SHA-256 is
`df99ce0dab83dde4172aa01477b0caf7eab19a636cd4c7d552b20b3bf636e1de`.

The final current-source open observer separately replayed the v8 open and
returns streams as seven and eight whole calls. Those 15 calls across two
streams differ in scope from the 17 named controlled pairs across all nine
cases. The observer/doc-review manifest SHA-256 is
`ea0475a3f17293e03b6543c5cc057ea3bcd21d786dffd8501034f172b1b294c8`.
Its frozen documentation snapshots record SIP restoration in progress at their
review time. Any later restoration proof will be separate; historical bytes
are not rewritten to update their tense.

The selected final portable logs contain six suites / 138 controls per host:
138 macOS controls passed; 136 Linux arm64 controls passed and two native Darwin
compiler controls were explicitly skipped. Separate v7/v8 host-native logs show
13 and 14 controls passed. These controls remain distinct from actual guest
capture, runtime acceptance and the complete extraction oracle.

The reviewed call-pairing adapter separately reproduced 1,083 BSD and 110 Mach
provider-return pairs across seven complete v8 capability streams. It retained
13 entries without a provider return (12 `exit` and one `bsdthread_terminate`)
with their observed lifecycle boundaries. These are paired transport records,
not inferred call success, filesystem effects or complete trace acceptance. Its
manifest SHA-256 is
`13a62c09ff543b4f19d461e92b0e4cb6df7a7535a581d20b8b00f7668e701c9a`;
the independent review manifest SHA-256 is
`f3bb65c478552404e9dc504ad5415789ab04ab377d19d435d3fbbc2105353e79`.
The subsequent seven-suite logs record 155 controls passed on macOS and 153
passed with two explicit Darwin compiler skips on Linux arm64.

The Mach assessment reverified the frozen v5 exported timeline inventory and
identified 18 scalar `mach_msg2_trap` pairs. Packed headers do not preserve
request bodies, descriptors, RPC replies or port/object generations. The pinned
kernel source also permits KOBJECT_CALL to message queues under its SIP-off
compatibility rule, so the observed option bit is not destination-type proof.
The assessment's manifest SHA-256 is
`4d3207010288577d61042902eafaccd7ae45d016016449a1f300b32a2d098dd5`.
It records the unresolved consumed-byte, rights, object-effect and completion
requirements without providing an acceptance shortcut.

The retained preflight verifier reproduced all 46 original capture attempts:
16 exact strict-reader rejections, four transport-consistent failed captures
and 26 transport-consistent captured capabilities. It also reproduced 25
byte-identical exports, nine binding sessions, all 161 source declarations,
nine incomplete source observations, 18 Mach pairs and 30 whole open calls
across the historical/current observer streams. Nine acceptance APIs rejected.
All 1,329 then-indexed files / 26,190,937 bytes and their modes remained
unchanged. The preflight review SHA-256 is
`7c3aa17d44d52d4e0918b3169f36fb650e4ebace0e2c7564c970c6ecb524b681`;
its verifier SHA-256 is
`9ee63605e42174b50f071db669cc29cfd2e6c11856247a6c0717962808cda286`.
This preflight did not observe final SIP restoration or prepare a bundle.

A preliminary candidate01 was prepared before the final pairing additions
and contains no SIP-restoration proof. Its 1,333 selected source files /
26,411,385 bytes restore as 1,335 archive members. The immutable 2,615,523-byte
archive SHA-256 is
`2ac4ea5f1f4737ada6ab1686c02e710622abe0d027c9902fd6d1acea8640a122`;
its complete member-inventory SHA-256 is
`7441a479c4028365cf306a3bad7b300478f2d35a6bface35ea36de5a2d8d5eed`.
Independent Mac and offline Linux arm64 tmpfs restores reproduced all 46
historical outcomes. Their replay JSON identities are respectively
`f55f038cece403d09f96b99634b7c30f0f344637228498dabadd71850f7a68ab` and
`c2600768faa61174eea302d661bbcc6d8314289048f65e0a7053d6868ad56ee9`.
This preliminary candidate remains unchanged and excludes final SIP proof.
Candidate02 uses a separate output root and inventory. Neither candidate
contains a final SIP restoration observation.

## Preparation and replay

The frozen candidate02 was locally prepared, restored and replayed with the
external-root [retention profile](../../decisions/mvp-r04-external-evidence-retention.md).
The compressed archive is 2,877,455 bytes / 1,374 members, with SHA-256
`3194d8109daf4fb7192b80f54957a2c09c2e2423c807b9f0f286a13325120b91`.
The committed complete member inventory SHA-256 is
`1623cfb36e665e2a5f3ab1ef169be605beb15a908604db5ebf825737eaea4337`.
Prepared metadata SHA-256 is
`56e24e98a83fefff536f5408d5c4d5dd748e3b0cd73315a7bb9eb98b0421d9fe`.
Local prepared, restored and replay roots are respectively:

- `/private/tmp/glue-darwin-calibration-candidate-02-20261016`;
- `/private/tmp/glue-darwin-calibration-restored-02-20261016`;
- `/private/tmp/glue-darwin-calibration-replayed-02-20261016`.

The restored verifier reproduced all 46 historical outcomes and 25 exact
exports, with every indexed file hash and mode unchanged. The replay JSON
SHA-256 is
`8c36add40b30f15b43afc2a1fa1b400c302619e0268caf97a4bee524f02fcd2c`.
A separate local read-only check verified the exact 1,374-member inventory and
all source sizes/modes, found no extra files, and reproduced the seven retained
call-pairing outputs exactly. Its report SHA-256 is
`09b102c6ffce9401364ffe9741cd6a2981f8348adb16d632448f142952ec1d3e`.
The check driver `/private/tmp/glue-darwin-calibration-candidate02-check-20261016.py`
(SHA-256 `e76d84107b2132575712d41542ca7299dd4d974614ee0bb125bb353ed975d4b6`)
and its `.log` (SHA-256
`42f6df0a49b1c3f2d6c4a014d9d7592e2d3c527597f56b749d6dc44d56738629`)
are local post-preparation proofs outside this frozen payload. They import only
the retained diagnostic Python and do not execute captured targets or argv.
All results keep full-trace acceptance false.

An independent restore into
`/private/tmp/glue-darwin-calibration-lua-audit-20261016/restored` reproduced
the same replay and post-inventory report identities, including all seven
pairing outputs, with no changed files or modes. Its review JSON SHA-256 is
`0d39a50b52aca7de611317d4e6c4448da0f0d398c850cd8c60727c20e9f16a2d`;
the external `AUDIT-SHA256SUMS` identity is
`ff9367e3a40c0f12ef054d4ba3712186afbdaa3d067492f5a8057147b8056467`.
These post-prepare audit files are separate from the immutable archive. Only
frozen Python verifier source ran; no captured native binary was executed.

Equivalent prepare/restore commands use new output directories:

```sh
python3 scripts/evidence-bundle.py prepare \
  --source-root /private/tmp \
  --inventory docs/evidence/compact-mvp-darwin-calibration-2026-10-15/local-evidence.sha256 \
  --output /absolute/new/darwin-prepared
python3 scripts/evidence-bundle.py restore \
  --archive /absolute/new/darwin-prepared/evidence.tar.gz \
  --metadata /absolute/new/darwin-prepared/prepared.json \
  --inventory docs/evidence/compact-mvp-darwin-calibration-2026-10-15/bundle-payload.sha256 \
  --output /absolute/new/darwin-restored
```

From a restored payload, the retained Python verifier can reproduce the bounded
historical checks with a new output directory. This checkpoint supplies no SIP
proof argument:

```sh
payload=/absolute/new/darwin-restored/payload
PYTHONDONTWRITEBYTECODE=1 python3 \
  "$payload/glue-darwin-calibration-portable-replay-20261016.py" \
  --payload "$payload" \
  --inventory /absolute/new/darwin-restored/source-inventory.sha256 \
  --output /absolute/new/darwin-replay
```

The restorer validates the exact compressed identity and member set, file hashes,
sizes and ordinary modes before promoting a new output root. Restored captures
live below `darwin-restored/payload/<original relative path>`. A strict reader
rejection of the original v3 records is the expected diagnostic result; failed
captures must retain their original statuses. No recorded binary or command is
executed during retrospective review. Preparation is not durable publication;
an authorized actual upload and verified remote fetch remain separate work.

The original failed open case can be checked from a restored tree with the
frozen reader, without executing any captured binary:

```sh
payload=/absolute/new/darwin-restored/payload
python3 "$payload/glue-mvp-macos-vm-toolkit/reader-v2/read_capability.py" \
  --capture "$payload/glue-mvp-macos-vm-results/glue-mvp-guest-native-v3-jWaBxiJ3/cases/open" \
  --toolkit "$payload/glue-mvp-macos-vm-results/glue-mvp-guest-native-v3-jWaBxiJ3/native-capture-v2"
```

A nonzero result reporting the consumer-index gap is expected. Replacing this
result with an accepted transport would change the historical observation.
