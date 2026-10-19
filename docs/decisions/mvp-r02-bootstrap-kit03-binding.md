# R02: bind VM preparation to the reviewed post-reboot kit03

Use the fresh reproducible host kit03 built from the independently reviewed
post-reboot deployment observation. Its literal manifest is
`ea67cfba1dab8dc51c44e514ca6ff8a00f703e665cbc89c17f996b3e02f4efae`,
build ID is
`1b85f0ac3d3ec2de7df50004ee2732d8d5c049adb44193383245050f800fa11d`,
and catalog SHA is
`c566af88348f4823aa93c67fa11ce851f210742c1b0b79ab792b3cb192e39e69`.
The admitted actual deployment proof manifest is
`ca2e111c6f6abcdb94ca8b6851b464a95f7cea0792990aec7d60b995ab1be09f`.
Root and Data both observe device `16777231`, with distinct full FSIDs
`[16777236,27]` and `[16777231,27]`; retain these literal tuples.

One combined independent artifact/catalog review covers this kit. Its manifest
`1910f6a1a1274fb41b32030e1a62dff2bf6a218b6d2db1788c3ebb50d6db0e22`
supplies both existing `kit_review_manifest_sha256` and
`catalog_review_manifest_sha256` fields. This is one audit with both scopes,
not two independent audits. The root-recorded normal-zero builder receipt has
manifest `5f9556fe22aa4e9764bf2184163ec704c4324e580624550a9eab1dbca04cb030`.
The independent review checks that receipt, both identical signed build trials,
all 34 source pins, the exact recorded tool commands and embedded/catalog
bindings. Passive signature analysis is distinct from the builder's recorded
strict OS signature-verification success; no fresh codesign run or execution
is implied by this binding.

Replace the single literal VM kit binding and admitted-proof identity together.
The old kit02, prior packets/results and existing protected prefix stay unchanged;
the current preparer must refuse kit02 rather than relabel or mutate it. There
is no runtime trust/profile/hash override or multiple-kit selection. Preserve
the pure host parser pin, current-deployment preflight, plan/evidence schemas,
checker, root stage, launch and closure/export policy. This step does not create
or run a packet, install a payload, execute a kit binary, rebuild a kit or change
guest security settings. A future concrete packet still needs independent
inspection before staging/launch. Bootstrap, kernel exec, tracing, no extraction
and full R02/M2 acceptance remain separate gates.
