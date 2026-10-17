# R02: share the closed deployment-proof binding with the offline checker

Actual kit03 packet04 completed its four wrapper cases and exported a normal
zero-status receipt. The offline checker then refused `kit/proof scope` while
validating packet metadata, before reading native case exports. Its separate
literal still selects the earlier deployment proof, although the preparer and
reviewed actual kit03 select the post-reboot proof. Preserve this failed checker
record and all native exports unchanged.

Define one literal `APPROVED_PROOF_MANIFEST_SHA` in the reviewed preparer and use
it in both pure kit loading and offline packet validation. Its sole value remains
the independently reviewed actual proof
`ca2e111c6f6abcdb94ca8b6851b464a95f7cea0792990aec7d60b995ab1be09f`.
There is no caller-selected proof, runtime override, additional registry entry,
schema change or relaxed scope check. The preparer renders the same packet bytes;
the native kit, scripts, requests, case outputs and receipts remain unchanged.

Update the independently constructed synthetic workflow to the current literal,
and reject old/unknown proof identities even when all synthetic outer inventories
are rebuilt. Run focused checker/preparer controls and independently review this
source repair before rechecking the already completed actual exports. Do not
rerun a native case to repair a host metadata-validator mismatch. A later checker
success establishes owned nontracing consistency only; kernel exec, tracing,
extraction and full R02/M2 acceptance remain separate.
