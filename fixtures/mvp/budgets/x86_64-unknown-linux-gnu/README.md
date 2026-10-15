# Reviewed native x86_64 R03 profiles

These five numeric profiles were reviewed from native run 38796669924 after
independent replay of 15 acceptance receipts, 60 oracle controls and 990 rank
results. Numeric limits match the proposed observations; added metadata records
their review and explicit `traceable-native-syscalls-v1` CI environment.

The environment disables asynchronous kernel I/O for the complete test process
tree, including references and measured ranks. These profiles do not establish
unrestricted-host acceptance. Time/RSS limits apply only to the recorded full
host boot fingerprint; structure/size/I/O/FD/scaling limits remain enforced on
other hosts. First/warm observations do not imply a cold filesystem cache.

The overall native run failed a separate Python 3.14 native build. Only these
five complete R03 profiles are accepted. See
[`../observations-x86_64-unknown-linux-gnu.json`](../observations-x86_64-unknown-linux-gnu.json)
and the R03 decision for the exact inputs, costs, hashes and retention limits.
