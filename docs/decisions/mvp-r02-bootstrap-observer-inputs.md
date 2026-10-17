# R02: register reviewed bootstrap observer sources

Advance the existing 34-file bootstrap kit source lock to committed revision
`fbcc2cf583469f45dc9684a6b5a60329c0e6a3ce`. Only bootstrap_io.c and
bootstrap_io.h have changed in that closure. The separate observed operations
have passed their recorded strict/sanitizer controls and peer source review;
legacy entry points and their operation table remain unchanged.

The peer review is `/private/tmp/glue-bio-observer-source-review-dGeMdp`, manifest
`4718ca0ad470988ffea370ab3a53067886d40f1f2a46cc8b79cebc16aadb76e2`.
Register C hash `aa24fd6bf0982d2249cbd98dfbb435577f09999f44bc12996352390b2b7c4e7a`
and header hash `2aa78f6b51c6a61baa3490deae88f31ac9e84eec32bc280e0172d7185f8db4d1`.
Preserve all other source hashes, both actual deployment-proof entries, compile
unit lists, builder/parser and admission policy.

This is a source-registration step. It does not build, sign, install or run a
new kit, activate observed operations, or register trace-session sources. Kit03
and its completed nontracing guest exports keep their historical source lock
and identities. Native tracing integration and R02/M2 acceptance remain open.
