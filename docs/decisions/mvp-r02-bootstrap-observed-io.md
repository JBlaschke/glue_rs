# R02: pump tracing during bounded bootstrap pipe waits

The owned-probe tracing coordinator needs cooperative progress while the parent
waits on bootstrap status, GO and EOF. The existing transport may poll one pipe
for the entire remaining deadline. Add explicit observed variants of the three
BIO operations, sharing their existing transfer core. Existing entry points keep
their behavior and operation table layout; append new diagnostic enum values.

An observed operation copies a separate trusted observer table once. Its progress
callback receives the unchanged absolute deadline. Poll waits use the smaller of
the original remaining timeout and a fixed20ms quantum. Pump before waits, after
validated nonfatal waits and after confirmed I/O progress/EOF, with monotonic and
original-deadline checks before touching further pipe bytes. No timeout, EINTR,
EAGAIN, pump or partial transfer renews that deadline or the retry bound.

Fatal/anomalous poll results retain their original classification before later
observer or clock failures. Fatal/truncated I/O likewise keeps its established
error. An observer's explicit failure needs no invented errno. Preserve confirmed
byte counts and prefixes even when the complete record was delivered before a
later observer fault; failed records stay opaque and must never be replayed.

Callbacks are cooperative trusted internal code and cannot interrupt a blocked
kernel operation. They must preserve pipe identities/flags, buffers, aliases and
signal policy and must not reenter BIO. This step supplies no tracing backend,
event validation, runner adoption, new source registration/kit, guest operation
or native proof. A later caller must connect the coordinator and independently
enforce its lifecycle/result gates. Preserve the completed kit03 exports.
