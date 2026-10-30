#ifndef GLUE_POST_EXEC_OUTPUT_H
#define GLUE_POST_EXEC_OUTPUT_H
#include <stdint.h>
#define PX_BYTES 4096
#define PX_NATIVE_BYTES 176
#define PX_ORIGINAL_BYTES 320
#define PX_QUERY_COUNT 8
#define PX_WAIT_COUNT 64
/* Header flags; observations are never execution or policy authority. */
#define PX_OWNED 1u
#define PX_STOPPED 2u
#define PX_ATTEMPTED 4u
#define PX_MATCHED 8u
#define PX_REAPED 16u
#define PX_LOST 32u
#define PX_Q_ATTEMPTED 1u
#define PX_Q_FULL 2u
#define PX_Q_OPAQUE 4u
#define PX_Q_AFTER 8u
#define PX_W_ATTEMPTED 1u
#define PX_W_AFTER 2u
#define PX_W_TERMINAL 4u
#define PX_W_ECHILD 8u
#define PX_W_STOP 16u
#define PX_W_STATUS 32u
enum px_state { PX_ACTIVE=1, PX_COMPLETE, PX_REFUSED, PX_REAPED_STATE, PX_LOST_STATE };
enum px_reason { PX_OK, PX_ARGUMENT, PX_UNSUPPORTED, PX_POLICY, PX_OWNER,
 PX_CLOCK, PX_DEADLINE, PX_WAIT_LIMIT, PX_WAIT, PX_TERMINAL, PX_OWNERSHIP_LOST,
 PX_STOP_SIGNAL, PX_QUERY, PX_MISMATCH };
struct px_error { enum px_reason reason; int system_errno; };
struct px_plan {
 uint32_t child;
 int held[2];
 uint64_t sequence, deadline, exec_ordinal, new_tid;
 /* request, catalog, complete READY, fixed program, original GLUERW SHA256. */
 uint8_t digests[5][32];
 uint8_t original[PX_ORIGINAL_BYTES];
};
struct px_observer;
/* Caller owns the actual fork PID, is the sole reaper/controller, retains both
 * original references and all immutable storage, and excludes concurrent FD,
 * credential, signal-policy and task-control changes. The original deadline
 * and clock source must be the launch attempt's. Native factory is Darwin
 * LP64 little-endian only, actual SIGCHLD DFL
 * without SA_NOCLDWAIT; the native factory recomputes original GLUERW SHA256.
 * Caller privilege is unchanged. No stop/resume/signal/close/dup/provider API exists.
 * These source preconditions are not established by a packet or equal samples. */
struct px_observer *px_observer_new(const struct px_plan *, struct px_error *);
/* One real wait; 0 means retry (only wait 0/EINTR), 1 complete conditional match,
 * -1 permanent refusal or duplicate attempt. Stop does not reap. Terminal wait
 * and ECHILD retire ownership before after-clock; sample failure never retries.
 * Cooperative deadline checks cannot interrupt a blocked call. */
int px_observer_poll(struct px_observer *, struct px_error *);
/* Complete original prefixes, zero unread rows. Clears output on bad arguments.
 * Encoding has no callbacks and does not authenticate native origin. */
int px_observer_encode(const struct px_observer *, uint8_t out[PX_BYTES], struct px_error *);
int px_observer_owns_child(const struct px_observer *);
/* Frees only observer memory. Caller separately cleans up its unreaped child. */
void px_observer_free(struct px_observer *);
/* Pure explicit field codec. Input is exactly the source-defined Darwin LP64
 * LE field layout, not a claim that the host or supplied bytes are native. */
int px_codec_native_lp64le(const uint8_t native[PX_NATIVE_BYTES], uint8_t be[PX_NATIVE_BYTES]);
#endif
