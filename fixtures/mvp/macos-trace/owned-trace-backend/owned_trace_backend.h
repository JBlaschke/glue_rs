#ifndef GLUE_OWNED_TRACE_BACKEND_H
#define GLUE_OWNED_TRACE_BACKEND_H
#include "../trace-session/trace_session.h"

#define OTB_MAX_PROBES 8192u
#define OTB_MAX_ENABLINGS 8192u
#define OTB_MAX_RAW_BYTES UINT64_C(134217728)
#define OTB_MAX_DIAGNOSTIC_BYTES UINT64_C(65536)
enum otb_stage { OTB_NONE, OTB_CREATE, OTB_START, OTB_PUMP, OTB_STOP, OTB_DRAIN, OTB_CLOSE };
enum otb_reason { OTB_OK, OTB_ARGUMENT, OTB_OWNER, OTB_CLOCK, OTB_DEADLINE,
 OTB_POSIX, OTB_LIBDTRACE, OTB_INVENTORY, OTB_LAYOUT, OTB_BINDING,
 OTB_ORDER, OTB_LIMIT, OTB_DROP, OTB_OUTPUT, OTB_CONSUMER, OTB_INCOMPLETE };
struct otb_error {
 enum otb_stage stage; enum otb_reason reason;
 int system_errno, libdtrace_code;
 /* Adapter status mapping required by ts_operations; NEVER native POSIX
  * provenance. In particular, libdtrace_code is not a system errno. */
 int callback_error;
 char message[513];
};
struct otb_snapshot {
 struct ts_binding binding; uint64_t original_attempt_deadline_ns, cleanup_deadline_ns;
 struct otb_error first_error, close_error, writer_close_error;
 /* Fixed bit/index order: program.d, probes.tsv, events.jsonl, errors.jsonl.
  * Native close outcomes survive an earlier close-phase clock/deadline fault. */
 unsigned writer_close_attempted_mask, writer_close_failed_mask;
 int writer_close_errno[4];
 uint64_t events, raw_bytes, diagnostic_bytes, inventory_bytes, drops, faults;
 unsigned inventory_probes, expected_matches, enabled_matches, enablings;
 unsigned begin_count, terminal_count, end_count;
 int start_attempted, started, stop_attempted, stopped, drain_attempted, drained;
 int close_attempted, resources_closed;
};
struct otb_backend;
/* Trusted internal caller only, AFTER complete independent READY comparison and
 * while owning the actual unreaped bootstrap child. confirmed_ready must be1.
 * Tags/digests are context, never kernel attestation. Directory is borrowed:
 * caller admits its fresh private namespace and keeps FD/identity stable until
 * callback close. No concurrent mutation/reentry; storage/spans do not alias.
 * No tracing resources exist before this confirmation. No provider runs here.
 * start exclusively creates program.d/probes.tsv/events.jsonl/errors.jsonl.
 * The sole execution interface is the returned fixed native ts_operations;
 * no CLI, target argv, profile or injected production operations are supported.
 * All callbacks retain original deadlines; cleanup binds once, at most2s ahead.
 * Native syscall/libdtrace stalls cannot be interrupted by these checks. */
int otb_create(struct otb_backend **, int held_directory_fd,
 const struct ts_binding *, uint64_t original_attempt_deadline_ns,
 int confirmed_ready, struct ts_operations *, struct otb_error *);
/* Pure snapshot; lifecycle counts are observations, never a success oracle. */
int otb_snapshot(const struct otb_backend *, struct otb_snapshot *);
/* Free only after the once-only callback close resolves resources, or before
 * any start attempt. Never closes/retries anything implicitly. */
int otb_destroy(struct otb_backend **);
#endif
