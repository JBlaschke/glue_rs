#ifndef GLUE_RUNTIME_TRACE_BACKEND_H
#define GLUE_RUNTIME_TRACE_BACKEND_H
#include "../trace-session/trace_session.h"

#define RT_MAX_PROBES 8192u
#define RT_MAX_ENABLINGS 8192u
#define RT_MAX_RAW_BYTES UINT64_C(134217728)
#define RT_MAX_DIAGNOSTIC_BYTES UINT64_C(65536)
enum rt_stage { RT_NONE, RT_CREATE, RT_START, RT_PUMP, RT_STOP, RT_DRAIN, RT_CLOSE };
enum rt_reason { RT_OK, RT_ARGUMENT, RT_OWNER, RT_CLOCK, RT_DEADLINE,
 RT_POSIX, RT_LIBDTRACE, RT_INVENTORY, RT_LAYOUT, RT_BINDING,
 RT_ORDER, RT_LIMIT, RT_DROP, RT_OUTPUT, RT_CONSUMER, RT_INCOMPLETE };
struct rt_error {
 enum rt_stage stage; enum rt_reason reason;
 int system_errno, libdtrace_code;
 /* Adapter status mapping required by ts_operations; NEVER native POSIX
  * provenance. In particular, libdtrace_code is not a system errno. */
 int callback_error;
 char message[513];
};
struct rt_snapshot {
 struct ts_binding binding; uint64_t original_attempt_deadline_ns, cleanup_deadline_ns;
 struct rt_error first_error, close_error, writer_close_error;
 /* Fixed bit/index order: program.d, probes.tsv, events.jsonl, errors.jsonl.
  * Native close outcomes survive an earlier close-phase clock/deadline fault. */
 unsigned writer_close_attempted_mask, writer_close_failed_mask;
 int writer_close_errno[4];
 uint64_t events, raw_bytes, diagnostic_bytes, inventory_bytes, drops, faults;
 unsigned inventory_probes, expected_matches, enabled_matches, enablings;
 unsigned begin_count, terminal_count, end_count;
 unsigned selected_exec_entry_count, selected_exec_success_count;
 int start_attempted, started, stop_attempted, stopped, drain_attempted, drained;
 int close_attempted, resources_closed;
};
/* Source-selected boundary transport, still bound to the existing confirmed
 * owned-context request. Successful transport is not native calibration or
 * full runtime admission. The independent reader validates bootstrap/image
 * witnesses and selected old/new TIDs. No caller-selected D source. */
struct rt_backend;
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
int rt_create(struct rt_backend **, int held_directory_fd,
 const struct ts_binding *, uint64_t original_attempt_deadline_ns,
 int confirmed_ready, struct ts_operations *, struct rt_error *);
/* Pure snapshot; lifecycle counts are observations, never a success oracle. */
int rt_snapshot(const struct rt_backend *, struct rt_snapshot *);
/* Free only after the once-only callback close resolves resources, or before
 * any start attempt. Never closes/retries anything implicitly. */
int rt_destroy(struct rt_backend **);
#endif
