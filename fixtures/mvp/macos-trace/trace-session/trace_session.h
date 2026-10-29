#ifndef GLUE_OWNED_TRACE_SESSION_H
#define GLUE_OWNED_TRACE_SESSION_H
#include <stddef.h>
#include <stdint.h>

#define TS_OWNED_CONTEXT_PROBE 1u
#define TS_OWNED_RUNTIME_RECIPE 2u
#define TS_MAX_PUMPS 65536u
#define TS_MAX_EVENTS 1000000u
#define TS_STATUS_CAPACITY 769u
#define TS_RUNTIME_STATUS_CAPACITY 1537u
enum ts_phase { TS_BOOTSTRAP, TS_WAITING, TS_CLEANUP };
enum ts_event_kind { TS_PROVIDER_READY=1, TS_BEGIN, TS_ACTIVITY, TS_TERMINAL,
                    TS_END, TS_DROP, TS_BACKEND_FAULT, TS_OUTPUT_FAULT };
enum ts_child_state { TS_CHILD_LIVE, TS_CHILD_REAPED, TS_CHILD_LOST };
enum ts_stage { TS_STAGE_NONE, TS_STAGE_INIT, TS_STAGE_START, TS_STAGE_PUMP,
 TS_STAGE_GO, TS_STAGE_BOOTSTRAP, TS_STAGE_WAIT, TS_STAGE_CLEANUP, TS_STAGE_STOP,
 TS_STAGE_DRAIN, TS_STAGE_CLOSE, TS_STAGE_PARENT };
enum ts_reason { TS_OK, TS_INVALID, TS_WRONG_OWNER, TS_CLOCK, TS_CLOCK_ROLLBACK,
 TS_DEADLINE, TS_BACKEND, TS_BAD_BINDING, TS_EVENT_ORDER, TS_NOT_READY,
 TS_DROPPED, TS_OUTPUT, TS_LIMIT, TS_PARENT_FAILURE, TS_CHILD_FAILURE,
 TS_LOST_CHILD, TS_INCOMPLETE };
struct ts_error { enum ts_stage stage; enum ts_reason reason; int system_errno; size_t detail; };
struct ts_binding { uint32_t fixture, owner_pid, target_pid; uint8_t request_sha256[32], catalog_sha256[32]; };
struct ts_event { enum ts_event_kind kind; struct ts_binding binding; };
typedef int (*ts_consume_fn)(void *, const struct ts_event *);
/* Trusted internal callbacks, copied once. No native implementation exists.
 * No callback may mutate coordinator/input storage or call its public API.
 * The only permitted reentry is consume(ctx,event) during pump/drain. Before
 * delivering an event a future adapter must validate actual raw descriptors,
 * layout, provider/enabling and output bounds. Binding tags are context, not
 * kernel attestation. Callback delivery means a consumed event, not readiness
 * inferred from start() or nonzero probe counts. Stop/drain/close are once-only.
 * Callbacks are cooperative and must honor the supplied absolute deadline;
 * coordinator checks cannot interrupt a stalled callback/kernel call.
 * int callbacks return0 or-1 with positive errno on failure; errno0 on success.
 * owner returns actual controller PID or0 with positive errno on failure.
 * close must resolve all backend resources after ANY start attempt, including a
 * failed start; no coordinator retry is available. drain0 means actual DONE. */
struct ts_operations {
 void *context;
 uint32_t (*owner_fn)(void *, int *);
 int (*clock_fn)(void *, uint64_t *, int *);
 int (*start_fn)(void *, const struct ts_binding *, uint64_t, int *);
 int (*pump_fn)(void *, enum ts_phase, uint64_t, ts_consume_fn, void *, int *);
 int (*stop_fn)(void *, uint64_t, int *);
 int (*drain_fn)(void *, uint64_t, ts_consume_fn, void *, int *);
 int (*close_fn)(void *, uint64_t, int *);
};
/* Caller-owned zero-initialized, nonalias stable storage; one init, one owner,
 * no concurrent mutation/caller, no reuse after finalization. Exposed fields
 * are observations for models/receipts, not permission for caller mutation. */
struct ts_session {
 uint32_t tag; int configured, initialized; struct ts_binding binding; struct ts_operations operations;
 uint64_t attempt_deadline_ns, cleanup_deadline_ns, last_ns;
 unsigned cleanup_ms; int clock_seen, cleanup_attempted, cleanup_bound;
 struct ts_error error, cleanup_error;
 enum ts_child_state child; uint32_t wait_status; int kill_claimed;
 int start_attempted, backend_touched, started;
 unsigned provider_ready, begin_count, terminal_count, end_count;
 unsigned pump_calls[3], total_pumps, events; int consuming, draining, consume_failed;
 int go_claim_attempted, go_possibly_released, go_result_seen, go_complete;
 size_t go_bytes, bootstrap_prefix_bytes; int bootstrap_seen, bootstrap_sealed;
 int gate_close_seen, gate_closed, parent_close_seen, parent_closed;
 int stop_attempted, stopped, drain_attempted, drained, close_attempted, closed;
};
/* Entry only AFTER the parent independently compares the complete READY and
 * owns the actual unreaped fork child. This API neither verifies READY nor
 * authorizes native execution. Exact reviewed request cleanup_ms is retained. */
int ts_init(struct ts_session *, const struct ts_binding *, uint64_t attempt_deadline_ns,
            unsigned cleanup_ms, const struct ts_operations *);
/* Separate fixed runtime-recipe binding; identical owner/lifecycle policy.
 * Runtime object-status success retains 1024 bytes and failures at most 1537;
 * ts_init remains exclusively fixture 1 with its original 512/769-byte bounds. */
int ts_runtime_init(struct ts_session *, const struct ts_binding *, uint64_t attempt_deadline_ns,
                    unsigned cleanup_ms, const struct ts_operations *);
int ts_start(struct ts_session *);
int ts_pump(struct ts_session *, enum ts_phase);
int ts_claim_go(struct ts_session *); /*0 grants one use; mark possible release first.*/
int ts_go_result(struct ts_session *, size_t confirmed_bytes, int operation_error);
/* Explicit failed BIO result, including semantic/clock failures with errno0
 * and even all64 confirmed bytes. It consumes the same once-only result slot. */
int ts_go_failed(struct ts_session *, size_t confirmed_bytes, int system_errno);
/* Result reports are consumed once, even malformed errno or owner-observation
 * failure. Reported0 means the actual close succeeded; negative errno is invalid
 * and permanently leaves closure unresolved. These functions never retry close. */
int ts_gate_close_result(struct ts_session *, int operation_error);
int ts_gate_close_failed(struct ts_session *, int system_errno); /*explicit failure, errno0 allowed*/
/* Called only after the parent's independent strict BW codec+EOF check. No
 * opaque prefix is decoded here. Failure retains the confirmed prefix count. */
int ts_bootstrap_sealed(struct ts_session *);
int ts_bootstrap_failed(struct ts_session *, size_t confirmed_prefix_bytes, int system_errno); /*errno0 allowed*/
int ts_child_reaped(struct ts_session *, uint32_t raw_wait_status);
int ts_child_lost(struct ts_session *); /*actual ECHILD; never authorizes kill.*/
int ts_kill_eligible(const struct ts_session *); /*owner-only state observation*/
int ts_claim_kill(struct ts_session *); /*state permission only; never signals.*/
int ts_begin_cleanup(struct ts_session *, uint64_t original_cleanup_deadline_ns);
int ts_stop(struct ts_session *);
int ts_drain(struct ts_session *);
int ts_close(struct ts_session *);
/* The trusted parent confirms the attempt's bootstrap/target/trace channels,
 * writers and admission FDs resolved, and its signal policy restored. This
 * declaration is not checked by the coordinator. Final metadata authoring FDs
 * and the held output directory belong to the caller's separate finalizer;
 * that caller must close them before result promotion. Keep operations.context
 * alive through this report's owner/clock callbacks. */
int ts_parent_close_result(struct ts_session *, int operation_error);
int ts_parent_close_failed(struct ts_session *, int system_errno); /*explicit failure, errno0 allowed*/
/* Lifecycle prerequisite only; never permission to publish final metadata. */
int ts_finalization_safe(const struct ts_session *); /*may be true for failure*/
int ts_success_eligible(const struct ts_session *); /*additional prerequisite only*/
#endif
