#ifndef GLUE_RUNNER_TRACE_H
#define GLUE_RUNNER_TRACE_H
#ifdef GLUE_RUNTIME_TRACING
#include "../runtime-boundary/runtime_trace_backend.h"
typedef struct rt_backend nr_trace_backend;
typedef struct rt_snapshot nr_trace_snapshot;
typedef struct rt_error nr_trace_backend_error;
#else
#include "../owned-trace-backend/owned_trace_backend.h"
typedef struct otb_backend nr_trace_backend;
typedef struct otb_snapshot nr_trace_snapshot;
typedef struct otb_error nr_trace_backend_error;
#endif
#include "../bootstrap-io/bootstrap_io.h"
struct nr_attempt;
struct nr_trace {
 nr_trace_backend *backend;
 struct ts_session session;
 nr_trace_snapshot snapshot;
 nr_trace_backend_error create_error;
 struct bio_observer observer;
 struct bio_time cleanup_deadline;
 int create_attempted,session_present,cleanup_attempted,cleanup_valid;
 int snapshot_valid,destroy_attempted,destroyed,parent_reported,finalized,resources_safe;
};
int nr_trace_start(struct nr_attempt *);
int nr_trace_pump(struct nr_attempt *,enum ts_phase);
int nr_trace_claim_go(struct nr_attempt *);
int nr_trace_go_result(struct nr_attempt *,int);
int nr_trace_gate_result(struct nr_attempt *,int,int);
void nr_trace_bootstrap_result(struct nr_attempt *,int);
void nr_trace_child_result(struct nr_attempt *,int,int);
int nr_trace_claim_kill(struct nr_attempt *);
void nr_trace_begin_cleanup(struct nr_attempt *);
void nr_trace_close_backend(struct nr_attempt *);
int nr_trace_parent_closed(struct nr_attempt *,int);
int nr_trace_write_sidecar(struct nr_attempt *);
int nr_trace_success(const struct nr_attempt *);
#endif
