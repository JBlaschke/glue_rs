#ifndef GLUE_RUNNER_TRACE_H
#define GLUE_RUNNER_TRACE_H
#include "../owned-trace-backend/owned_trace_backend.h"
#include "../bootstrap-io/bootstrap_io.h"
struct nr_attempt;
struct nr_trace {
 struct otb_backend *backend;
 struct ts_session session;
 struct otb_snapshot snapshot;
 struct otb_error create_error;
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
