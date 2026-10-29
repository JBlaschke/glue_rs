#ifndef GLUE_RUNNER_INTERNAL_H
#define GLUE_RUNNER_INTERNAL_H
#define _DARWIN_C_SOURCE 1
#include "runner_catalog.h"
#ifdef GLUE_RUNTIME_PROFILE
#include "../bootstrap-runtime-runner/runtime_catalog.h"
#include "../bootstrap-runtime-runner/runtime_request.h"
#include "../bootstrap-runtime-runner/runtime_witness.h"
#endif
#include "runner_protocol.h"
#include "../bootstrap-signals/bootstrap_signals.h"
#include "../target-endpoints/target_endpoints.h"
#include "../target-descriptors/target_descriptors.h"
#include <sys/stat.h>
#include <sys/types.h>
#ifdef GLUE_OWNED_TRACING
#include "runner_trace.h"
#endif

enum nr_stage {NR_NONE,NR_PREFLIGHT,NR_SIGNAL,NR_REQUEST,NR_CATALOG,NR_ADMISSION,NR_OUTPUT,
 NR_ENDPOINTS,NR_FORK,NR_PROCESS_GROUP,NR_READY,NR_GO,NR_STATUS,NR_WAIT,NR_PROBE,NR_CLEANUP,NR_FINALIZE,NR_TRACE};
enum nr_reason {NR_NO_ERROR,NR_INVALID,NR_UNSUPPORTED,NR_NOT_ROOT,NR_UNCONFIGURED,
 NR_SYSCALL,NR_MISMATCH,NR_TIMEOUT,NR_CLOCK,NR_HELPER,NR_INCOMPLETE,NR_PROTOCOL,NR_REPORTED,
 NR_CHILD_STATUS,NR_LOST_CHILD,NR_OWNERSHIP};
struct nr_error {enum nr_stage stage;enum nr_reason reason;int saved_errno;int detail;};
struct nr_attempt {
 const struct nr_catalog *catalog;
#ifdef GLUE_RUNTIME_PROFILE
 const struct nrr_catalog *runtime_catalog;
 struct tl_plan runtime_plan;
 int runtime_cwd_fd,runtime_outputs_valid;
 int runtime_witness_attempted,runtime_delivery_attempted;
 int runtime_witness_written,runtime_delivery_written;
 struct ba_metadata runtime_cwd_metadata;
 uint64_t runtime_stream_sizes[2];
 int runtime_stream_observed[2],runtime_stream_oversize[2];
#endif
 struct nr_error error,cleanup_error;
 uint8_t request_wire[BR_MAX_WIRE];size_t request_size;struct br_request request;
 uint8_t request_sha[32],catalog_sha[32],policy_sha[32];char request_hex[65];
 char executable[BA_PATH_MAX],cwd[BA_PATH_MAX],output_path[BA_PATH_MAX];
 struct ba_result admission;struct ba_error admission_error;
 struct bs_state signals;int signals_initialized,signals_restored;struct bs_error signal_prepare_error,signal_restore_error;
 struct te_prepared endpoints;struct te_error endpoint_error;
 int output_fd,sources[5],gate[2],status[2],ownership_uncertain,close_failed;
 struct stat stdout_identity,stderr_identity;
 uint64_t stdio_flags[3],ready_context_fds[2];
 pid_t owner,child;int forked,reaped,lost_child,wait_status,kill_attempted;
 struct bio_time deadline;uint64_t start_clock,last_clock;
 struct nr_status_stream stream;struct bw_status ready;int ready_matched,probe_matched;
 struct bio_result go_result;struct bio_error go_error;int go_attempted,go_closed;
 enum br_fault ready_fault;enum np_fault probe_fault;
#ifdef GLUE_FD_OBJECTS
 int held_outputs[2],objects_matched;
 struct tfo_snapshot child_objects;
 struct tfo_matches output_matches;struct tfo_error object_match_error;
#endif
#ifdef GLUE_OWNED_TRACING
 struct nr_trace trace;
#endif
};
int nr_fail(struct nr_attempt *,enum nr_stage,enum nr_reason,int,int);
int nr_close_owned(struct nr_attempt *,int *,enum nr_stage);
int nr_clock(struct nr_attempt *,uint64_t *);
int nr_deadline(struct nr_attempt *,unsigned,struct bio_time *);
int nr_before(struct nr_attempt *,struct bio_time,enum nr_stage);
int nr_sha_bytes(const uint8_t *,size_t,uint8_t [32]);
int nr_read_request(struct nr_attempt *,const char *);
int nr_admit(struct nr_attempt *);
int nr_output(struct nr_attempt *,const char *);
int nr_endpoints(struct nr_attempt *);
int nr_write_new(struct nr_attempt *,const char *,const uint8_t *,size_t);
int nr_finish_outputs(struct nr_attempt *);
_Noreturn void nr_child(struct nr_attempt *);
void nr_cleanup(struct nr_attempt *);
int nr_execute(struct nr_attempt *);
#endif
