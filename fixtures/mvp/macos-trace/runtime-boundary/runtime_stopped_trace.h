#ifndef GLUE_RUNTIME_STOPPED_TRACE_H
#define GLUE_RUNTIME_STOPPED_TRACE_H
#include "runtime_trace_backend.h"
#include "runtime_trace_program.h"
#define RT_STOPPED_PROGRAM_PROFILE "glue-stopped-runtime-v1; first-selected-exec; owner-control-snapshots; no-process-creation"
#define RT_STOPPED_PROFILE_VERSION 1u
#define RT_STOPPED_LAYOUT_VERSION 1u
#define RT_STOPPED_SELECTORS 23u
/* Internal backend class3 still uses the existing runtime-recipe binding2.
 * No TS initializer, runner, controller, currentconsumer or nativeadmission is
 * selected by these APIs. No callerD/template/policy or injectedoperations. */
enum rt_stopped_identity_state { RT_STOPPED_PENDING, RT_STOPPED_PREFIX_RECORDED, RT_STOPPED_UNUSABLE };
struct rt_stopped_identity {
 uint32_t profile_version,layout_version;
 struct ts_binding binding;
 enum rt_stopped_identity_state state;
 unsigned program_written,entry_seen,success_seen,lwp_seen,marker_seen,later_exec;
 uint8_t program_sha256[32];
 uint64_t entry_ordinal,entry_tid;
 uint64_t exec_success_ordinal,exec_success_timestamp,new_tid;
 uint64_t lwp_start_ordinal,lwp_start_timestamp;
 uint64_t marker_ordinal,marker_timestamp,marker_epoch,latch_tid,signal;
 uint64_t total_events,common_counts[19],extra_counts[5];
 uint64_t drops,faults;
 struct rt_error first_error;
 int native_admission,quiescence_proved,state_admission,exemption_admission;
};
/* Pure fixed formatting, same output reset/capacity rules as rt_program.
 * Requires fixture2 and positive distinct signed32 PIDs/nonzero SHA bindings.
 * Return0 establishes canonical bytes only; no provider or process operation. */
int rt_stopped_program(const struct ts_binding *,char out[RT_PROGRAM_CAPACITY],size_t *used);
/* Same trusted confirmedREADY/owned-child/helddirectory/deadline requirements
 * as rt_recipe_images_create, separate source-selected stoppedclass only.
 * Destructive yes is requested ONLY by this class at start; restrictivepolicy
 * may refuse. Neither setter success nor marker proves an actual SIGSTOP.
 * Ordinary factories/options/programs are unchanged. No C signal/resume API,
 * processgrab/ptrace, mutableprogram, newTS or runneradoption is exposed. */
int rt_stopped_recipe_create(struct rt_backend **,int held_directory_fd,
 const struct ts_binding *,uint64_t original_attempt_deadline_ns,
 int confirmed_ready,struct ts_operations *,struct rt_error *);
/* Pure copy of already validated/serialized original callback identities.
 * No callback,I/O,clock,ownerquery or mutation. Pendingprefix is explicit;
 * any error/drop/fault/writefailure or laterexec makes it unusable. Fields
 * survive invalidation. PREFIX_RECORDED is not a stop/retention/native grant.
 * rt_snapshot refuses only this newclass; its oldABI/classes stay unchanged.
 * New19..23 counts are separate and never index old0..18 storage. */
int rt_stopped_identity(const struct rt_backend *,struct rt_stopped_identity *);
#endif
