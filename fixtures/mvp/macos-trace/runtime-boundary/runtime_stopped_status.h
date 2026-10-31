#ifndef GLUE_RUNTIME_STOPPED_STATUS_H
#define GLUE_RUNTIME_STOPPED_STATUS_H
#include "runtime_stopped_trace.h"
#define RT_STOPPED_STATUS_VERSION 1u
/* Distinct diagnostic for the stopped class. This does not change or make the
 * old rt_snapshot API accept that class. lifecycle.events is the TOTAL outer
 * event count; identity.common_counts[0..18]/extra_counts[0..4] retain their
 * separate domains. No field is a session-success or authority grant. */
struct rt_stopped_status {
 uint32_t version,profile_version,layout_version;
 struct rt_stopped_identity identity;
 struct rt_snapshot lifecycle;
 int native_admission,quiescence_proved,state_admission,exemption_admission;
 int full_flags_authority;
};
/* Pure live-object copy: no callback, I/O, clock, owner query or mutation.
 * Output is cleared before refusing NULL or a foreign class. The backend must
 * remain live, with non-aliased output and no concurrent mutation. After
 * rt_destroy the owner's backend pointer is NULL and is refused; a stale
 * freed alias must never be passed. Old APIs/factories remain unchanged. */
int rt_stopped_status(const struct rt_backend *,struct rt_stopped_status *);
#endif
