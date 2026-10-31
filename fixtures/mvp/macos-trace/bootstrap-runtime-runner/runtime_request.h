#ifndef GLUE_RUNTIME_BOOTSTRAP_REQUEST_H
#define GLUE_RUNTIME_BOOTSTRAP_REQUEST_H
#include "../bootstrap-request/bootstrap_request.h"
/* Separate closed request profile: fixture2/template2, empty environment.
 * No argv/environment bytes or native trust flags are accepted from the wire.
 * The BR valid/stable/nonoverlapping object/span preconditions still apply.
 * Decoded spans borrow the actual immutable input. This API grants no launch. */
enum br_fault rr_request_encode(const struct br_request *,uint8_t out[BR_MAX_WIRE],size_t *,struct br_error *);
enum br_fault rr_request_decode(const uint8_t *,size_t,struct br_request *,struct br_error *);
enum br_fault rr_ready_compare(const struct br_request *,const struct br_ready_context *,const struct bw_status *,struct br_error *);
#endif
