#ifndef GLUE_RUNTIME_OUTPUT_WITNESS_H
#define GLUE_RUNTIME_OUTPUT_WITNESS_H
#include "../target-fd-objects/target_fd_objects.h"
#include "../bootstrap-io/bootstrap_io.h"
#define NRW_OUTPUT_BYTES 320u
#define NRW_DELIVERY_BYTES 240u
struct nrw_binding {
 uint32_t owner,child;
 uint8_t request_sha[32],catalog_sha[32],ready_sha[32];
};
/* Canonical transport of original observations, not an authentication API.
 * Valid stable mutually nonoverlapping input/output spans are required.
 * Failure clears the entire advertised output. No I/O, match/admission or retry. */
int nrw_output_encode(const struct nrw_binding *,const struct tfo_reference_observation *,
 const struct tfo_error *,uint8_t out[NRW_OUTPUT_BYTES]);
int nrw_delivery_encode(const struct nrw_binding *,unsigned action,int attempted,
 const struct bio_result *,const struct bio_error *,int write_result,
 int close_attempted,int close_result,int close_errno,uint8_t out[NRW_DELIVERY_BYTES]);
struct nr_attempt;
/* Actual parent calls once before trace/GO and once after its gate operation.
 * Confirmed prefixes stay opaque on failure, including full failed delivery. */
int nrw_record_ready(struct nr_attempt *,const struct tfo_reference_observation *);
int nrw_record_delivery(struct nr_attempt *,int write_result,int close_result,int close_errno);
#endif
