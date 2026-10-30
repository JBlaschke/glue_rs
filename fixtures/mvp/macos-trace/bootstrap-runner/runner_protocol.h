#ifndef GLUE_BOOTSTRAP_RUNNER_PROTOCOL_H
#define GLUE_BOOTSTRAP_RUNNER_PROTOCOL_H
#include "../bootstrap-io/bootstrap_io.h"
#include "../bootstrap-request/bootstrap_request.h"
#include "../bootstrap-probe/probe_report.h"
#ifdef GLUE_FD_OBJECTS
#include "../bootstrap-object-wire/bootstrap_object_wire.h"
#define NR_STATUS_RECORD_BYTES BOW_STATUS_SIZE
#else
#define NR_STATUS_RECORD_BYTES BW_STATUS_SIZE
#endif
#define NR_STATUS_CAPACITY (3u*NR_STATUS_RECORD_BYTES+1u)
struct nr_status_stream {
    struct bw_state wire;
    uint8_t raw[NR_STATUS_CAPACITY]; size_t used;
    struct bio_error first_io_error;
    enum bw_fault first_wire_error;
    enum bw_eof_result end;
    int failed, ended;
#ifdef GLUE_FD_OBJECTS
    struct tfo_snapshot ready_objects;
#endif
};
/* Internal trusted state: initialize once; no rebind/concurrent caller mutation.
 * Native entry supplies bio_native_operations only. Tests use isolated models.
 * 0 means one accepted record, 1 confirmed on-time EOF, -1 failure. None is exec. */
int nr_status_init(struct nr_status_stream *,const struct bw_binding *);
int nr_status_next(struct nr_status_stream *,int,struct bio_time,const struct bio_operations *);
/* Explicit cooperative progress, including strict EOF/fallback, at the original
 * absolute deadline. Observer/callback are required; failed I/O prefixes remain
 * opaque and poison the stream even when a complete record was received. */
int nr_status_next_observed(struct nr_status_stream *,int,struct bio_time,
                            const struct bio_operations *,const struct bio_observer *);
/* Pure comparison of supplied declarations, not provenance or kernel proof. */
int nr_probe_compare(const struct br_request *,const struct bw_binding *,
                     const uint64_t expected_status_flags[3],const struct np_report *);
#endif
