#ifndef GLUE_BOOTSTRAP_RUNNER_PROTOCOL_H
#define GLUE_BOOTSTRAP_RUNNER_PROTOCOL_H
#include "../bootstrap-io/bootstrap_io.h"
#include "../bootstrap-request/bootstrap_request.h"
#include "../bootstrap-probe/probe_report.h"
#define NR_STATUS_CAPACITY (3u*BW_STATUS_SIZE+1u)
struct nr_status_stream {
    struct bw_state wire;
    uint8_t raw[NR_STATUS_CAPACITY]; size_t used;
    struct bio_error first_io_error;
    enum bw_fault first_wire_error;
    enum bw_eof_result end;
    int failed, ended;
};
/* Internal trusted state: initialize once; no rebind/concurrent caller mutation.
 * Native entry supplies bio_native_operations only. Tests use isolated models.
 * 0 means one accepted record, 1 confirmed on-time EOF, -1 failure. None is exec. */
int nr_status_init(struct nr_status_stream *,const struct bw_binding *);
int nr_status_next(struct nr_status_stream *,int,struct bio_time,const struct bio_operations *);
/* Pure comparison of supplied declarations, not provenance or kernel proof. */
int nr_probe_compare(const struct br_request *,const struct bw_binding *,
                     const uint64_t expected_status_flags[3],const struct np_report *);
#endif
