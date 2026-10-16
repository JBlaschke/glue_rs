#ifndef GLUE_BOOTSTRAP_REQUEST_H
#define GLUE_BOOTSTRAP_REQUEST_H
#include <stddef.h>
#include <stdint.h>
#include "../target-credentials/target_credentials.h"
#include "../bootstrap-wire/bootstrap_wire.h"

#define BR_HEADER_SIZE 208u
#define BR_MAX_WIRE 16384u
#define BR_MAX_PATH 4095u
#define BR_MAX_COMPONENT 255u
#define BR_NO_INDEX SIZE_MAX
#define BR_READY_FLAGS (BW_CREDENTIAL_ATTEMPT | BW_DESCRIPTOR_ATTEMPT)
struct br_span { const uint8_t *bytes; size_t length; };
/* Host model, not a serialized struct. Wide scalars reject narrowing overflow. */
struct br_request {
    uint64_t fixture;
    struct tc_request credentials;
    uint64_t signal_policy, stdio_policy, release_action, max_live_fds;
    uint64_t attempt_ms, cleanup_ms, argv_template, environment_count;
    uint8_t catalog_sha256[32];
    uint64_t cwd_device, cwd_inode;
    struct br_span executable, cwd;
};
enum br_release_action { BR_SEND_GO=1, BR_SIMULATED_PROVIDER_FAILURE=2 };
enum br_fault {
    BR_OK=0, BR_ARGUMENT, BR_LENGTH, BR_MAGIC, BR_VERSION, BR_RESERVED,
    BR_SELECTOR, BR_RANGE, BR_GROUPS, BR_PATH, BR_CANONICAL,
    BR_CONTEXT, BR_STATUS, BR_MISMATCH
};
enum br_field {
    BR_FIELD_NONE=0, BR_FIELD_HEADER, BR_FIELD_FIXTURE, BR_FIELD_CREDENTIALS,
    BR_FIELD_SIGNAL_POLICY, BR_FIELD_STDIO_POLICY, BR_FIELD_RELEASE,
    BR_FIELD_FD_LIMIT, BR_FIELD_ATTEMPT_MS, BR_FIELD_CLEANUP_MS,
    BR_FIELD_ARGV_TEMPLATE, BR_FIELD_ENVIRONMENT, BR_FIELD_GROUPS,
    BR_FIELD_EXECUTABLE, BR_FIELD_CWD, BR_FIELD_BINDING, BR_FIELD_KEPT_FDS,
    BR_FIELD_READY_KIND, BR_FIELD_IDS, BR_FIELD_CWD_IDENTITY,
    BR_FIELD_READY_FLAGS
};
struct br_error {
    enum br_fault fault;
    enum br_field field;
    size_t index;
    enum bw_fault wire_fault;
};
/* Caller-selected declarations, not authenticated process/endpoint objects.
 * Signal digest denotes DFL/no-altstack/blocked-READY/empty-final-mask policy. */
struct br_ready_context {
    struct bw_binding binding;
    uint64_t kept_fds[5];
    uint8_t signal_policy_sha256[32];
};
/* Future runner vocabulary only: an attempted GO may already release the peer.
 * EOF outcomes use enum bw_eof_result; none proves exec or full acceptance. */
enum br_gate_observation { BR_GO_NOT_ATTEMPTED=0, BR_GO_POSSIBLY_RELEASED=1 };

/* Pure, allocation-free. All non-NULL objects/spans are valid, stable and mutually
 * nonoverlapping. error is mandatory. Encode output is exactly BR_MAX_WIRE bytes
 * and always fully cleared before validation; written is mandatory and starts0.
 * Decode output is cleared on every failure. Decoded spans borrow immutable input
 * bytes; no NUL is added. Invalid lengths reject before any input read. No IO,
 * hashing, callback, native credential operation, path admission or launch. */
enum br_fault br_request_encode(const struct br_request *, uint8_t out[BR_MAX_WIRE],
                                size_t *written, struct br_error *);
enum br_fault br_request_decode(const uint8_t *, size_t, struct br_request *, struct br_error *);
/* Valid canonical READY + exact requested observations. Expected request digest
 * must be computed by future native parent over consumed bytes; matching supplied
 * declarations alone does NOT authenticate a request or authorize GO/exec. */
enum br_fault br_ready_compare(const struct br_request *, const struct br_ready_context *,
                               const struct bw_status *, struct br_error *);
#endif
