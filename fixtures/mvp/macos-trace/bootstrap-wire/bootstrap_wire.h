#ifndef GLUE_BOOTSTRAP_WIRE_H
#define GLUE_BOOTSTRAP_WIRE_H
#include <stddef.h>
#include <stdint.h>
#define BW_STATUS_SIZE 256u
#define BW_GO_SIZE 64u
#define BW_GROUPS 16u
#define BW_CREDENTIAL_ATTEMPT 1u
#define BW_DESCRIPTOR_ATTEMPT 2u
enum bw_kind { BW_READY=1, BW_EXEC_ATTEMPT=2, BW_ERROR=3 };
enum bw_stage { BW_NONE=0, BW_REQUEST, BW_PROCESS_GROUP, BW_SIGNALS, BW_STDIO,
    BW_CREDENTIALS, BW_CWD, BW_DESCRIPTORS, BW_READY_IO, BW_GO_IO, BW_GO_VALIDATE,
    BW_GATE_CLOSE, BW_MASK_RESTORE, BW_EXEC };
enum bw_reason { BW_REASON_NONE=0, BW_ARGUMENT, BW_RANGE, BW_SYSCALL, BW_MISMATCH,
    BW_OWNERSHIP, BW_SIGNAL_POLICY, BW_CAPACITY, BW_DUPLICATE, BW_MISSING_KEEP,
    BW_EOF, BW_EXTRA, BW_TIMEOUT, BW_SHORT, BW_UNSUPPORTED, BW_ADAPTER,
    BW_REPLACEMENT, BW_SET_ID };
enum bw_fault { BW_OK=0, BW_FAULT_ARGUMENT, BW_FAULT_LENGTH, BW_FAULT_MAGIC,
    BW_FAULT_VERSION, BW_FAULT_KIND, BW_FAULT_RESERVED, BW_FAULT_BINDING,
    BW_FAULT_CANONICAL, BW_FAULT_ORDER, BW_FAULT_EXTRA, BW_FAULT_STATE };
struct bw_binding { uint32_t controller_pid, child_pid; uint8_t request_sha256[32]; };
/* Host models, NOT serialized C layouts. Caller checks native-width conversions. */
struct bw_status {
    struct bw_binding binding;
    uint32_t kind, sequence, stage, system_errno, mutation_flags;
    uint32_t real_uid, effective_uid, real_gid, effective_gid, group_count;
    uint32_t groups[BW_GROUPS];
    uint64_t cwd_device, cwd_inode;
    uint32_t kept_fds[5];
    uint8_t signal_policy_sha256[32];
    uint32_t reason;
    int64_t detail; /* Canonical values -1..INT32_MAX only. */
};
enum bw_phase { BW_START=0, BW_HAVE_READY, BW_HAVE_ATTEMPT, BW_REPORTED_ERROR, BW_POISONED };
enum bw_eof_result { BW_END_INVALID=0, BW_END_INCOMPLETE, BW_END_REPORTED_ERROR,
    BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR };
/* Initialize only with bw_state_init; do not modify between calls. last is the
 * last accepted record, never evidence that it matches an actual launch request.
 * reported_error is retained even if a later extra record poisons the state. */
struct bw_state {
    uint32_t tag, phase, accepted_records, sealed, ready_flags, has_reported_error;
    enum bw_fault first_fault;
    struct bw_binding expected;
    struct bw_status last, reported_error;
};
/* Pure, allocation-free data API. All non-NULL objects/spans must be valid,
 * aligned, stable and nonoverlapping. Encode output spans are fixed256/64 bytes
 * and cleared on failure; decode output objects are cleared on failure. Exact
 * lengths are checked before input reads. NULL is rejected, not dereferenced.
 * Bindings are caller-selected known controller/unreaped child/request context.
 * No ownership, IO, clock, exec, requested-observation or acceptance proof. */
enum bw_fault bw_status_encode(const struct bw_status *, uint8_t out[BW_STATUS_SIZE]);
enum bw_fault bw_status_decode(const uint8_t *, size_t, const struct bw_binding *, struct bw_status *);
enum bw_fault bw_go_encode(const struct bw_binding *, uint8_t out[BW_GO_SIZE]);
enum bw_fault bw_go_decode(const uint8_t *, size_t, const struct bw_binding *, struct bw_binding *);
enum bw_fault bw_state_init(struct bw_state *, const struct bw_binding *);
enum bw_fault bw_state_push(struct bw_state *, const uint8_t *, size_t);
enum bw_eof_result bw_state_finish(struct bw_state *);
#endif
