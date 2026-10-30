#ifndef GLUE_BOOTSTRAP_OBJECT_WIRE_H
#define GLUE_BOOTSTRAP_OBJECT_WIRE_H
#include "../bootstrap-wire/bootstrap_wire.h"
#include "../target-fd-objects/target_fd_objects.h"

#define BOW_STATUS_SIZE 512u
#define BOW_PAYLOAD_OFFSET 32u
#define BOW_ROW_OFFSET 288u
#define BOW_ROW_SIZE 40u
#define BOW_GO_SIZE 64u

/* Pure, allocation-free data codec. All non-NULL objects, nested members and
 * spans must be valid, aligned, stable and nonoverlapping for the call. Fixed
 * output spans require their complete advertised size. NULL is rejected, never
 * dereferenced. Every available output is cleared on every refusal. Decode
 * checks the exact input length before reading input bytes.
 *
 * READY requires a snapshot with ready == 1, the same controller/child binding
 * and exactly the five BW kept_fds, in order. Native int FDs/flags must be
 * nonnegative; all bits are preserved. Mode/device/inode/link fields are opaque
 * typed observations. ERROR/EXEC_ATTEMPT require a NULL snapshot and zero rows.
 * Binding, ownership, native provenance, object matching, IO, deadlines and
 * authorization remain the caller's responsibility. No legacy wire fallback.
 */
enum bw_fault bow_status_encode(const struct bw_status *,
    const struct tfo_snapshot *, uint8_t out[BOW_STATUS_SIZE]);
enum bw_fault bow_status_decode(const uint8_t *, size_t,
    const struct bw_binding *, struct bw_status *, struct tfo_snapshot *);
enum bw_fault bow_go_encode(const struct bw_binding *, uint8_t out[BOW_GO_SIZE]);
enum bw_fault bow_go_decode(const uint8_t *, size_t,
    const struct bw_binding *, struct bw_binding *);
#endif
