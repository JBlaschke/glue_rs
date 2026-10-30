#ifndef GLUE_POST_EXEC_RETENTION_H
#define GLUE_POST_EXEC_RETENTION_H
#include "../post-exec-output/post_exec_output.h"
#include <stddef.h>
#include <stdint.h>
#define PXRET_WRITE_LIMIT 64u
#define PXRET_BASENAME "post-exec-output.bin"
enum px_retention_state { PXRET_NEW=1, PXRET_REFUSED, PXRET_FILE_SYNCED };
enum px_retention_stage { PXRET_VALIDATE, PXRET_DIR_FD, PXRET_DIR_FL,
 PXRET_DIR_STAT, PXRET_OPEN, PXRET_FILE_FD, PXRET_FILE_FL, PXRET_FILE_STAT,
 PXRET_WRITE, PXRET_SYNC, PXRET_CLOSE, PXRET_FINAL };
enum px_retention_reason { PXRET_OK, PXRET_ARGUMENT, PXRET_REPLAY, PXRET_OWNER,
 PXRET_LEASE, PXRET_OBSERVATION, PXRET_DEADLINE_BINDING, PXRET_CLOCK,
 PXRET_ROLLBACK, PXRET_LATE, PXRET_SYSCALL, PXRET_IDENTITY, PXRET_FLAGS,
 PXRET_ZERO_WRITE, PXRET_BAD_RESULT, PXRET_LIMIT };
struct px_retention_error {
 enum px_retention_stage stage;
 enum px_retention_reason reason;
 int system_errno;
};
struct px_retention_call {
 uint64_t before_ns, after_ns;
 int64_t result;
 int system_errno;
 unsigned attempted, before_present, after_present;
 struct px_retention_error before_error, after_error;
};
struct px_retention_identity {
 uint64_t device, inode, uid, links;
 int64_t size;
 uint32_t mode;
};
struct px_retention_status {
 enum px_retention_state state;
 uint32_t owner_pid, child_pid;
 uint64_t effective_uid, original_deadline_ns, last_clock_ns;
 int borrowed_directory_fd, opened_fd;
 unsigned attempt_consumed, observation_encoded, open_succeeded;
 unsigned write_rows, write_calls, sync_succeeded, close_succeeded;
 unsigned file_ownership_unresolved, file_synced_content;
 size_t bytes_written;
 unsigned faults, clock_faults;
 struct px_retention_error first_error, last_error;
 struct px_error observer_error;
 struct px_retention_identity directory_identity, file_identity;
 struct px_retention_call directory_fd_flags, directory_status_flags, directory_stat;
 struct px_retention_call open_call, file_fd_flags, file_status_flags, file_stat;
 struct px_retention_call writes[PXRET_WRITE_LIMIT], sync_call, close_call, final_check;
 int native_admission, state_admission, output_authority, full_acceptance;
 int namespace_durability, power_loss_durability;
};
struct px_retention;
/* Trusted source-selected caller only. Borrow the actual completed observer and
 * a fresh private0700 current-EUID directory opened O_RDONLY|O_CLOEXEC (fd>=3).
 * Keep both alive/stable; sole actual fork-PID reaper/controller, unchanged
 * credentials/FDs/namespace and the observer's original clock/deadline apply.
 * The borrowed directory is never mutated, duplicated or closed. No packet,
 * pathname, policy boolean or callback is accepted. Native origin is unproved. */
struct px_retention *px_retention_new(const struct px_observer *,int borrowed_directory_fd,
 uint64_t original_deadline_ns,struct px_retention_error *);
/* Exactly one attempt, including refusal. Actual encoder/owns APIs are used.
 * Exclusive fixed basename; <=64 writes including EINTR; one file fsync and
 * one close. Checks cannot interrupt a blocked syscall. Return0 means timely
 * file-synced content/actual close only, never namespace/power-loss durability,
 * child execution permission, current reader adoption or native acceptance. */
int px_retention_write(struct px_retention *,struct px_retention_error *);
/* Pure copied observations, no owner/clock/I/O callbacks. Bad output is zeroed.
 * copy_observation returns the exact encoder bytes, including refused prefixes. */
int px_retention_snapshot(const struct px_retention *,struct px_retention_status *);
int px_retention_copy_observation(const struct px_retention *,uint8_t out[PX_BYTES]);
/* Memory only. Never closes, retries, unlinks or reopens. Capture status first:
 * a failed close retains unresolved ownership of opened_fd for caller diagnosis;
 * freeing memory is not evidence that this descriptor/resource was resolved. */
void px_retention_free(struct px_retention *);
#endif
