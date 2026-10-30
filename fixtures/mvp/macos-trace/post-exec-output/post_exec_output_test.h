#ifndef GLUE_POST_EXEC_OUTPUT_TEST_H
#define GLUE_POST_EXEC_OUTPUT_TEST_H
#ifndef PX_TESTING
#error test-only model operations require PX_TESTING
#endif
#include "post_exec_output.h"
#include <stddef.h>
#include <sys/types.h>
/* Model inputs are injected controls, never native admission or a public
 * supported/profile selector. Production builds expose only the native factory. */
struct px_test_operations {
 void *context;
 pid_t (*getpid_fn)(void *);
 int (*policy_fn)(void *, int *); /* 0 success, -1 with saved errno */
 int (*clock_fn)(void *, uint64_t *, int *); /* monotonic ns, 0/-1 */
 pid_t (*wait_fn)(void *, pid_t, int *, int, int *);
 int (*query_fn)(void *, pid_t, int, uint8_t [PX_NATIVE_BYTES], int *);
};
struct px_observer *px_observer_model_new(const struct px_plan *,
 const struct px_test_operations *, struct px_error *);
#endif
