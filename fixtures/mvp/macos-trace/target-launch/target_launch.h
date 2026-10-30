#ifndef GLUE_TARGET_LAUNCH_H
#define GLUE_TARGET_LAUNCH_H
#include <stddef.h>
#include <stdint.h>

#define TL_MAX_ARGS 16u
#define TL_MAX_BYTES 4096u
#define TL_MAX_EXECUTABLE_BYTES 255u
#define TL_CANONICAL_CAPACITY (24u + 4u * TL_MAX_ARGS + TL_MAX_BYTES)

struct tl_span { const uint8_t *bytes; size_t length; };
enum tl_target { TL_AARCH64_DARWIN = 1 };
struct tl_recipe {
    uint64_t target;
    /* These arguments exclude the separately supplied executable. */
    const struct tl_span *arguments;
    size_t argument_count;
    size_t environment_count;
};
enum tl_reason {
    TL_REASON_NONE, TL_REASON_ARGUMENT, TL_REASON_TARGET,
    TL_REASON_ENVIRONMENT, TL_REASON_COUNT, TL_REASON_SPAN,
    TL_REASON_PATH, TL_REASON_CAPACITY, TL_REASON_PLAN
};
struct tl_error {
    enum tl_reason reason;
    /* argv index, including executable at zero; SIZE_MAX when not indexed. */
    size_t argument;
};
struct tl_plan {
    uint64_t target;
    /* Total argument count, including argv[0]. used includes every terminator. */
    size_t argument_count;
    size_t environment_count;
    size_t used;
    int ready;
    char storage[TL_MAX_BYTES];
    char *argv[TL_MAX_ARGS + 1u];
    char *environment[1];
};

/* Pure copied data, not authorization or native path/runtime admission. Inputs
 * must name readable, stable storage for the entire call and must not alias
 * either output; the plan and error outputs must not alias each other. An empty
 * argument may use {NULL, 0}; a
 * nonempty span requires bytes. All spans exclude their terminator and contain
 * no NUL. The executable is an absolute 2..255-byte POSIX path with nonempty
 * components other than "." or ".." and no trailing slash. Other bytes,
 * including spaces, UTF-8 or non-UTF-8 bytes, are copied literally.
 *
 * Only target 1 and environment_count 0 are supported. The argument vector may
 * contain 0..15 recipe arguments; total copied bytes including argv[0] and all
 * terminators may not exceed 4096. Success produces envp={NULL}. Failure clears
 * the entire plan when supplied. The plan owns its bytes but contains internal
 * pointers: keep its address fixed, do not copy/move it, and do not mutate it
 * between preparation and use. No allocation, callbacks, or syscalls occur. */
int tl_prepare(const struct tl_recipe *, struct tl_span executable,
               struct tl_plan *, struct tl_error *);

/* Canonical version 1: eight bytes {'G','L','U','E','T','L',0,1}, target BE64,
 * total argc BE32, envc BE32 (zero), then for every argv entry a BE32 length and
 * its exact bytes excluding NUL. Length framing distinguishes empty/absent and
 * argument boundaries. At most TL_CANONICAL_CAPACITY bytes are needed.
 *
 * Plan, output and used must not alias. The output must span capacity writable
 * bytes. Failure clears that output and sets *used=0 when supplied. Validation
 * rejects malformed counts, layout, termination, target, environment or path;
 * it does not authenticate a plan against its compiled source or detect every
 * possible valid-byte mutation. */
int tl_canonical(const struct tl_plan *, uint8_t *out, size_t capacity,
                 size_t *used);
#endif
