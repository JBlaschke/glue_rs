#ifndef GLUE_RUNTIME_TRACE_PROGRAM_H
#define GLUE_RUNTIME_TRACE_PROGRAM_H
#include <stddef.h>
#include <stdint.h>
#define RT_PROGRAM_CAPACITY 16384u
#define RT_PROGRAM_PROFILE "glue-runtime-boundary-v1; selected-exec; no-process-creation"
#define RT_IMAGES_PROGRAM_PROFILE "glue-runtime-images-v2; quiescent-exec; no-process-creation"
/* Pure formatting only: no provider, file, process, or clock access. The caller
 * supplies a nonoverlapping RT_PROGRAM_CAPACITY-byte output and size pointer.
 * A positive signed-32-bit PID selects the sole watched process. Success emits
 * canonical NUL-terminated D bytes and their length excluding NUL. On refusal
 * available outputs are reset to empty/zero. No caller-selectable clauses. */
int rt_program(uint32_t target_pid,char out[RT_PROGRAM_CAPACITY],size_t *used);
/* Separate fixed v2 producer. Same bounds/layout, distinct profile marker;
 * thread/image interpretation belongs to the independent full-stream reader. */
int rt_images_program(uint32_t target_pid,char out[RT_PROGRAM_CAPACITY],size_t *used);
#endif
