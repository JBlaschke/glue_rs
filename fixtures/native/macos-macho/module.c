/* Trusted C ABI fixture, not a Lua/Python/Node extension. */
#include <unistd.h>

extern int glue_probe_dep(void);

int glue_probe_data = 7;
/* Volatile preserves the initializer and its rebase slot in the linked image. */
static volatile int constructor_count;

__attribute__((constructor))
static void initialize_probe(void) {
    ++constructor_count;
}

int glue_answer(void) {
    return glue_probe_dep() + glue_probe_data;
}

int glue_probe_constructor_count(void) {
    return constructor_count;
}

int glue_probe_pid(void) {
    return (int)getpid();
}
