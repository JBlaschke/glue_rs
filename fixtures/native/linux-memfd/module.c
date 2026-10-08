/* Controlled ABI fixture. Compile with -fno-builtin-strlen and a dependency SONAME. */
#include <string.h>

extern int glue_probe_dep(void);

int glue_probe_data = 7;
static int constructor_count;

__attribute__((constructor))
static void initialize_probe(void) {
    ++constructor_count;
}

int glue_probe_constructor_count(void) {
    return constructor_count;
}

int glue_answer(const char *input) {
    return glue_probe_dep() + (int)strlen(input);
}
