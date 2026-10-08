/* Ordinary OS-loader comparison for the controlled memfd fixture. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*answer_fn)(const char *);
typedef int (*count_fn)(void);

static void loader_failure(const char *operation) {
    const char *error = dlerror();
    fprintf(stderr, "baseline failed: %s: %s\n", operation,
            error != NULL ? error : "no loader diagnostic");
}

static int lookup(void *handle, const char *name, void **result) {
    dlerror();
    *result = dlsym(handle, name);
    const char *error = dlerror();
    if (error != NULL || *result == NULL) {
        fprintf(stderr, "baseline failed: dlsym(%s): %s\n", name,
                error != NULL ? error : "NULL fixture export");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: baseline MODULE_SO\n");
        return EXIT_FAILURE;
    }
    dlerror();
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        loader_failure("dlopen");
        return EXIT_FAILURE;
    }

    int status = EXIT_FAILURE;
    void *reopened = NULL;
    void *answer_symbol, *data_symbol, *count_symbol;
    if (lookup(handle, "glue_answer", &answer_symbol) != 0 ||
        lookup(handle, "glue_probe_data", &data_symbol) != 0 ||
        lookup(handle, "glue_probe_constructor_count", &count_symbol) != 0) {
        goto cleanup;
    }
    /* The Linux POSIX loader returns the fixed C ABI exports in module.c.
       memcpy preserves pointer representation without aliasing typed objects. */
    answer_fn answer;
    count_fn count;
    _Static_assert(sizeof(answer) == sizeof(answer_symbol), "Linux pointer ABI");
    _Static_assert(sizeof(count) == sizeof(count_symbol), "Linux pointer ABI");
    memcpy(&answer, &answer_symbol, sizeof(answer));
    memcpy(&count, &count_symbol, sizeof(count));
    int observed_answer = answer("archive");
    int observed_data = *(const int *)data_symbol;
    int constructors = count();
    if (observed_answer != 42 || observed_data != 7 || constructors != 1) {
        fprintf(stderr,
                "baseline failed: answer=%d data=%d constructors=%d; expected 42/7/1\n",
                observed_answer, observed_data, constructors);
        goto cleanup;
    }
    dlerror();
    reopened = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (reopened == NULL) {
        loader_failure("repeated dlopen");
        goto cleanup;
    }
    if (reopened != handle || count() != 1) {
        fprintf(stderr, "baseline failed: repeated loading changed handle or constructor count\n");
        goto cleanup;
    }
    status = EXIT_SUCCESS;

cleanup:
    if (reopened != NULL) {
        dlerror();
        if (dlclose(reopened) != 0) {
            loader_failure("dlclose repeated reference");
            status = EXIT_FAILURE;
        }
    }
    dlerror();
    if (dlclose(handle) != 0) {
        loader_failure("dlclose original reference");
        status = EXIT_FAILURE;
    }
    if (status == EXIT_SUCCESS) {
        puts("baseline PASS answer=42 data=7 constructors=1 mechanism=ordinary-disk-dlopen");
    }
    return status;
}
