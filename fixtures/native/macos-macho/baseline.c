/* Ordinary dyld loading of exactly the same dependency/module images. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int (*probe_fn)(void);

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

static int call(void *symbol) {
    probe_fn function;
    _Static_assert(sizeof(function) == sizeof(symbol), "macOS pointer ABI");
    memcpy(&function, &symbol, sizeof(function));
    return function();
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: baseline DEPENDENCY_DYLIB MODULE_DYLIB\n");
        return EXIT_FAILURE;
    }
    dlerror();
    void *dependency = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (dependency == NULL) {
        fprintf(stderr, "baseline failed: dependency dlopen: %s\n", dlerror());
        return EXIT_FAILURE;
    }
    void *module = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (module == NULL) {
        fprintf(stderr, "baseline failed: module dlopen: %s\n", dlerror());
        (void)dlclose(dependency);
        return EXIT_FAILURE;
    }
    void *answer, *data, *count, *pid;
    int status = EXIT_FAILURE;
    if (lookup(module, "glue_answer", &answer) != 0 ||
        lookup(module, "glue_probe_data", &data) != 0 ||
        lookup(module, "glue_probe_constructor_count", &count) != 0 ||
        lookup(module, "glue_probe_pid", &pid) != 0) {
        goto cleanup;
    }
    int answer_value = call(answer);
    int data_value = *(const int *)data;
    int constructors = call(count);
    int pid_value = call(pid);
    if (answer_value != 42 || data_value != 7 || constructors != 1 ||
        pid_value != (int)getpid()) {
        fprintf(stderr, "baseline failed: answer=%d data=%d constructors=%d pid=%d\n",
                answer_value, data_value, constructors, pid_value);
        goto cleanup;
    }
    void *reopened = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (reopened == NULL || reopened != module || call(count) != 1) {
        fprintf(stderr, "baseline failed: repeated loading changed identity or constructor count\n");
        if (reopened != NULL) {
            (void)dlclose(reopened);
        }
        goto cleanup;
    }
    if (dlclose(reopened) != 0) {
        fprintf(stderr, "baseline failed: repeated dlclose: %s\n", dlerror());
        goto cleanup;
    }
    printf("PASS answer=42 data=7 constructors=1 pid=%d\n", pid_value);
    status = EXIT_SUCCESS;

cleanup:
    if (dlclose(module) != 0 || dlclose(dependency) != 0) {
        fprintf(stderr, "baseline failed: dlclose: %s\n", dlerror());
        status = EXIT_FAILURE;
    }
    return status;
}
