#define _GNU_SOURCE
#include <Python.h>
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ledger.h"

/* Independent build-time comparison: no Rust adapter or archive importer. */
static void fail(const char *message)
{
    const char *detail = dlerror();
    fprintf(stderr, "%s%s%s\n", message, detail ? ": " : "", detail ? detail : "");
    exit(1);
}

static void *symbol(void *handle, const char *name)
{
    dlerror();
    void *address = dlsym(handle, name);
    if (address == NULL || dlerror() != NULL) {
        fail(name);
    }
    return address;
}

static uintptr_t image_base(void *handle)
{
    struct link_map *map = NULL;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || map == NULL) {
        fail("link map");
    }
    return (uintptr_t)map->l_addr;
}

static void require_owner(void *handle, const char *name, uintptr_t expected)
{
    Dl_info owner;
    if (!dladdr(symbol(handle, name), &owner) || (uintptr_t)owner.dli_fbase != expected) {
        fail("unexpected imported symbol owner");
    }
}

static void *load(const char *path)
{
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fail("private image load");
    }
    /* Keep every image live through Py_FinalizeEx and process termination. */
    return handle;
}

static void require_status(PyStatus status,
                           int (*exception)(PyStatus),
                           int (*is_exit)(PyStatus))
{
    if (is_exit(status)) {
        fprintf(stderr, "Python configuration requested exit: %d\n", status.exitcode);
        exit(1);
    }
    if (exception(status)) {
        fprintf(stderr, "Python configuration: %s\n",
                status.err_msg ? status.err_msg : "unknown error");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "Usage: baseline-driver PRODUCER NATIVE_DIRECTORY APP_FILE LIBRARY\n");
        return 1;
    }
    void *runtime = load(argv[4]);
    uintptr_t runtime_base = image_base(runtime);
    int (*status_exception)(PyStatus) = symbol(runtime, "PyStatus_Exception");
    int (*status_is_exit)(PyStatus) = symbol(runtime, "PyStatus_IsExit");
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/libglue_python_lifecycle.so", argv[2]);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        fail("dependency path too long");
    }
    void *dependency = load(path);
    uintptr_t dependency_base = image_base(dependency);
    const char *names[] = {
        "glue_native_lifecycle", "glue_native_create_error", "glue_native_lifecycle_exec_error"
    };
    const char *imports[] = {
        "PyLong_FromLong", "PyModule_NewObject", "PyModuleDef_Init", "PyModule_GetState",
        "PyModule_AddIntConstant", "PyObject_GetAttrString", "PyList_New", "PyList_SetItem",
        "PyErr_SetString", "PyExc_RuntimeError", "Py_IncRef", "Py_DecRef", NULL
    };
    long (*ledger)(long, long, long) = symbol(dependency, "glue_python_lifecycle_ledger");
    require_owner(dependency, "glue_python_lifecycle_ledger", dependency_base);
    int (*append)(const char *, PyObject *(*)(void)) = symbol(runtime, "PyImport_AppendInittab");
    for (size_t index = 0; index < 3; index++) {
        length = snprintf(path, sizeof(path), "%s/%s.so", argv[2], names[index]);
        if (length < 0 || (size_t)length >= sizeof(path)) {
            fail("module path too long");
        }
        void *module = load(path);
        require_owner(module, "glue_python_lifecycle_ledger", dependency_base);
        for (size_t imported = 0; imports[imported] != NULL; imported++) {
            require_owner(module, imports[imported], runtime_base);
        }
        char initializer[256];
        length = snprintf(initializer, sizeof(initializer), "PyInit_%s", names[index]);
        if (length < 0 || (size_t)length >= sizeof(initializer)) {
            fail("initializer name too long");
        }
        PyObject *(*function)(void) = symbol(module, initializer);
        if (append(names[index], function) != 0) {
            fail("initializer registration");
        }
    }
    if (dlsym(RTLD_DEFAULT, "PyLong_FromLong") != NULL ||
        dlsym(RTLD_DEFAULT, "glue_python_lifecycle_ledger") != NULL) {
        fail("private runtime or dependency became globally visible");
    }
    void (*preconfig_init)(PyPreConfig *) = symbol(runtime, "PyPreConfig_InitIsolatedConfig");
    PyStatus (*preinitialize)(const PyPreConfig *) = symbol(runtime, "Py_PreInitialize");
    void (*config_init)(PyConfig *) = symbol(runtime, "PyConfig_InitIsolatedConfig");
    PyStatus (*config_bytes)(PyConfig *, wchar_t **, const char *) = symbol(runtime, "PyConfig_SetBytesString");
    PyStatus (*initialize)(const PyConfig *) = symbol(runtime, "Py_InitializeFromConfig");
    void (*clear)(PyConfig *) = symbol(runtime, "PyConfig_Clear");
    PyPreConfig preconfig;
    preconfig_init(&preconfig);
    preconfig.utf8_mode = 1;
    require_status(preinitialize(&preconfig), status_exception, status_is_exit);
    PyConfig config;
    config_init(&config);
    config.site_import = 0;
    config.write_bytecode = 0;
    require_status(config_bytes(&config, &config.home, argv[1]), status_exception, status_is_exit);
    require_status(config_bytes(&config, &config.executable, "/__glue_archive__/baseline"),
                   status_exception, status_is_exit);
    require_status(initialize(&config), status_exception, status_is_exit);
    clear(&config);
    FILE *app = fopen(argv[3], "rb");
    if (app == NULL || fseek(app, 0, SEEK_END) != 0) {
        fail("app source open");
    }
    long size = ftell(app);
    if (size <= 0 || size > 65536 || fseek(app, 0, SEEK_SET) != 0) {
        fail("app source size");
    }
    char *source = malloc((size_t)size + 1);
    if (source == NULL || fread(source, 1, (size_t)size, app) != (size_t)size || fclose(app) != 0) {
        fail("app source read");
    }
    source[size] = '\0';
    int (*run)(const char *, PyCompilerFlags *) = symbol(runtime, "PyRun_SimpleStringFlags");
    int result = run(source, NULL);
    free(source);
    int (*finalize)(void) = symbol(runtime, "Py_FinalizeEx");
    int finalization = finalize();
    /* The remaining observation uses only the pinned pure-C ledger. */
    if (result != 0 || finalization != 0 || ledger(GLUE_LIFECYCLE_CHECK, 0, 0) != 0 ||
        ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_ALLOCATIONS) != 5 ||
        ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_FREES) != 5 ||
        ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_OWNED) != 0 ||
        ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_RELEASES) != 5) {
        fprintf(stderr, "lifecycle baseline failed: run=%d finalize=%d allocated=%ld freed=%ld released=%ld owned=%ld errors=%ld\n",
                result, finalization,
                ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_ALLOCATIONS),
                ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_FREES),
                ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_RELEASES),
                ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_OWNED),
                ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_ERRORS));
        return 1;
    }
    fputs(GLUE_LIFECYCLE_FINALIZE_MARKER, stdout);
    return 0;
}
