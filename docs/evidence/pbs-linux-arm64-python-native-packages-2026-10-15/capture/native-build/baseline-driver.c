#define _GNU_SOURCE
#include <Python.h>
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "../python-native-lifecycle/ledger.h"

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


static const char *full_names[3] = {
    "glue_native_pkg.glue_native_lifecycle", "glue_native_pkg.glue_native_create_error",
    "glue_native_pkg.glue_native_lifecycle_exec_error"
};
static const char *leaf_names[3] = {
    "glue_native_lifecycle", "glue_native_create_error", "glue_native_lifecycle_exec_error"
};
static const char *public_imports[] = {
    "PyLong_FromLong", "PyModule_NewObject", "PyModuleDef_Init", "PyModule_GetState",
    "PyModule_AddIntConstant", "PyObject_GetAttrString", "PyList_New", "PyList_SetItem",
    "PyErr_SetString", "PyExc_RuntimeError", "Py_IncRef", "Py_DecRef", NULL
};
static void *native_handles[3];
static uintptr_t native_bases[3];
static char native_aliases[3][64];
static int native_fds[4];
static void *selected_runtime;
static uintptr_t selected_runtime_base;
static void *selected_dependency;
static uintptr_t selected_dependency_base;
static uintptr_t image_bases[32];
static size_t image_count;
static int image_checking;
static int image_mismatch;

static int observe_image(struct dl_phdr_info *info, size_t size, void *context)
{
    (void)size;
    (void)context;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    if (image_checking) {
        size_t index = 0;
        while (index < image_count && image_bases[index] != base) index++;
        if (index == image_count) image_mismatch = 1;
    } else {
        if (image_count == 32) fail("baseline image limit");
        image_bases[image_count++] = base;
    }
    return 0;
}

static void verify_native(void)
{
    image_checking = 1;
    image_mismatch = 0;
    dl_iterate_phdr(observe_image, NULL);
    if (image_mismatch || image_base(selected_runtime) != selected_runtime_base ||
        image_base(selected_dependency) != selected_dependency_base) fail("native closure changed");
    require_owner(selected_dependency, "glue_python_lifecycle_ledger", selected_dependency_base);
    if (dlsym(RTLD_DEFAULT, "glue_python_lifecycle_ledger") != NULL) fail("global ledger");
    for (size_t index = 0; public_imports[index] != NULL; index++) {
        require_owner(selected_runtime, public_imports[index], selected_runtime_base);
        if (dlsym(RTLD_DEFAULT, public_imports[index]) != NULL) fail("global Python API");
    }
    for (size_t index = 0; index < 3; index++) {
        if (image_base(native_handles[index]) != native_bases[index]) fail("native root changed");
        require_owner(native_handles[index], "glue_python_lifecycle_ledger", selected_dependency_base);
        for (size_t imported = 0; public_imports[imported] != NULL; imported++) {
            require_owner(native_handles[index], public_imports[imported], selected_runtime_base);
        }
        char initializer[256];
        int length = snprintf(initializer, sizeof(initializer), "PyInit_%s", leaf_names[index]);
        if (length < 0 || (size_t)length >= sizeof(initializer)) fail("initializer length");
        require_owner(native_handles[index], initializer, native_bases[index]);
        if (dlsym(RTLD_DEFAULT, initializer) != NULL) fail("global initializer");
    }
}

static const char *(*unicode_utf8)(PyObject *, Py_ssize_t *);
static PyObject *(*bytes_new)(const char *, Py_ssize_t);
static void (*set_error)(PyObject *, const char *);
static PyObject **runtime_error;

static PyObject *native_request(PyObject *module, PyObject *argument)
{
    (void)module;
    Py_ssize_t size;
    const char *text = unicode_utf8(argument, &size);
    if (text == NULL) return NULL;
    if (size < 1 || size > 256 || (size_t)size != strlen(text)) goto invalid;
    const char *tab = strchr(text, '\t');
    if (tab == NULL || strchr(tab + 1, '\t') != NULL) goto invalid;
    size_t index = 0;
    while (index < 3 && strcmp(tab + 1, full_names[index]) != 0) index++;
    if (index == 3) goto invalid;
    if (tab - text == 11 && strncmp(text, "native-path", 11) == 0) {
        return bytes_new(native_aliases[index], (Py_ssize_t)strlen(native_aliases[index]));
    }
    if (tab - text == 12 && strncmp(text, "native-check", 12) == 0) {
        verify_native();
        return bytes_new("checked", 7);
    }
invalid:
    set_error(*runtime_error, "undeclared native baseline request");
    return NULL;
}

static PyMethodDef callback_methods[] = {
    {"request", native_request, METH_O, NULL},
    {NULL, NULL, 0, NULL}
};

static void run_source(void *runtime, const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) fail("source open");
    long size = ftell(file);
    if (size <= 0 || size > 65536 || fseek(file, 0, SEEK_SET) != 0) fail("source size");
    char *source = malloc((size_t)size + 1);
    if (source == NULL || fread(source, 1, (size_t)size, file) != (size_t)size || fclose(file) != 0) fail("source read");
    source[size] = '\0';
    int (*run)(const char *, PyCompilerFlags *) = symbol(runtime, "PyRun_SimpleStringFlags");
    int status = run(source, NULL);
    free(source);
    if (status != 0) fail("baseline source failed");
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
    selected_runtime = runtime;
    selected_runtime_base = image_base(runtime);
    uintptr_t runtime_base = image_base(runtime);
    int (*status_exception)(PyStatus) = symbol(runtime, "PyStatus_Exception");
    int (*status_is_exit)(PyStatus) = symbol(runtime, "PyStatus_IsExit");
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/libglue_python_lifecycle.so", argv[2]);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        fail("dependency path too long");
    }
    native_fds[0] = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (native_fds[0] < 0) fail("dependency descriptor");
    char dependency_alias[64];
    snprintf(dependency_alias, sizeof(dependency_alias), "/proc/self/fd/%d", native_fds[0]);
    void *dependency = load(dependency_alias);
    selected_dependency = dependency;
    selected_dependency_base = image_base(dependency);
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
    for (size_t index = 0; index < 3; index++) {
        length = snprintf(path, sizeof(path), "%s/%s.so", argv[2], names[index]);
        if (length < 0 || (size_t)length >= sizeof(path)) fail("module path too long");
        native_fds[index + 1] = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (native_fds[index + 1] < 0) fail("native descriptor");
        snprintf(native_aliases[index], sizeof(native_aliases[index]), "/proc/self/fd/%d", native_fds[index + 1]);
        void *module = load(native_aliases[index]);
        native_handles[index] = module;
        native_bases[index] = image_base(module);
        require_owner(module, "glue_python_lifecycle_ledger", dependency_base);
        for (size_t imported = 0; imports[imported] != NULL; imported++) {
            require_owner(module, imports[imported], runtime_base);
        }
    }
    dl_iterate_phdr(observe_image, NULL);
    verify_native();
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
    unicode_utf8 = symbol(runtime, "PyUnicode_AsUTF8AndSize");
    bytes_new = symbol(runtime, "PyBytes_FromStringAndSize");
    set_error = symbol(runtime, "PyErr_SetString");
    runtime_error = symbol(runtime, "PyExc_RuntimeError");
    PyObject *(*add_module)(const char *) = symbol(runtime, "PyImport_AddModule");
    int (*add_functions)(PyObject *, PyMethodDef *) = symbol(runtime, "PyModule_AddFunctions");
    PyObject *callback_module = add_module("_glue_archive");
    if (callback_module == NULL || add_functions(callback_module, callback_methods) != 0) fail("native callback module");
    const char *slash = strrchr(argv[3], '/');
    if (slash == NULL || strchr(argv[3], '\'') != NULL || strchr(argv[3], '\\') != NULL || strchr(argv[3], '\n') != NULL) fail("app pathname");
    char directory[4096];
    size_t directory_size = (size_t)(slash - argv[3]);
    if (directory_size >= sizeof(directory)) fail("app directory length");
    memcpy(directory, argv[3], directory_size);
    directory[directory_size] = '\0';
    char setup[16384];
    length = snprintf(setup, sizeof(setup),
        "import sys\n__glue_native_baseline__ = True\n__glue_native_parent_path__ = '%s/input/app/python/glue_native_pkg'\nsys.path.insert(0, '%s/input/app/python')\n",
        directory, directory);
    if (length < 0 || (size_t)length >= sizeof(setup)) fail("setup length");
    int (*run)(const char *, PyCompilerFlags *) = symbol(runtime, "PyRun_SimpleStringFlags");
    if (run(setup, NULL) != 0) fail("baseline setup");
    length = snprintf(path, sizeof(path), "%s/bootstrap.py", directory);
    if (length < 0 || (size_t)length >= sizeof(path)) fail("bootstrap path");
    run_source(runtime, path);
    run_source(runtime, argv[3]);
    int result = 0;
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
