/* This small ABI boundary owns the exact stock CPython header layouts and all
 * Python references. The Rust caller supplies reviewed dynamic addresses;
 * there is no direct libpython link or callback through Rust frames. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "bridge.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if PY_VERSION_HEX != 0x030d10f0
#error "The bootstrap boundary requires the pinned CPython 3.13.16 headers"
#endif
#if defined(Py_GIL_DISABLED) && Py_GIL_DISABLED
#error "The bootstrap boundary requires the conventional GIL ABI"
#endif
#ifdef Py_DEBUG
#error "The bootstrap boundary requires the non-debug ABI"
#endif

_Static_assert(sizeof(void *) == 8 && sizeof(int) == 4,
               "The bootstrap boundary requires the selected 64-bit ABI");
_Static_assert(sizeof(GluePythonApi) == 168 &&
                   offsetof(GluePythonApi, Py_GetVersion) == 8 &&
                   offsetof(GluePythonApi, PyImport_FrozenModules) == 160 &&
                   sizeof(GlueFrozenRecord) == 24 &&
                   sizeof(GluePythonResult) == 16,
               "Python bridge ABI revision 1 must match the Rust layout");
_Static_assert(sizeof(struct _frozen) == 24 &&
                   offsetof(struct _frozen, is_package) == 20,
               "The pinned public frozen descriptor has four fields");

#define MAX_RECORDS 512u
#define MAX_NAME 255u
#define MAX_CODE (4u * 1024u * 1024u)
#define MAX_TOTAL_CODE (64u * 1024u * 1024u)
#define MAX_APP (256u * 1024u)
#define MAX_ERROR (16u * 1024u)
#define CALL(api, name) ((__typeof__(&name))((api)->name))

static atomic_int attempted = 0;

typedef struct FrozenOwner {
    struct _frozen *table;
    size_t original_count;
    size_t custom_count;
} FrozenOwner;

static size_t bounded_length(const char *text, size_t maximum) {
    size_t length = 0;
    if (text != NULL) {
        while (length < maximum && text[length] != '\0') {
            length++;
        }
    }
    return length;
}

static void copy_error(GluePythonResult *result, const char *text, size_t length) {
    if (result == NULL || result->error != NULL) {
        return;
    }
    if (length > MAX_ERROR) {
        length = MAX_ERROR;
    }
    result->error = malloc(length + 1);
    if (result->error != NULL) {
        memcpy(result->error, text, length);
        result->error[length] = '\0';
        result->error_len = length;
    }
}

static int fail(GluePythonResult *result, const char *message) {
    copy_error(result, message, bounded_length(message, MAX_ERROR));
    return 1;
}

void glue_python_result_free(GluePythonResult *result) {
    if (result != NULL) {
        free(result->error);
        result->error = NULL;
        result->error_len = 0;
    }
}

static int valid_api(const GluePythonApi *api) {
    return api != NULL && api->abi_revision == 1 && api->reserved == 0 &&
           api->Py_GetVersion && api->Py_IsInitialized &&
           api->PyPreConfig_InitIsolatedConfig && api->Py_PreInitialize &&
           api->PyConfig_InitIsolatedConfig && api->PyConfig_SetString &&
           api->PyConfig_Clear && api->Py_InitializeFromConfig &&
           api->PyStatus_Exception && api->PyStatus_IsExit &&
           api->PyImport_AddModuleRef && api->PyModule_GetDict &&
           api->PyRun_StringFlags && api->Py_DecRef &&
           api->PyErr_GetRaisedException && api->PyObject_Str &&
           api->PyUnicode_AsUTF8AndSize && api->PyErr_Clear &&
           api->Py_FinalizeEx && api->PyImport_FrozenModules;
}

static int status_error(const GluePythonApi *api, PyStatus status,
                        GluePythonResult *result) {
    if (!CALL(api, PyStatus_Exception)(status)) {
        return 0;
    }
    if (CALL(api, PyStatus_IsExit)(status)) {
        char message[96];
        snprintf(message, sizeof(message), "Python initialization requested exit %d",
                 status.exitcode);
        return fail(result, message);
    }
    return fail(result, status.err_msg != NULL ? status.err_msg
                                              : "Python initialization failed");
}

static void python_error(const GluePythonApi *api, GluePythonResult *result) {
    PyObject *exception = CALL(api, PyErr_GetRaisedException)();
    PyObject *message = exception != NULL ? CALL(api, PyObject_Str)(exception) : NULL;
    if (message != NULL) {
        Py_ssize_t length = 0;
        const char *text = CALL(api, PyUnicode_AsUTF8AndSize)(message, &length);
        if (text != NULL && length >= 0) {
            copy_error(result, text, (size_t)length);
        }
        CALL(api, Py_DecRef)(message);
    }
    if (exception != NULL) {
        CALL(api, Py_DecRef)(exception);
    }
    CALL(api, PyErr_Clear)();
    if (result->error == NULL) {
        fail(result, "Python application failed; exception text unavailable");
    }
}

static int module_name(const char *name) {
    size_t length = bounded_length(name, MAX_NAME + 1);
    if (length == 0 || length > MAX_NAME) {
        return 0;
    }
    int initial = 1;
    for (size_t index = 0; index < length; index++) {
        unsigned char character = (unsigned char)name[index];
        if (character == '.') {
            if (initial) {
                return 0;
            }
            initial = 1;
        } else if ((character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') || character == '_' ||
                   (!initial && character >= '0' && character <= '9')) {
            initial = 0;
        } else {
            return 0;
        }
    }
    return !initial;
}

static void free_frozen(FrozenOwner *owner) {
    if (owner->table != NULL) {
        for (size_t index = 0; index < owner->custom_count; index++) {
            struct _frozen *record = &owner->table[owner->original_count + index];
            free((void *)record->name);
            free((void *)record->code);
        }
        free(owner->table);
        owner->table = NULL;
    }
}

static int make_frozen(const struct _frozen *original,
                       const GlueFrozenRecord *records, size_t count,
                       FrozenOwner *owner, GluePythonResult *result) {
    if (records == NULL || count == 0 || count > MAX_RECORDS) {
        return fail(result, "invalid frozen record count");
    }
    size_t original_count = 0;
    if (original != NULL) {
        while (original_count <= MAX_RECORDS && original[original_count].name != NULL) {
            original_count++;
        }
        if (original_count > MAX_RECORDS) {
            return fail(result, "existing public frozen table exceeds the bound");
        }
    }
    size_t total = 0;
    for (size_t index = 0; index < count; index++) {
        const GlueFrozenRecord *record = &records[index];
        if (!module_name(record->name) || record->code == NULL || record->size <= 0 ||
            (uint32_t)record->size > MAX_CODE ||
            (record->is_package != 0 && record->is_package != 1)) {
            return fail(result, "invalid frozen record");
        }
        total += (size_t)record->size;
        if (total > MAX_TOTAL_CODE) {
            return fail(result, "frozen code exceeds the total bound");
        }
        for (size_t earlier = 0; earlier < index; earlier++) {
            if (strcmp(record->name, records[earlier].name) == 0) {
                return fail(result, "duplicate frozen record name");
            }
        }
        for (size_t earlier = 0; earlier < original_count; earlier++) {
            if (strcmp(record->name, original[earlier].name) == 0) {
                return fail(result, "frozen record conflicts with the existing public table");
            }
        }
    }
    owner->table = calloc(original_count + count + 1, sizeof(*owner->table));
    if (owner->table == NULL) {
        return fail(result, "cannot allocate frozen table");
    }
    owner->original_count = original_count;
    owner->custom_count = count;
    if (original_count != 0) {
        memcpy(owner->table, original, original_count * sizeof(*original));
    }
    for (size_t index = 0; index < count; index++) {
        const GlueFrozenRecord *source = &records[index];
        struct _frozen *destination = &owner->table[original_count + index];
        size_t length = strlen(source->name);
        char *name = malloc(length + 1);
        unsigned char *code = malloc((size_t)source->size);
        if (name == NULL || code == NULL) {
            free(name);
            free(code);
            free_frozen(owner);
            return fail(result, "cannot copy frozen record");
        }
        memcpy(name, source->name, length + 1);
        memcpy(code, source->code, (size_t)source->size);
        destination->name = name;
        destination->code = code;
        destination->size = source->size;
        destination->is_package = source->is_package;
    }
    return 0;
}

int glue_python_run(const GluePythonApi *api, const GlueFrozenRecord *records,
                    size_t count, const unsigned char *app_source,
                    size_t app_len, GluePythonResult *result) {
    if (result == NULL) {
        return 1;
    }
    result->error = NULL;
    result->error_len = 0;
    if (!valid_api(api)) {
        return fail(result, "invalid Python boundary API table");
    }
    if (app_source == NULL || app_len == 0 || app_len > MAX_APP ||
        memchr(app_source, '\0', app_len) != NULL) {
        return fail(result, "invalid Python application source");
    }
    const char *version = CALL(api, Py_GetVersion)();
    if (version == NULL || strncmp(version, "3.13.16", 7) != 0 ||
        (version[7] != ' ' && version[7] != '\0')) {
        return fail(result, "Python boundary requires runtime version 3.13.16");
    }
    if (CALL(api, Py_IsInitialized)()) {
        return fail(result, "Python boundary requires an uninitialized runtime");
    }
    if (atomic_exchange(&attempted, 1) != 0) {
        return fail(result, "Python boundary permits one attempt per process");
    }
    const struct _frozen **frozen_address = api->PyImport_FrozenModules;
    const struct _frozen *original = *frozen_address;
    FrozenOwner owner = {0};
    if (make_frozen(original, records, count, &owner, result)) {
        return 1;
    }
    char *source = malloc(app_len + 1);
    if (source == NULL) {
        free_frozen(&owner);
        return fail(result, "cannot allocate Python application source");
    }
    memcpy(source, app_source, app_len);
    source[app_len] = '\0';
    *frozen_address = owner.table;

    int failed = 0;
    int config_ready = 0;
    int initialization_attempted = 0;
    int initialized = 0;
    PyConfig config;
    PyPreConfig preconfig;
    CALL(api, PyPreConfig_InitIsolatedConfig)(&preconfig);
    preconfig.utf8_mode = 1;
    preconfig.configure_locale = 0;
    preconfig.use_environment = 0;
    preconfig.parse_argv = 0;
    if (status_error(api, CALL(api, Py_PreInitialize)(&preconfig), result)) {
        failed = 1;
        goto cleanup;
    }

    CALL(api, PyConfig_InitIsolatedConfig)(&config);
    config_ready = 1;
    config.isolated = 1;
    config.use_environment = 0;
    config.parse_argv = 0;
    config.site_import = 0;
    config.user_site_directory = 0;
    config.write_bytecode = 0;
    config.install_signal_handlers = 0;
    config.configure_c_stdio = 0;
    config.safe_path = 1;
    config.use_frozen_modules = 1;
    config.module_search_paths_set = 1;
    config.pathconfig_warnings = 0;
    config.faulthandler = 0;
    config.tracemalloc = 0;
    config.dev_mode = 0;
    config.verbose = 0;

#define SET(field, value)                                                        \
    do {                                                                         \
        if (status_error(api, CALL(api, PyConfig_SetString)(                      \
                                  &config, &config.field, value), result)) {      \
            failed = 1;                                                          \
            goto cleanup;                                                        \
        }                                                                        \
    } while (0)
    SET(program_name, L"glue-python-bootstrap");
    SET(home, L"/__glue_archive__/python");
    SET(prefix, L"/__glue_archive__/python");
    SET(base_prefix, L"/__glue_archive__/python");
    SET(exec_prefix, L"/__glue_archive__/python");
    SET(base_exec_prefix, L"/__glue_archive__/python");
    SET(stdlib_dir, L"/__glue_archive__/python/stdlib");
    SET(executable, L"/__glue_archive__/launcher");
    SET(base_executable, L"/__glue_archive__/launcher");
    SET(filesystem_encoding, L"utf-8");
    SET(filesystem_errors, L"surrogateescape");
    SET(stdio_encoding, L"utf-8");
    SET(stdio_errors, L"strict");
#undef SET

    initialization_attempted = 1;
    if (status_error(api, CALL(api, Py_InitializeFromConfig)(&config), result)) {
        failed = 1;
        goto cleanup;
    }
    initialized = 1;
    CALL(api, PyConfig_Clear)(&config);
    config_ready = 0;
    PyObject *main_module = CALL(api, PyImport_AddModuleRef)("__main__");
    if (main_module == NULL) {
        python_error(api, result);
        failed = 1;
        goto cleanup;
    }
    PyObject *globals = CALL(api, PyModule_GetDict)(main_module);
    PyObject *value = globals != NULL
                          ? CALL(api, PyRun_StringFlags)(source, Py_file_input,
                                                        globals, globals, NULL)
                          : NULL;
    if (value == NULL) {
        python_error(api, result);
        failed = 1;
    } else {
        CALL(api, Py_DecRef)(value);
    }
    CALL(api, Py_DecRef)(main_module);

cleanup:
    if (config_ready) {
        CALL(api, PyConfig_Clear)(&config);
    }
    if (initialized || CALL(api, Py_IsInitialized)()) {
        if (CALL(api, Py_FinalizeEx)() < 0) {
            failed = fail(result, "Python finalization failed");
        }
    }
    int still_initialized = CALL(api, Py_IsInitialized)();
    if (!still_initialized) {
        *frozen_address = original;
    }
    /* A failed initialization can leave a partially initialized runtime even
     * when Py_IsInitialized() is false. Keep our C-owned bytes alive until
     * process exit in that case; this boundary never retries initialization. */
    if (!initialization_attempted || (initialized && !still_initialized)) {
        free_frozen(&owner);
    }
    free(source);
    return failed;
}

int glue_python_boundary_test_ownership(void) {
    char name[] = "encodings";
    unsigned char code[] = {1, 2, 3};
    const struct _frozen original[] = {
        {"original", code, 3, 0}, {NULL, NULL, 0, 0}
    };
    GlueFrozenRecord record = {name, code, 3, 1};
    FrozenOwner owner = {0};
    GluePythonResult result = {0};
    int failed = 1;
    if (make_frozen(original, &record, 1, &owner, &result)) {
        goto done;
    }
    if (owner.table[0].name != original[0].name ||
        owner.table[0].code != original[0].code ||
        owner.table[1].name == record.name ||
        owner.table[1].code == record.code ||
        owner.table[1].is_package != 1 || owner.table[2].name != NULL) {
        goto done;
    }
    name[0] = 'x';
    code[0] = 9;
    if (strcmp(owner.table[1].name, "encodings") != 0 ||
        owner.table[1].code[0] != 1 || owner.table[0].code[0] != 9) {
        goto done;
    }
    free_frozen(&owner);
    if (owner.table != NULL) {
        goto done;
    }
    record.is_package = 2;
    if (!make_frozen(original, &record, 1, &owner, &result) ||
        owner.table != NULL || result.error == NULL || result.error_len == 0) {
        goto done;
    }
    glue_python_result_free(&result);
    glue_python_result_free(&result);
    if (result.error != NULL || result.error_len != 0) {
        goto done;
    }
    char long_message[MAX_ERROR + 32];
    memset(long_message, 'x', sizeof(long_message));
    copy_error(&result, long_message, sizeof(long_message));
    if (result.error == NULL || result.error_len != MAX_ERROR ||
        result.error[MAX_ERROR] != '\0') {
        goto done;
    }
    failed = 0;
done:
    free_frozen(&owner);
    glue_python_result_free(&result);
    return failed;
}
