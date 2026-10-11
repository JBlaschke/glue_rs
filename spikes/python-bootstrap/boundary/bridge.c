/* This small ABI boundary owns the exact stock CPython header layouts and all
 * Python references. The Rust caller supplies reviewed dynamic addresses;
 * there is no direct libpython link. The bounded resource callback transfers
 * bytes only; C owns every Python object and publishes callback errors. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "bridge.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

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
_Static_assert(sizeof(GluePythonApi) == 240 &&
                   offsetof(GluePythonApi, Py_GetVersion) == 8 &&
                   offsetof(GluePythonApi, PyImport_FrozenModules) == 160 &&
                   offsetof(GluePythonApi, PyWideStringList_Append) == 168 &&
                   offsetof(GluePythonApi, PyModule_New) == 176 &&
                   offsetof(GluePythonApi, PyCFunction_NewEx) == 184 &&
                   offsetof(GluePythonApi, PyImport_GetModuleDict) == 192 &&
                   offsetof(GluePythonApi, PyDict_SetItemString) == 200 &&
                   offsetof(GluePythonApi, PyBytes_FromStringAndSize) == 208 &&
                   offsetof(GluePythonApi, PyErr_SetString) == 216 &&
                   offsetof(GluePythonApi, PyExc_RuntimeError) == 224 &&
                   offsetof(GluePythonApi, PyImport_AppendInittab) == 232 &&
                   sizeof(GlueFrozenRecord) == 24 &&
                   sizeof(GlueExtensionRecord) == 16 &&
                   offsetof(GlueExtensionRecord, initializer) == 8 &&
                   sizeof(GluePythonResult) == 16 &&
                   sizeof(GlueResourceReply) == 16 &&
                   offsetof(GlueResourceReply, len) == 8,
               "Python bridge ABI revision 4 must match the Rust layout");
_Static_assert(sizeof(PyObject *(*)(void)) == sizeof(void *),
               "The selected ABI has pointer-width native initializers");
_Static_assert(sizeof(struct _frozen) == 24 &&
                   offsetof(struct _frozen, is_package) == 20,
               "The pinned public frozen descriptor has four fields");

#define MAX_RECORDS 512u
#define MAX_NAME 255u
#define MAX_CODE (4u * 1024u * 1024u)
#define MAX_TOTAL_CODE (64u * 1024u * 1024u)
#define MAX_APP (256u * 1024u)
#define MAX_ERROR (16u * 1024u)
#define MAX_HOST_PATH 4096u
#define MAX_REQUEST 4096u
#define MAX_BOOTSTRAP (256u * 1024u)
#define MAX_EXTENSIONS 8u
#define CALL(api, name) ((__typeof__(&name))((api)->name))

static atomic_int attempted = 0;

typedef struct FrozenOwner {
    struct _frozen *table;
    size_t original_count;
    size_t custom_count;
} FrozenOwner;

typedef struct HostPaths {
    wchar_t *prefix;
    wchar_t *stdlib;
} HostPaths;

typedef struct ExtensionOwner {
    GlueExtensionRecord records[MAX_EXTENSIONS];
    size_t count;
    int published;
} ExtensionOwner;

typedef struct ArchiveBridge {
    GlueResourceRequest request;
    GlueResourceRelease release;
    void *context;
} ArchiveBridge;

typedef struct OwnedReply {
    unsigned char *data;
    size_t len;
    int status;
    const char *failure;
} OwnedReply;

/* Method definitions outlive their Python wrappers. The copied address table
 * also remains valid because Rust pins the selected runtime until process
 * exit. The borrowed context itself is accessible only on the caller thread
 * and remains active through Python finalization, then is cleared. */
static GluePythonApi callback_api;
static _Thread_local const ArchiveBridge *active_archive;
static void python_error(const GluePythonApi *api, GluePythonResult *result);

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
    return api != NULL && api->abi_revision == 4 && api->reserved == 0 &&
           api->Py_GetVersion && api->Py_IsInitialized &&
           api->PyPreConfig_InitIsolatedConfig && api->Py_PreInitialize &&
           api->PyConfig_InitIsolatedConfig && api->PyConfig_SetString &&
           api->PyConfig_Clear && api->Py_InitializeFromConfig &&
           api->PyStatus_Exception && api->PyStatus_IsExit &&
           api->PyImport_AddModuleRef && api->PyModule_GetDict &&
           api->PyRun_StringFlags && api->Py_DecRef &&
           api->PyErr_GetRaisedException && api->PyObject_Str &&
           api->PyUnicode_AsUTF8AndSize && api->PyErr_Clear &&
           api->Py_FinalizeEx && api->PyImport_FrozenModules &&
           api->PyWideStringList_Append && api->PyModule_New &&
           api->PyCFunction_NewEx && api->PyImport_GetModuleDict &&
           api->PyDict_SetItemString && api->PyBytes_FromStringAndSize &&
           api->PyErr_SetString && api->PyExc_RuntimeError &&
           api->PyImport_AppendInittab;
}

static int valid_archive(const ArchiveBridge *bridge) {
    return bridge != NULL && bridge->request != NULL &&
           bridge->release != NULL && bridge->context != NULL;
}

static int valid_source(const unsigned char *source, size_t length,
                         size_t maximum) {
    return source != NULL && length != 0 && length <= maximum &&
           memchr(source, '\0', length) == NULL;
}

/* Pure C UTF-8 validation avoids publishing an invalid byte reply through a
 * Python API. It rejects surrogates, overlong forms and out-of-range values. */
static int valid_utf8(const unsigned char *text, size_t length) {
    for (size_t index = 0; index < length;) {
        unsigned char first = text[index++];
        if (first < 0x80) {
            continue;
        }
        size_t extra;
        uint32_t value;
        uint32_t minimum;
        if (first >= 0xc2 && first <= 0xdf) {
            extra = 1;
            value = first & 0x1f;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            extra = 2;
            value = first & 0x0f;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            extra = 3;
            value = first & 0x07;
            minimum = 0x10000;
        } else {
            return 0;
        }
        if (extra > length - index) {
            return 0;
        }
        for (size_t continuation = 0; continuation < extra; continuation++) {
            unsigned char character = text[index++];
            if ((character & 0xc0) != 0x80) {
                return 0;
            }
            value = (value << 6) | (character & 0x3f);
        }
        if (value < minimum || value > 0x10ffff ||
            (value >= 0xd800 && value <= 0xdfff)) {
            return 0;
        }
    }
    return 1;
}

/* No Python API or Python allocator is used until the Rust-owned reply has
 * been released. Protocol rejection still releases the transferred buffer. */
static void request_owned(const ArchiveBridge *bridge,
                          const unsigned char *request, size_t request_len,
                          OwnedReply *owned) {
    GlueResourceReply reply = {0};
    owned->status = bridge->request(bridge->context, request, request_len, &reply);
    if (owned->status != 0 && owned->status != 1) {
        owned->failure = "archive resource callback returned an invalid status";
    } else if (reply.len > (owned->status == 0 ? MAX_CODE : MAX_ERROR) ||
               (reply.len != 0 && reply.data == NULL)) {
        owned->failure = "archive resource callback returned an invalid buffer";
    } else if (owned->status == 1 && reply.len != 0 &&
               (memchr(reply.data, '\0', reply.len) != NULL ||
                !valid_utf8(reply.data, reply.len))) {
        owned->failure = "archive resource callback returned an invalid error";
    } else {
        owned->data = malloc(reply.len + 1);
        if (owned->data == NULL) {
            owned->failure = "cannot copy archive resource callback reply";
        } else {
            if (reply.len != 0) {
                memcpy(owned->data, reply.data, reply.len);
            }
            owned->data[reply.len] = '\0';
            owned->len = reply.len;
        }
    }
    bridge->release(bridge->context, reply.data, reply.len);
}

static PyObject *archive_error(const char *message) {
    PyObject *exception = *(PyObject **)callback_api.PyExc_RuntimeError;
    CALL(&callback_api, PyErr_SetString)(exception, message);
    return NULL;
}

static PyObject *archive_request(PyObject *self, PyObject *argument) {
    (void)self;
    if (active_archive == NULL) {
        return archive_error("archive resource callback is outside its caller thread or lifetime");
    }
    Py_ssize_t length = 0;
    const char *text = CALL(&callback_api, PyUnicode_AsUTF8AndSize)(argument, &length);
    if (text == NULL) {
        return NULL;
    }
    if (length < 0 || (size_t)length > MAX_REQUEST) {
        return archive_error("archive resource request exceeds the byte bound");
    }
    OwnedReply reply = {0};
    request_owned(active_archive, (const unsigned char *)text, (size_t)length, &reply);
    PyObject *value = NULL;
    if (reply.failure != NULL) {
        archive_error(reply.failure);
    } else if (reply.status == 1) {
        archive_error(reply.len != 0 ? (const char *)reply.data
                                    : "archive resource callback failed");
    } else {
        value = CALL(&callback_api, PyBytes_FromStringAndSize)(
            (const char *)reply.data, (Py_ssize_t)reply.len);
    }
    free(reply.data);
    return value;
}

static PyMethodDef archive_method = {
    "request", archive_request, METH_O,
    "Read bounded archive resource bytes through the retained archive view."
};

static int install_archive(const GluePythonApi *api, GluePythonResult *result) {
    PyObject *module = CALL(api, PyModule_New)("_glue_archive");
    PyObject *method = module != NULL
                           ? CALL(api, PyCFunction_NewEx)(&archive_method, NULL, NULL)
                           : NULL;
    PyObject *dictionary = module != NULL ? CALL(api, PyModule_GetDict)(module) : NULL;
    PyObject *modules = method != NULL ? CALL(api, PyImport_GetModuleDict)() : NULL;
    int failed = dictionary == NULL || method == NULL || modules == NULL ||
                 CALL(api, PyDict_SetItemString)(dictionary, "request", method) < 0 ||
                 CALL(api, PyDict_SetItemString)(modules, "_glue_archive", module) < 0;
    if (method != NULL) {
        CALL(api, Py_DecRef)(method);
    }
    if (module != NULL) {
        CALL(api, Py_DecRef)(module);
    }
    if (failed) {
        python_error(api, result);
    }
    return failed;
}

/* ASCII is a deliberately narrow fixture boundary, independent of locale or
 * Python's allocator/preinitialization state. Spaces are accepted so the
 * installed fixture can exercise explicit paths containing spaces. */
static int host_path(const char *path, size_t *length) {
    *length = bounded_length(path, MAX_HOST_PATH + 1);
    if (*length <= 1 || *length > MAX_HOST_PATH || path[0] != '/') {
        return 0;
    }
    size_t component = 1;
    for (size_t index = 1; index <= *length; index++) {
        unsigned char character = (unsigned char)path[index];
        if (character == '/' || character == '\0') {
            size_t count = index - component;
            if (count == 0 ||
                (count == 1 && path[component] == '.') ||
                (count == 2 && path[component] == '.' && path[component + 1] == '.')) {
                return 0;
            }
            component = index + 1;
        } else if (character < 0x20 || character > 0x7e || character == '\\') {
            return 0;
        }
    }
    return 1;
}

static void free_host_paths(HostPaths *paths) {
    free(paths->prefix);
    free(paths->stdlib);
    paths->prefix = NULL;
    paths->stdlib = NULL;
}

static int make_host_paths(const char *prefix, const char *stdlib,
                           HostPaths *paths, GluePythonResult *result) {
    size_t prefix_length = 0;
    size_t stdlib_length = 0;
    if (!host_path(prefix, &prefix_length) || !host_path(stdlib, &stdlib_length) ||
        stdlib_length <= prefix_length ||
        memcmp(prefix, stdlib, prefix_length) != 0 || stdlib[prefix_length] != '/') {
        return fail(result, "invalid explicit host Python paths");
    }
    paths->prefix = malloc((prefix_length + 1) * sizeof(*paths->prefix));
    paths->stdlib = malloc((stdlib_length + 1) * sizeof(*paths->stdlib));
    if (paths->prefix == NULL || paths->stdlib == NULL) {
        free_host_paths(paths);
        return fail(result, "cannot copy explicit host Python paths");
    }
    for (size_t index = 0; index <= prefix_length; index++) {
        paths->prefix[index] = (wchar_t)(unsigned char)prefix[index];
    }
    for (size_t index = 0; index <= stdlib_length; index++) {
        paths->stdlib[index] = (wchar_t)(unsigned char)stdlib[index];
    }
    return 0;
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

static int valid_extensions(const GlueExtensionRecord *records, size_t count) {
    if (count > MAX_EXTENSIONS || (records == NULL) != (count == 0)) {
        return 0;
    }
    static const char prefix[] = "glue_native_";
    for (size_t index = 0; index < count; index++) {
        const GlueExtensionRecord *record = &records[index];
        if (record->initializer == NULL || !module_name(record->name) ||
            strlen(record->name) <= sizeof(prefix) - 1 ||
            strncmp(record->name, prefix, sizeof(prefix) - 1) != 0 ||
            strchr(record->name, '.') != NULL) {
            return 0;
        }
        for (size_t earlier = 0; earlier < index; earlier++) {
            if (strcmp(record->name, records[earlier].name) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

static void free_extensions(ExtensionOwner *owner) {
    /* AppendInittab retains the name pointers. Registration can succeed for
     * some records before another fails, so all names are deliberately pinned
     * from the first append attempt through process exit. */
    if (!owner->published) {
        for (size_t index = 0; index < owner->count; index++) {
            free((void *)owner->records[index].name);
        }
        memset(owner, 0, sizeof(*owner));
    }
}

static int make_extensions(const GlueExtensionRecord *records, size_t count,
                           ExtensionOwner *owner, GluePythonResult *result) {
    if (!valid_extensions(records, count)) {
        return fail(result, "invalid Python extension registrations");
    }
    for (size_t index = 0; index < count; index++) {
        size_t length = strlen(records[index].name);
        char *name = malloc(length + 1);
        if (name == NULL) {
            free_extensions(owner);
            return fail(result, "cannot copy Python extension names");
        }
        memcpy(name, records[index].name, length + 1);
        owner->records[index].name = name;
        owner->records[index].initializer = records[index].initializer;
        owner->count++;
    }
    return 0;
}

static int register_extensions(const GluePythonApi *api, ExtensionOwner *owner,
                               GluePythonResult *result) {
    if (owner->count != 0) {
        owner->published = 1;
    }
    for (size_t index = 0; index < owner->count; index++) {
        const GlueExtensionRecord *record = &owner->records[index];
        /* Rust validates address ownership and pins the native code. Only C
         * supplies the selected public API with the Python initializer type;
         * stock import machinery invokes it after interpreter initialization. */
        PyObject *(*initializer)(void) =
            (PyObject *(*)(void))record->initializer;
        if (CALL(api, PyImport_AppendInittab)(record->name, initializer) != 0) {
            return fail(result, "cannot register Python extension initializer");
        }
    }
    return 0;
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

static int run_python(const GluePythonApi *api, const GlueFrozenRecord *records,
                       size_t count, const HostPaths *host,
                       const ArchiveBridge *archive,
                       const GlueExtensionRecord *extensions,
                       size_t extension_count,
                       const unsigned char *bootstrap_source,
                       size_t bootstrap_len,
                       const unsigned char *app_source, size_t app_len,
                       GluePythonResult *result) {
    if (result == NULL) {
        return 1;
    }
    result->error = NULL;
    result->error_len = 0;
    if (!valid_api(api)) {
        return fail(result, "invalid Python boundary API table");
    }
    if (!valid_source(app_source, app_len, MAX_APP)) {
        return fail(result, "invalid Python application source");
    }
    if (!valid_extensions(extensions, extension_count)) {
        return fail(result, "invalid Python extension registrations");
    }
    if (archive != NULL &&
        (!valid_archive(archive) ||
         !valid_source(bootstrap_source, bootstrap_len, MAX_BOOTSTRAP) ||
         !valid_utf8(bootstrap_source, bootstrap_len))) {
        return fail(result, "invalid Python archive importer inputs");
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
    if (host != NULL) {
        if (original != NULL && original[0].name != NULL) {
            return fail(result, "host Python requires an empty public frozen table");
        }
    } else {
        if (make_frozen(original, records, count, &owner, result)) {
            return 1;
        }
    }
    ExtensionOwner native = {0};
    if (make_extensions(extensions, extension_count, &native, result)) {
        free_frozen(&owner);
        return 1;
    }
    for (size_t index = 0; index < native.count; index++) {
        for (size_t frozen = 0;
             frozen < owner.original_count + owner.custom_count; frozen++) {
            if (strcmp(native.records[index].name, owner.table[frozen].name) == 0) {
                free_extensions(&native);
                free_frozen(&owner);
                return fail(result, "Python extension conflicts with a frozen module");
            }
        }
    }
    char *source = malloc(app_len + 1);
    if (source == NULL) {
        free_extensions(&native);
        free_frozen(&owner);
        return fail(result, "cannot allocate Python application source");
    }
    memcpy(source, app_source, app_len);
    source[app_len] = '\0';
    char *bootstrap = NULL;
    if (archive != NULL) {
        bootstrap = malloc(bootstrap_len + 1);
        if (bootstrap == NULL) {
            free_extensions(&native);
            free(source);
            free_frozen(&owner);
            return fail(result, "cannot allocate Python archive importer source");
        }
        memcpy(bootstrap, bootstrap_source, bootstrap_len);
        bootstrap[bootstrap_len] = '\0';
    }
    if (host == NULL) {
        *frozen_address = owner.table;
    }

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
    SET(home, host != NULL ? host->prefix : L"/__glue_archive__/python");
    SET(prefix, host != NULL ? host->prefix : L"/__glue_archive__/python");
    SET(base_prefix, host != NULL ? host->prefix : L"/__glue_archive__/python");
    SET(exec_prefix, host != NULL ? host->prefix : L"/__glue_archive__/python");
    SET(base_exec_prefix, host != NULL ? host->prefix : L"/__glue_archive__/python");
    SET(stdlib_dir, host != NULL ? host->stdlib : L"/__glue_archive__/python/stdlib");
    SET(executable, L"/__glue_archive__/launcher");
    SET(base_executable, L"/__glue_archive__/launcher");
    SET(filesystem_encoding, L"utf-8");
    SET(filesystem_errors, L"surrogateescape");
    SET(stdio_encoding, L"utf-8");
    SET(stdio_errors, L"strict");
#undef SET

    if (host != NULL) {
        if (config.module_search_paths.length != 0 ||
            config.module_search_paths.items != NULL) {
            failed = fail(result, "host Python requires an initially empty search path");
            goto cleanup;
        }
        if (status_error(api, CALL(api, PyWideStringList_Append)(
                                  &config.module_search_paths, config.stdlib_dir), result)) {
            failed = 1;
            goto cleanup;
        }
    }

    if (register_extensions(api, &native, result)) {
        failed = 1;
        goto cleanup;
    }
    initialization_attempted = 1;
    if (status_error(api, CALL(api, Py_InitializeFromConfig)(&config), result)) {
        failed = 1;
        goto cleanup;
    }
    initialized = 1;
    CALL(api, PyConfig_Clear)(&config);
    config_ready = 0;
    if (archive != NULL) {
        callback_api = *api;
        active_archive = archive;
        if (*(PyObject **)api->PyExc_RuntimeError == NULL) {
            failed = fail(result, "Python archive importer requires RuntimeError");
            goto cleanup;
        }
        if (install_archive(api, result)) {
            failed = 1;
            goto cleanup;
        }
        PyObject *bootstrap_module = CALL(api, PyImport_AddModuleRef)(
            "_glue_archive_bootstrap");
        if (bootstrap_module == NULL) {
            python_error(api, result);
            failed = 1;
            goto cleanup;
        }
        PyObject *bootstrap_globals = CALL(api, PyModule_GetDict)(bootstrap_module);
        PyObject *bootstrap_value = bootstrap_globals != NULL
                                       ? CALL(api, PyRun_StringFlags)(
                                             bootstrap, Py_file_input,
                                             bootstrap_globals, bootstrap_globals,
                                             NULL)
                                       : NULL;
        if (bootstrap_value == NULL) {
            python_error(api, result);
            failed = 1;
        } else {
            CALL(api, Py_DecRef)(bootstrap_value);
        }
        CALL(api, Py_DecRef)(bootstrap_module);
        if (failed) {
            goto cleanup;
        }
    }
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
    if (archive != NULL) {
        active_archive = NULL;
    }
    int still_initialized = CALL(api, Py_IsInitialized)();
    if (host == NULL && !still_initialized) {
        *frozen_address = original;
    }
    /* A failed initialization can leave a partially initialized runtime even
     * when Py_IsInitialized() is false. Keep our C-owned bytes alive until
     * process exit in that case; this boundary never retries initialization. */
    if (host == NULL &&
        (!initialization_attempted || (initialized && !still_initialized))) {
        free_frozen(&owner);
    }
    free(source);
    free(bootstrap);
    free_extensions(&native);
    return failed;
}

int glue_python_run(const GluePythonApi *api, const GlueFrozenRecord *records,
                    size_t count, const unsigned char *app_source,
                    size_t app_len, GluePythonResult *result) {
    return run_python(api, records, count, NULL, NULL, NULL, 0, NULL, 0,
                      app_source, app_len, result);
}

int glue_python_run_host(const GluePythonApi *api, const char *prefix,
                         const char *stdlib, const unsigned char *app_source,
                         size_t app_len, GluePythonResult *result) {
    if (result == NULL) {
        return 1;
    }
    result->error = NULL;
    result->error_len = 0;
    HostPaths paths = {0};
    if (make_host_paths(prefix, stdlib, &paths, result)) {
        return 1;
    }
    int failed = run_python(api, NULL, 0, &paths, NULL, NULL, 0, NULL, 0,
                            app_source, app_len, result);
    free_host_paths(&paths);
    return failed;
}

int glue_python_run_extensions(const GluePythonApi *api,
                            const GlueFrozenRecord *records, size_t count,
                            const char *prefix, const char *stdlib,
                            const GlueExtensionRecord *extensions,
                            size_t extension_count,
                            GlueResourceRequest request,
                            GlueResourceRelease release, void *context,
                            const unsigned char *bootstrap_source,
                            size_t bootstrap_len,
                            const unsigned char *app_source, size_t app_len,
                            GluePythonResult *result) {
    if (result == NULL) {
        return 1;
    }
    result->error = NULL;
    result->error_len = 0;
    ArchiveBridge bridge = {request, release, context};
    if (!valid_archive(&bridge)) {
        return fail(result, "invalid Python archive resource callbacks");
    }
    HostPaths paths = {0};
    const HostPaths *selected_host = NULL;
    if (prefix != NULL || stdlib != NULL) {
        if (prefix == NULL || stdlib == NULL || records != NULL || count != 0) {
            return fail(result, "invalid Python archive startup selection");
        }
        if (make_host_paths(prefix, stdlib, &paths, result)) {
            return 1;
        }
        selected_host = &paths;
    } else if (records == NULL || count == 0 || count > MAX_RECORDS) {
        return fail(result, "invalid Python archive startup selection");
    }
    int failed = run_python(api, records, count, selected_host, &bridge,
                            extensions, extension_count,
                            bootstrap_source, bootstrap_len,
                            app_source, app_len, result);
    free_host_paths(&paths);
    return failed;
}

int glue_python_run_archive(const GluePythonApi *api,
                            const GlueFrozenRecord *records, size_t count,
                            const char *prefix, const char *stdlib,
                            GlueResourceRequest request,
                            GlueResourceRelease release, void *context,
                            const unsigned char *bootstrap_source,
                            size_t bootstrap_len,
                            const unsigned char *app_source, size_t app_len,
                            GluePythonResult *result) {
    return glue_python_run_extensions(api, records, count, prefix, stdlib,
                                      NULL, 0, request, release, context,
                                      bootstrap_source, bootstrap_len,
                                      app_source, app_len, result);
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

int glue_python_boundary_test_host_paths(void) {
    char prefix[] = "/installed Python";
    char stdlib[] = "/installed Python/lib/python3.13";
    HostPaths paths = {0};
    GluePythonResult result = {0};
    int failed = 1;
    if (make_host_paths(prefix, stdlib, &paths, &result)) {
        goto done;
    }
    prefix[1] = 'x';
    stdlib[1] = 'x';
    if (wcscmp(paths.prefix, L"/installed Python") != 0 ||
        wcscmp(paths.stdlib, L"/installed Python/lib/python3.13") != 0) {
        goto done;
    }
    free_host_paths(&paths);
    free_host_paths(&paths);
    if (paths.prefix != NULL || paths.stdlib != NULL) {
        goto done;
    }
    const char *invalid[] = {
        NULL, "", "/", "relative", "//host", "/host/", "/host/./lib",
        "/host/../lib", "/host//lib", "/host\\lib", "/host\nlib",
        "/host\177", "/host\200"
    };
    for (size_t index = 0; index < sizeof(invalid) / sizeof(*invalid); index++) {
        size_t length = 0;
        if (host_path(invalid[index], &length)) {
            goto done;
        }
    }
    char bounded[MAX_HOST_PATH + 2];
    memset(bounded, 'x', sizeof(bounded));
    bounded[0] = '/';
    bounded[MAX_HOST_PATH] = '\0';
    size_t length = 0;
    if (!host_path(bounded, &length) || length != MAX_HOST_PATH) {
        goto done;
    }
    bounded[MAX_HOST_PATH] = 'x';
    bounded[MAX_HOST_PATH + 1] = '\0';
    if (host_path(bounded, &length)) {
        goto done;
    }
    const char *mismatched[] = {"/host", "/host-other/lib", "/elsewhere/lib"};
    for (size_t index = 0; index < sizeof(mismatched) / sizeof(*mismatched); index++) {
        if (!make_host_paths("/host", mismatched[index], &paths, &result) ||
            paths.prefix != NULL || paths.stdlib != NULL ||
            result.error == NULL || result.error_len == 0) {
            goto done;
        }
        glue_python_result_free(&result);
    }
    /* Reject invalid ABI tables before any Python call. The valid host paths
     * are copied and released even on this configuration-validation failure. */
    GluePythonApi api = {0};
    api.abi_revision = 1;
    static const unsigned char source[] = "pass";
    if (!glue_python_run_host(&api, "/host", "/host/lib/python3.13", source,
                              sizeof(source) - 1, &result) ||
        result.error == NULL ||
        strcmp(result.error, "invalid Python boundary API table") != 0) {
        goto done;
    }
    failed = 0;
done:
    free_host_paths(&paths);
    glue_python_result_free(&result);
    return failed;
}

typedef struct CallbackTest {
    unsigned char *data;
    size_t len;
    int status;
    size_t requests;
    size_t releases;
    int invalid;
} CallbackTest;

static int test_request(void *context, const unsigned char *request,
                         size_t request_len, GlueResourceReply *reply) {
    CallbackTest *test = context;
    static const unsigned char expected[] = {'r', '\0', 0xce, 0xbb};
    if (request_len != sizeof(expected) ||
        memcmp(request, expected, sizeof(expected)) != 0 ||
        reply->data != NULL || reply->len != 0) {
        test->invalid = 1;
    }
    test->requests++;
    reply->data = test->data;
    reply->len = test->len;
    return test->status;
}

static void test_release(void *context, unsigned char *data, size_t len) {
    CallbackTest *test = context;
    if (data != test->data || len != test->len || test->releases != 0) {
        test->invalid = 1;
    }
    test->releases++;
    /* The successful copy must survive releasing and changing the producer's
     * buffer. The storage bound is deliberately separate from reply length:
     * invalid oversized replies are released without reading their bytes. */
    if (data != NULL) {
        memset(data, 0xdd, 4);
    }
    free(data);
    test->data = NULL;
}

int glue_python_boundary_test_archive_callbacks(void) {
    static const unsigned char request[] = {'r', '\0', 0xce, 0xbb};
    static const unsigned char source[] = "pass";
    static const struct {
        int status;
        size_t len;
        unsigned char bytes[4];
        int null_buffer;
        int invalid;
    } cases[] = {
        {0, 3, {'a', '\0', 'b', 0}, 0, 0},
        {0, 0, {0}, 1, 0},
        {0, 0, {0}, 0, 0},
        {1, 3, {'x', 0xce, 0xbb, 0}, 0, 0},
        {1, 0, {0}, 1, 0},
        {2, 1, {'a', 0}, 0, 1},
        {0, MAX_CODE + 1, {'a', 0}, 0, 1},
        {1, MAX_ERROR + 1, {'a', 0}, 0, 1},
        {0, 1, {0}, 1, 1},
        {1, 3, {'a', '\0', 'b', 0}, 0, 1},
        {1, 2, {0xc0, 0x80, 0}, 0, 1},
        {1, 3, {0xed, 0xa0, 0x80, 0}, 0, 1},
        {1, 4, {0xf4, 0x90, 0x80, 0x80}, 0, 1},
        {1, 1, {0xce, 0}, 0, 1}
    };
    GluePythonResult result = {0};
    int failed = 1;
    static const unsigned char nul_source[] = {'p', '\0', 's'};
    static const unsigned char utf8_source[] = {0xce, 0xbb};
    static const unsigned char invalid_utf8_source[] = {0xc0, 0x80};
    if (!valid_source(source, sizeof(source) - 1, MAX_BOOTSTRAP) ||
        valid_source(NULL, 1, MAX_BOOTSTRAP) ||
        valid_source(source, 0, MAX_BOOTSTRAP) ||
        valid_source(source, MAX_BOOTSTRAP + 1, MAX_BOOTSTRAP) ||
        valid_source(nul_source, sizeof(nul_source), MAX_BOOTSTRAP) ||
        !valid_utf8(utf8_source, sizeof(utf8_source)) ||
        valid_utf8(invalid_utf8_source, sizeof(invalid_utf8_source))) {
        goto done;
    }
    for (size_t index = 0; index < sizeof(cases) / sizeof(*cases); index++) {
        CallbackTest test = {0};
        test.status = cases[index].status;
        test.len = cases[index].len;
        if (!cases[index].null_buffer) {
            test.data = malloc(4);
            if (test.data == NULL) {
                goto done;
            }
            memcpy(test.data, cases[index].bytes, 4);
        }
        ArchiveBridge bridge = {test_request, test_release, &test};
        OwnedReply owned = {0};
        request_owned(&bridge, request, sizeof(request), &owned);
        int invalid = test.invalid || test.requests != 1 || test.releases != 1 ||
                      test.data != NULL ||
                      (owned.failure != NULL) != cases[index].invalid;
        if (!cases[index].invalid) {
            invalid = invalid || owned.status != test.status ||
                      owned.len != cases[index].len || owned.data == NULL ||
                      owned.data[owned.len] != '\0' ||
                      memcmp(owned.data, cases[index].bytes, owned.len) != 0;
        } else {
            invalid = invalid || owned.data != NULL || owned.len != 0;
        }
        free(owned.data);
        if (invalid) {
            goto done;
        }
    }
    CallbackTest test = {0};
    ArchiveBridge bridge = {test_request, test_release, &test};
    if (!valid_archive(&bridge)) {
        goto done;
    }
    bridge.request = NULL;
    if (valid_archive(&bridge)) {
        goto done;
    }
    bridge.request = test_request;
    bridge.release = NULL;
    if (valid_archive(&bridge)) {
        goto done;
    }
    bridge.release = test_release;
    bridge.context = NULL;
    if (valid_archive(&bridge)) {
        goto done;
    }
    GluePythonApi api = {0};
    api.abi_revision = 2;
    unsigned char code[] = {1, 2, 3};
    GlueFrozenRecord record = {"encodings", code, 3, 1};
    if (!glue_python_run_archive(&api, &record, 1, NULL, NULL,
                                 test_request, test_release, &test,
                                 source, sizeof(source) - 1,
                                 source, sizeof(source) - 1, &result) ||
        result.error == NULL ||
        strcmp(result.error, "invalid Python boundary API table") != 0 ||
        test.requests != 0 || test.releases != 0) {
        goto done;
    }
    glue_python_result_free(&result);
    if (!glue_python_run_archive(&api, &record, 1,
                                 "/host", "/host/lib/python3.13",
                                 test_request, test_release, &test,
                                 source, sizeof(source) - 1,
                                 source, sizeof(source) - 1, &result) ||
        result.error == NULL ||
        strcmp(result.error, "invalid Python archive startup selection") != 0 ||
        test.requests != 0 || test.releases != 0) {
        goto done;
    }
    glue_python_result_free(&result);
    if (!glue_python_run_archive(&api, &record, 1, NULL, NULL,
                                 test_request, NULL, &test,
                                 source, sizeof(source) - 1,
                                 source, sizeof(source) - 1, &result) ||
        result.error == NULL ||
        strcmp(result.error, "invalid Python archive resource callbacks") != 0 ||
        test.requests != 0 || test.releases != 0) {
        goto done;
    }
    failed = 0;
done:
    glue_python_result_free(&result);
    return failed;
}

typedef struct ExtensionRegistrationTest {
    const ExtensionOwner *expected;
    size_t calls;
    size_t fail_at;
    size_t initializations;
    int invalid;
} ExtensionRegistrationTest;

static ExtensionRegistrationTest extension_test;

static PyObject *test_extension_initializer(void) {
    extension_test.initializations++;
    return NULL;
}

static int test_append_inittab(const char *name,
                               PyObject *(*initializer)(void)) {
    size_t index = extension_test.calls++;
    if (index >= extension_test.expected->count ||
        name != extension_test.expected->records[index].name ||
        initializer != test_extension_initializer) {
        extension_test.invalid = 1;
    }
    return index == extension_test.fail_at ? -1 : 0;
}

int glue_python_boundary_test_extensions(void) {
    char names[MAX_EXTENSIONS][MAX_NAME + 2];
    GlueExtensionRecord records[MAX_EXTENSIONS];
    for (size_t index = 0; index < MAX_EXTENSIONS; index++) {
        snprintf(names[index], sizeof(names[index]), "glue_native_%zu", index);
        records[index].name = names[index];
        records[index].initializer = (const void *)test_extension_initializer;
    }
    ExtensionOwner owner = {0};
    GluePythonResult result = {0};
    int failed = 1;
    if (!valid_extensions(NULL, 0) || valid_extensions(NULL, 1) ||
        valid_extensions(records, 0) ||
        valid_extensions(records, MAX_EXTENSIONS + 1) ||
        !valid_extensions(records, MAX_EXTENSIONS)) {
        goto done;
    }
    const char *invalid[] = {
        NULL, "", "glue_native_", "other", "glue_native_x.y",
        "glue_native_x-y", "glue_native_x/y", "glue_native_x y",
        "glue_native_x\n", "glue_native_\177", "glue_native_\200",
        "Glue_native_x"
    };
    for (size_t index = 0; index < sizeof(invalid) / sizeof(*invalid); index++) {
        records[0].name = invalid[index];
        if (valid_extensions(records, 1) ||
            !make_extensions(records, 1, &owner, &result) ||
            owner.count != 0 || result.error == NULL) {
            goto done;
        }
        glue_python_result_free(&result);
    }
    records[0].name = names[0];
    records[0].initializer = NULL;
    if (valid_extensions(records, 1)) {
        goto done;
    }
    records[0].initializer = (const void *)test_extension_initializer;
    records[1].name = names[0];
    if (valid_extensions(records, 2)) {
        goto done;
    }
    records[1].name = names[1];
    char bounded[MAX_NAME + 2];
    memset(bounded, 'x', sizeof(bounded));
    memcpy(bounded, "glue_native_", sizeof("glue_native_") - 1);
    bounded[MAX_NAME] = '\0';
    records[0].name = bounded;
    if (!valid_extensions(records, 1)) {
        goto done;
    }
    bounded[MAX_NAME] = 'x';
    bounded[MAX_NAME + 1] = '\0';
    if (valid_extensions(records, 1)) {
        goto done;
    }
    records[0].name = names[0];
    if (make_extensions(records, MAX_EXTENSIONS, &owner, &result) ||
        owner.count != MAX_EXTENSIONS || owner.published ||
        owner.records[0].name == names[0] ||
        owner.records[0].initializer != records[0].initializer) {
        goto done;
    }
    names[0][0] = 'x';
    if (strcmp(owner.records[0].name, "glue_native_0") != 0) {
        goto done;
    }
    names[0][0] = 'g';
    free_extensions(&owner);
    free_extensions(&owner);
    if (owner.count != 0 || owner.records[0].name != NULL) {
        goto done;
    }
    GluePythonApi api = {0};
    api.PyImport_AppendInittab = (void *)test_append_inittab;
    /* This fake public API records borrowed pointers without calling Python or
     * any initializer. Exercise success and first/partial append failures. */
    const size_t failures[] = {MAX_EXTENSIONS, 0, 1};
    for (size_t index = 0; index < sizeof(failures) / sizeof(*failures); index++) {
        if (make_extensions(records, 2, &owner, &result)) {
            goto done;
        }
        extension_test = (ExtensionRegistrationTest){&owner, 0, failures[index], 0, 0};
        int rejected = register_extensions(&api, &owner, &result);
        size_t calls = failures[index] == 0 ? 1 : 2;
        if (rejected != (failures[index] < 2) ||
            extension_test.calls != calls || extension_test.initializations != 0 ||
            extension_test.invalid || !owner.published) {
            goto done;
        }
        const char *copied = owner.records[0].name;
        free_extensions(&owner);
        if (owner.count != 2 || owner.records[0].name != copied ||
            strcmp(copied, "glue_native_0") != 0) {
            goto done;
        }
        /* The fake append retains no process table. Only this test may release
         * names after proving the production cleanup preserves published ones. */
        owner.published = 0;
        free_extensions(&owner);
        glue_python_result_free(&result);
    }
    failed = 0;
done:
    owner.published = 0; /* No real AppendInittab call occurs in this selftest. */
    free_extensions(&owner);
    glue_python_result_free(&result);
    return failed;
}
