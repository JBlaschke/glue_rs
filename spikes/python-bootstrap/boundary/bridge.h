#ifndef GLUE_PYTHON_BOOTSTRAP_BRIDGE_H
#define GLUE_PYTHON_BOOTSTRAP_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

/* Revision 3: every address belongs to the one selected, pinned runtime.
 * PyImport_FrozenModules and PyExc_RuntimeError are exported public data
 * symbol addresses, not their values.
 * No Python object, PyConfig or PyStatus crosses this boundary. */
typedef struct GluePythonApi {
    uint32_t abi_revision;
    uint32_t reserved;
    void *Py_GetVersion;
    void *Py_IsInitialized;
    void *PyPreConfig_InitIsolatedConfig;
    void *Py_PreInitialize;
    void *PyConfig_InitIsolatedConfig;
    void *PyConfig_SetString;
    void *PyConfig_Clear;
    void *Py_InitializeFromConfig;
    void *PyStatus_Exception;
    void *PyStatus_IsExit;
    void *PyImport_AddModuleRef;
    void *PyModule_GetDict;
    void *PyRun_StringFlags;
    void *Py_DecRef;
    void *PyErr_GetRaisedException;
    void *PyObject_Str;
    void *PyUnicode_AsUTF8AndSize;
    void *PyErr_Clear;
    void *Py_FinalizeEx;
    void *PyImport_FrozenModules;
    void *PyWideStringList_Append;
    void *PyModule_New;
    void *PyCFunction_NewEx;
    void *PyImport_GetModuleDict;
    void *PyDict_SetItemString;
    void *PyBytes_FromStringAndSize;
    void *PyErr_SetString;
    void *PyExc_RuntimeError;
} GluePythonApi;

typedef struct GlueFrozenRecord {
    const char *name;
    const unsigned char *code;
    int32_t size;
    int32_t is_package;
} GlueFrozenRecord;

typedef struct GluePythonResult {
    char *error;
    size_t error_len;
} GluePythonResult;

/* A reply is transferred to C even when its status/length is invalid. C calls
 * release exactly once after request returns, including NULL/empty replies.
 * No Python reference is accepted or returned by either callback. Status 0 is
 * resource bytes (at most 4 MiB); status 1 is error UTF-8 (at most 16 KiB,
 * without NUL bytes). C copies bytes before releasing the Rust-owned buffer.
 * Callbacks must never unwind or longjmp across the boundary. */
typedef struct GlueResourceReply {
    unsigned char *data;
    size_t len;
} GlueResourceReply;
typedef int (*GlueResourceRequest)(void *context, const unsigned char *request,
                                   size_t request_len, GlueResourceReply *reply);
typedef void (*GlueResourceRelease)(void *context, unsigned char *data,
                                    size_t len);

/* One attempt per process, on the caller's thread. Inputs are borrowed during
 * this call and must remain valid; records require NUL-terminated names.
 * Application source is length-delimited UTF-8 without NUL bytes.
 * stdout/stderr belong to the application. Only bounded owned error bytes are
 * returned. Result must be fresh; release it exactly once with the free call.
 * Return 0 on success, 1 on validation/Python/configuration/finalization error.
 * Runtime mappings must remain pinned until process exit, including failures. */
int glue_python_run(const GluePythonApi *api, const GlueFrozenRecord *records,
                    size_t count, const unsigned char *app_source,
                    size_t app_len, GluePythonResult *result);

/* The host fixture uses the same ownership/thread/one-attempt rules. Prefix
 * and stdlib are borrowed, NUL-terminated canonical absolute ASCII paths, at
 * most 4096 bytes each. The stdlib must be below prefix. C copies and widens
 * them without locale-dependent decoding. No custom frozen table is installed;
 * a pre-existing nonempty public PyImport_FrozenModules table is rejected.
 * Rust must validate and retain the exact installed runtime and stdlib before
 * calling this function; it does not discover installations or verify files. */
int glue_python_run_host(const GluePythonApi *api, const char *prefix,
                         const char *stdlib, const unsigned char *app_source,
                         size_t app_len, GluePythonResult *result);

/* Exactly one startup profile is selected: frozen records/count with NULL
 * prefix/stdlib, or host prefix/stdlib with NULL records and zero count.
 * A trusted, bounded, NUL-free importer bootstrap is executed after Python
 * initialization and before application source, in its own module globals. It may
 * call the native _glue_archive.request(str) method. Requests are length-delimited
 * UTF-8 at most 4096 bytes; callback context is non-NULL and remains borrowed
 * through finalization. The method rejects use outside the caller's thread or
 * after the call has finished. All earlier ownership/one-attempt rules apply. */
int glue_python_run_archive(const GluePythonApi *api,
                            const GlueFrozenRecord *records, size_t count,
                            const char *prefix, const char *stdlib,
                            GlueResourceRequest request,
                            GlueResourceRelease release, void *context,
                            const unsigned char *bootstrap_source,
                            size_t bootstrap_len,
                            const unsigned char *app_source, size_t app_len,
                            GluePythonResult *result);
void glue_python_result_free(GluePythonResult *result);

/* Ownership/validation test: no interpreter initialization or Python calls. */
int glue_python_boundary_test_ownership(void);
int glue_python_boundary_test_host_paths(void);
int glue_python_boundary_test_archive_callbacks(void);

#endif
