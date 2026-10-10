#ifndef GLUE_PYTHON_BOOTSTRAP_BRIDGE_H
#define GLUE_PYTHON_BOOTSTRAP_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

/* Revision 2: every address belongs to the one selected, pinned runtime.
 * PyImport_FrozenModules is the exported public data symbol, not its value.
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
void glue_python_result_free(GluePythonResult *result);

/* Ownership/validation test: no interpreter initialization or Python calls. */
int glue_python_boundary_test_ownership(void);
int glue_python_boundary_test_host_paths(void);

#endif
