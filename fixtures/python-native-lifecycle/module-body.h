#include <Python.h>
#include "ledger.h"

typedef struct {
    long instance;
    long executions;
    long value;
    PyObject *owned;
} State;

static void lifecycle_failure(const char *message)
{
    PyErr_SetString(PyExc_RuntimeError, message);
}

static State *module_state(PyObject *module)
{
    State *state = PyModule_GetState(module);
    if (state == NULL || state->instance == 0) {
        lifecycle_failure("lifecycle state is unavailable");
        return NULL;
    }
    return state;
}

static PyObject *answer(PyObject *module, PyObject *unused)
{
    (void)unused;
    State *state = module_state(module);
    return state == NULL ? NULL : PyLong_FromLong(state->value);
}

static PyObject *bump(PyObject *module, PyObject *unused)
{
    (void)unused;
    State *state = module_state(module);
    return state == NULL ? NULL : PyLong_FromLong(++state->value);
}

static PyObject *state_id(PyObject *module, PyObject *unused)
{
    (void)unused;
    State *state = module_state(module);
    return state == NULL ? NULL : PyLong_FromLong(state->instance);
}

static PyObject *executions(PyObject *module, PyObject *unused)
{
    (void)unused;
    State *state = module_state(module);
    return state == NULL ? NULL : PyLong_FromLong(state->executions);
}

static PyObject *method_error(PyObject *module, PyObject *unused)
{
    (void)module;
    (void)unused;
    lifecycle_failure("intentional lifecycle method error");
    return NULL;
}

#define QUERY_METHOD(name, root, field) \
    static PyObject *name(PyObject *module, PyObject *unused) \
    { \
        (void)module; \
        (void)unused; \
        return PyLong_FromLong(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, root, field)); \
    }
QUERY_METHOD(allocations, LIFECYCLE_ROOT, GLUE_LIFECYCLE_ALLOCATIONS)
QUERY_METHOD(frees, LIFECYCLE_ROOT, GLUE_LIFECYCLE_FREES)
QUERY_METHOD(owned, LIFECYCLE_ROOT, GLUE_LIFECYCLE_OWNED)
QUERY_METHOD(releases, LIFECYCLE_ROOT, GLUE_LIFECYCLE_RELEASES)
QUERY_METHOD(init_calls, LIFECYCLE_ROOT, GLUE_LIFECYCLE_INITS)
QUERY_METHOD(create_calls, LIFECYCLE_ROOT, GLUE_LIFECYCLE_CREATES)
QUERY_METHOD(created_objects, LIFECYCLE_ROOT, GLUE_LIFECYCLE_CREATED_OBJECTS)
QUERY_METHOD(traversals, LIFECYCLE_ROOT, GLUE_LIFECYCLE_TRAVERSALS)
QUERY_METHOD(clears, LIFECYCLE_ROOT, GLUE_LIFECYCLE_CLEARS)
QUERY_METHOD(protocol_errors, 0, GLUE_LIFECYCLE_ERRORS)
QUERY_METHOD(total_allocations, 0, GLUE_LIFECYCLE_ALLOCATIONS)
QUERY_METHOD(total_frees, 0, GLUE_LIFECYCLE_FREES)
QUERY_METHOD(total_owned, 0, GLUE_LIFECYCLE_OWNED)
QUERY_METHOD(total_releases, 0, GLUE_LIFECYCLE_RELEASES)

static PyMethodDef methods[] = {
    {"answer", answer, METH_NOARGS, NULL},
    {"bump", bump, METH_NOARGS, NULL},
    {"state_id", state_id, METH_NOARGS, NULL},
    {"executions", executions, METH_NOARGS, NULL},
    {"fail", method_error, METH_NOARGS, NULL},
    {"allocations", allocations, METH_NOARGS, NULL},
    {"frees", frees, METH_NOARGS, NULL},
    {"owned", owned, METH_NOARGS, NULL},
    {"releases", releases, METH_NOARGS, NULL},
    {"init_calls", init_calls, METH_NOARGS, NULL},
    {"create_calls", create_calls, METH_NOARGS, NULL},
    {"created_objects", created_objects, METH_NOARGS, NULL},
    {"traversals", traversals, METH_NOARGS, NULL},
    {"clears", clears, METH_NOARGS, NULL},
    {"protocol_errors", protocol_errors, METH_NOARGS, NULL},
    {"total_allocations", total_allocations, METH_NOARGS, NULL},
    {"total_frees", total_frees, METH_NOARGS, NULL},
    {"total_owned", total_owned, METH_NOARGS, NULL},
    {"total_releases", total_releases, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static PyObject *create_module(PyObject *spec, PyModuleDef *definition)
{
    (void)definition;
    long attempt = glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CREATE, LIFECYCLE_ROOT, 0);
    if (attempt < 1) {
        lifecycle_failure("lifecycle creation ledger rejected");
        return NULL;
    }
    if (LIFECYCLE_ROOT == 2 && attempt == 1) {
        lifecycle_failure("intentional lifecycle create error");
        return NULL;
    }
    PyObject *name = PyObject_GetAttrString(spec, "name");
    if (name == NULL) return NULL;
    PyObject *module = PyModule_NewObject(name);
    Py_DecRef(name);
    if (module == NULL) return NULL;
    if (PyModule_GetState(module) != NULL ||
        PyModule_AddIntConstant(module, "create_marker", 42) != 0 ||
        glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CREATED, LIFECYCLE_ROOT, 0) < 1) {
        Py_DecRef(module);
        lifecycle_failure("lifecycle custom creation state differs");
        return NULL;
    }
    return module;
}

static int execute_module(PyObject *module)
{
    State *state = PyModule_GetState(module);
    if (state == NULL || state->instance || state->executions || state->value || state->owned) {
        lifecycle_failure("lifecycle execution requires fresh zeroed state");
        return -1;
    }
    long instance = glue_python_lifecycle_ledger(GLUE_LIFECYCLE_ALLOCATE, LIFECYCLE_ROOT, 0);
    if (instance < 1) {
        lifecycle_failure("lifecycle allocation ledger rejected");
        return -1;
    }
    state->instance = instance;
    state->executions = 1;
    state->value = 42;
    PyObject *list = PyList_New(1);
    if (list == NULL) return -1;
    Py_IncRef(module);
    if (PyList_SetItem(list, 0, module) != 0) {
        Py_DecRef(list);
        return -1;
    }
    state->owned = list;
    if (glue_python_lifecycle_ledger(GLUE_LIFECYCLE_OWN, LIFECYCLE_ROOT, instance) != 0) {
        lifecycle_failure("lifecycle ownership ledger rejected");
        return -1;
    }
    if (LIFECYCLE_ROOT == 3 &&
        glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, LIFECYCLE_ROOT, GLUE_LIFECYCLE_ALLOCATIONS) == 1) {
        lifecycle_failure("intentional lifecycle exec error");
        return -1;
    }
    return 0;
}

static int traverse_module(PyObject *module, visitproc visit, void *arg)
{
    State *state = PyModule_GetState(module);
    if (state == NULL || state->instance == 0) return 0;
    glue_python_lifecycle_ledger(GLUE_LIFECYCLE_TRAVERSE, LIFECYCLE_ROOT, state->instance);
    return state->owned == NULL ? 0 : visit(state->owned, arg);
}

static void release_owned(State *state)
{
    PyObject *value = state->owned;
    if (value != NULL) {
        /* Detach before decref: destruction may invoke callbacks recursively. */
        state->owned = NULL;
        glue_python_lifecycle_ledger(GLUE_LIFECYCLE_RELEASE, LIFECYCLE_ROOT, state->instance);
        Py_DecRef(value);
        /* Do not access state after decref. */
    }
}

static int clear_module(PyObject *module)
{
    State *state = PyModule_GetState(module);
    if (state == NULL || state->instance == 0) return 0;
    glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CLEAR, LIFECYCLE_ROOT, state->instance);
    release_owned(state);
    return 0;
}

static void free_module(void *module)
{
    State *state = PyModule_GetState((PyObject *)module);
    if (state == NULL || state->instance == 0) return;
    long instance = state->instance;
    release_owned(state);
    glue_python_lifecycle_ledger(GLUE_LIFECYCLE_FREE, LIFECYCLE_ROOT, instance);
}

static PyModuleDef_Slot slots[] = {
    {Py_mod_create, create_module},
    {Py_mod_exec, execute_module},
    {Py_mod_multiple_interpreters, Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED},
    {0, NULL}
};

static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT,
    .m_name = LIFECYCLE_NAME,
    .m_size = sizeof(State),
    .m_methods = methods,
    .m_slots = slots,
    .m_traverse = traverse_module,
    .m_clear = clear_module,
    .m_free = free_module
};

PyMODINIT_FUNC LIFECYCLE_INITIALIZER(void)
{
    if (glue_python_lifecycle_ledger(GLUE_LIFECYCLE_INIT, LIFECYCLE_ROOT, 0) < 1) {
        lifecycle_failure("lifecycle initializer ledger rejected");
        return NULL;
    }
    return PyModuleDef_Init(&definition);
}
