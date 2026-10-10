#include <Python.h>

extern long glue_python_dependency_answer(void);
static long initialization_count;

typedef struct {
    long executions;
    long value;
} State;

static PyObject *answer(PyObject *module, PyObject *unused)
{
    (void)unused;
    State *state = PyModule_GetState(module);
    return PyLong_FromLong(state->value);
}

static PyObject *bump(PyObject *module, PyObject *unused)
{
    (void)unused;
    State *state = PyModule_GetState(module);
    return PyLong_FromLong(++state->value);
}

static PyObject *executions(PyObject *module, PyObject *unused)
{
    (void)unused;
    State *state = PyModule_GetState(module);
    return PyLong_FromLong(state->executions);
}

static PyObject *init_calls(PyObject *module, PyObject *unused)
{
    (void)module;
    (void)unused;
    return PyLong_FromLong(initialization_count);
}

static PyMethodDef methods[] = {
    {"answer", answer, METH_NOARGS, NULL},
    {"bump", bump, METH_NOARGS, NULL},
    {"executions", executions, METH_NOARGS, NULL},
    {"init_calls", init_calls, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static int execute(PyObject *module)
{
    State *state = PyModule_GetState(module);
    state->executions++;
    state->value = glue_python_dependency_answer();
    return PyModule_AddIntConstant(module, "answer_value", state->value);
}

static PyModuleDef_Slot slots[] = {
    {Py_mod_exec, execute},
    {Py_mod_multiple_interpreters, Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED},
    {0, NULL}
};

static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT,
    .m_name = "glue_native_multi",
    .m_size = sizeof(State),
    .m_methods = methods,
    .m_slots = slots
};

PyMODINIT_FUNC PyInit_glue_native_multi(void)
{
    initialization_count++;
    return PyModuleDef_Init(&definition);
}
