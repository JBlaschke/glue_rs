#include <Python.h>

extern long glue_python_dependency_answer(void);
static long initialization_count;

static PyObject *answer(PyObject *module, PyObject *unused)
{
    (void)module;
    (void)unused;
    return PyLong_FromLong(glue_python_dependency_answer());
}

static PyObject *init_calls(PyObject *module, PyObject *unused)
{
    (void)module;
    (void)unused;
    return PyLong_FromLong(initialization_count);
}

static PyObject *fail(PyObject *module, PyObject *unused)
{
    (void)module;
    (void)unused;
    PyErr_SetString(PyExc_RuntimeError, "intentional native method error");
    return NULL;
}

static PyMethodDef methods[] = {
    {"answer", answer, METH_NOARGS, NULL},
    {"init_calls", init_calls, METH_NOARGS, NULL},
    {"fail", fail, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

/* Negative m_size selects CPython's cached single-phase initial dictionary. */
static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT,
    .m_name = "glue_native_single",
    .m_size = -1,
    .m_methods = methods
};

PyMODINIT_FUNC PyInit_glue_native_single(void)
{
    initialization_count++;
    PyObject *module = PyModule_Create2(&definition, PYTHON_API_VERSION);
    if (module == NULL) {
        return NULL;
    }
    if (PyModule_AddIntConstant(module, "initial_value", 42) < 0) {
        /* The public function avoids a private _Py_Dealloc macro import. */
        Py_DecRef(module);
        return NULL;
    }
    return module;
}
