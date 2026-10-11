#include <Python.h>

extern long glue_python_dependency_answer(void);
static long initialization_count;

static PyObject *answer(PyObject *module, PyObject *unused)
{
    (void)module;
    (void)unused;
    return PyLong_FromLong(glue_python_dependency_answer());
}

static PyObject *attempts(PyObject *module, PyObject *unused)
{
    (void)module;
    (void)unused;
    return PyLong_FromLong(initialization_count);
}

static PyMethodDef methods[] = {
    {"answer", answer, METH_NOARGS, NULL},
    {"attempts", attempts, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT,
    .m_name = "glue_native_init_error",
    .m_size = -1,
    .m_methods = methods
};

PyMODINIT_FUNC PyInit_glue_native_init_error(void)
{
    initialization_count++;
    if (initialization_count == 1) {
        PyErr_SetString(PyExc_RuntimeError, "intentional native initializer error");
        return NULL;
    }
    return PyModule_Create2(&definition, PYTHON_API_VERSION);
}
