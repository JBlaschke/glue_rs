import ctypes
import importlib
import importlib.resources
import json
import os
import threading

import cffi
import contourpy
import native_probe
import numpy
import pydantic_core

matrix = numpy.array([[1.0, 2.0], [3.0, 4.0]])
assert numpy.allclose(matrix @ matrix, [[7, 10], [15, 22]])
assert numpy.allclose(numpy.linalg.solve(matrix, [5, 11]), [1, 2])
module = importlib.import_module("numpy._core._multiarray_umath")
assert module is importlib.import_module("numpy._core._multiarray_umath")
generator = contourpy.contour_generator(z=[[0.0, 1.0], [1.0, 0.0]], name="serial")
assert len(generator.lines(0.5)) == 2
try:
    generator.filled(1.0, 0.0)
except ValueError:
    cpp_exception = True
else:
    raise AssertionError("C++ binding failed to translate invalid contour levels")
validator = pydantic_core.SchemaValidator({"type": "int"})
assert validator.validate_python("42") == 42
try:
    validator.validate_python("invalid")
except pydantic_core.ValidationError:
    rust_error = True
else:
    raise AssertionError("Rust validation error was lost")
library = next(path for path in importlib.resources.files(native_probe).iterdir()
               if path.name.startswith("libsecondary."))
handle = ctypes.CDLL(os.fspath(library))
assert handle.secondary_answer() == 42
assert handle.secondary_threads() == 1
virtual = os.path.join(os.path.dirname(native_probe.__file__), library.name)
assert ctypes.CDLL(virtual).secondary_answer() == 42
ffi = cffi.FFI()
ffi.cdef("int secondary_answer(void); int secondary_threads(void);")
ffi_handle = ffi.dlopen(os.fspath(library))
assert ffi_handle.secondary_answer() == 42
assert ffi_handle.secondary_threads() == 1
results = []
threads = [threading.Thread(target=lambda: results.append(validator.validate_python("42")))
           for _ in range(4)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
assert results == [42] * 4
print(json.dumps({"status": "python-native-ok", "matrix": (matrix @ matrix).tolist(),
                  "cffi": True, "ctypes": True, "cpp_exception": cpp_exception,
                  "rust_error": rust_error, "threads": len(results)}))
