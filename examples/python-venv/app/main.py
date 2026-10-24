"""A normal Python application using pure Python and native wheel dependencies."""

import sys

import numpy as np
from packaging.version import Version


def main():
    # packaging is pure Python; NumPy's solver calls its compiled LAPACK code.
    if Version(np.__version__) < Version("2.4"):
        raise RuntimeError("This example requires NumPy 2.4 or newer")
    samples = np.arange(1.0, 9.0)
    solution = np.linalg.solve([[3.0, 1.0], [1.0, 2.0]], [9.0, 8.0])
    np.testing.assert_allclose(solution, [2.0, 3.0])
    print("python-venv: numpy + packaging")
    print(f"mean={samples.mean():.2f}; solve=[{solution[0]:.2f}, {solution[1]:.2f}]")
    print(f"argument={sys.argv[1] if len(sys.argv) > 1 else 'world'}")


if __name__ == "__main__":
    main()
