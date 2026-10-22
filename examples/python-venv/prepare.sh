#!/bin/sh
# Install inputs explicitly; glue itself never installs Python packages.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 PYTHON_EXECUTABLE [NEW_VENV_DIRECTORY]" >&2
    exit 2
fi
example=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python=$1
venv=${2:-"$example/../../target/examples/python-venv-env"}

if [ -e "$venv" ] || [ -L "$venv" ]; then
    echo "Refusing to replace an existing environment: $venv" >&2
    exit 1
fi
# The base interpreter's pip installs into a pip-free ordinary venv. This avoids
# bundling installer packages and executable .pth hooks in the application input.
"$python" -I -B -m pip --version
mkdir -p -- "$(dirname -- "$venv")"
"$python" -I -B -m venv --without-pip "$venv"
"$python" -I -B -m pip --python "$venv/bin/python" install \
    --only-binary=:all: --no-compile --requirement "$example/requirements.txt"
"$venv/bin/python" -B "$example/app/main.py"
