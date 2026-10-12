#!/bin/sh
set -eu
python3 target/python-source-apps-control-audit.py \
  --capture target/python-source-apps-final-capture --build target/python-source-apps-final-build \
  --source-revision d3ddac33e41bd681668ce0565c3830e46105ebf5 \
  --output target/python-source-apps-final-capture/control-audit.json
