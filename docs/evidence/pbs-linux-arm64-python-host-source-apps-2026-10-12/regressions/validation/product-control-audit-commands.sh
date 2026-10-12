#!/bin/sh
set -eu
python3 -B target/python-host-source-apps-control-audit.py --capture target/python-host-source-apps-final-capture --build target/python-host-source-apps-final-build --source-revision dd6274f9def358ce562ba229f79e14cc2fe6c818 --output target/python-host-source-apps-final-capture/control-audit.json
