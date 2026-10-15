#!/usr/bin/env python3
"""Run the shared native cost harness."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures/mvp"))
from benchmark import main
raise SystemExit(main())
