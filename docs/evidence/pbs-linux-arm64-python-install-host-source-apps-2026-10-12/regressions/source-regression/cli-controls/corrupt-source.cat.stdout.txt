import sys
import atexit
from simple_value import answer

assert __name__ == "__main__"
assert __file__ == "glue://minimal.source/app/launch.py"
assert sys.argv == [__file__]
assert __package__ is __spec__ is __cached__ is __loader__ is None
assert "_glue_run_source_entry" not in globals()
assert sys.version_info[:3] == (3, 13, 16)
assert sys.path == []
assert sys.flags.isolated == sys.flags.ignore_environment == 1
assert sys.flags.no_site == sys.flags.dont_write_bytecode == 1
assert answer == 42

def finish():
    from simple_value import answer
    assert answer == 42

atexit.register(finish)
print("PASS source-app=minimal entry=launch.py answer=42", flush=True)
