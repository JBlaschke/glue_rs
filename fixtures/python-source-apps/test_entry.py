#!/usr/bin/env python3
"""Execute the actual Rust launcher template over the portable byte protocol.

These checks use the host Python interpreter and fake immutable callbacks.
The separate GNU fixture proves the pinned interpreter and syscall behavior.
"""

from contextlib import contextmanager, redirect_stdout, redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "crates/glue-runtime-python/src/source_entry.rs"
TEMPLATE = re.search(r'const LAUNCHER_TEMPLATE: &str = r#"(.*?)"#;', RUST.read_text(), re.S).group(1)
spec = importlib.util.spec_from_file_location("source_entry_importer_protocol", ROOT / "fixtures/python-imports/test_importer.py")
IMPORTER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(IMPORTER)


def launcher(entry):
    # The template is the actual source sent through the native boundary. Only
    # Rust's serde_json string interpolation is supplied by this portable test.
    return TEMPLATE.replace("{entry}", json.dumps(entry, ensure_ascii=True))


@contextmanager
def application(entry, source):
    archive = IMPORTER.FakeArchive({entry: source})
    with IMPORTER.adapter(archive) as (namespace, _):
        previous_main = sys.modules["__main__"]
        previous_bootstrap = sys.modules.get("_glue_archive_bootstrap")
        previous_argv = sys.argv
        main = types.ModuleType("__main__")
        bootstrap = types.ModuleType("_glue_archive_bootstrap")
        bootstrap.__dict__.update(namespace)
        sys.modules["__main__"] = main
        sys.modules["_glue_archive_bootstrap"] = bootstrap
        sys.argv = ["preexisting", "arguments"]
        try:
            yield main, archive
        finally:
            sys.modules["__main__"] = previous_main
            sys.argv = previous_argv
            if previous_bootstrap is None:
                sys.modules.pop("_glue_archive_bootstrap", None)
            else:
                sys.modules["_glue_archive_bootstrap"] = previous_bootstrap


def execute(main, entry):
    exec(compile(launcher(entry), "trusted-glue-entry-launcher", "exec"), main.__dict__)


class EntryTests(unittest.TestCase):
    def test_declared_entry_outside_import_root_sets_metadata_without_helper_globals(self):
        entry = "app/tasks/report.py"
        source = b"import sys\nobserved = (__name__, __file__, __package__, __spec__, __cached__, __loader__, sys.argv[:], sys.modules['__main__'])\n"
        with application(entry, source) as (main, archive):
            execute(main, entry)
            origin = IMPORTER.origin(entry)
            self.assertEqual(main.observed, ("__main__", origin, None, None, None, None, [origin], main))
            for name in ("_glue_run_source_entry", "_sys", "_bootstrap", "_globals", "_origin"):
                self.assertNotIn(name, main.__dict__)
            self.assertIn("origin\t" + entry, archive.calls)
            self.assertIn("read\t" + entry, archive.calls)

    def test_source_bytes_keep_encoding_cookie_bom_and_empty_source_behavior(self):
        for source, expected in (
            (b"# coding: latin-1\r\ntext = 'caf\xe9'\r\n", "café"),
            (b"\xef\xbb\xbftext = 'caf\xc3\xa9'\n", "café"),
            ("text = 'λ'\n".encode(), "λ"),
            (b"", None),
        ):
            with self.subTest(source=source), application("app/entry.py", source) as (main, archive):
                execute(main, "app/entry.py")
                self.assertEqual(main.__dict__.get("text"), expected)
                self.assertIn("read\tapp/entry.py", archive.calls)

    def test_nested_code_filenames_use_the_declared_virtual_entry(self):
        entry = "app/jobs/nested.py"
        source = b"def outer():\n def inner():\n  return (lambda: [x for x in range(2)])()\n return inner\n"
        with application(entry, source) as (main, _):
            execute(main, entry)
            pending = [main.outer.__code__]
            count = 0
            while pending:
                code = pending.pop()
                self.assertEqual(code.co_filename, IMPORTER.origin(entry))
                pending.extend(value for value in code.co_consts if isinstance(value, types.CodeType))
                count += 1
            self.assertGreaterEqual(count, 3)
            self.assertEqual(main.outer()(), [0, 1])

    def test_syntax_nul_and_invalid_encoding_fail_with_virtual_identity(self):
        entry = "app/jobs/invalid.py"
        for source in (b'if True print("invalid source entry")\n', b'print("unreachable")\0\n', b"text = '\xff'\n"):
            with self.subTest(source=source), application(entry, source) as (main, _):
                with patch("builtins.open", side_effect=AssertionError("Python-level host fallback")), self.assertRaises(SyntaxError) as failure:
                    execute(main, entry)
                self.assertEqual(failure.exception.filename, IMPORTER.origin(entry))
                if len(failure.exception.args) == 2:
                    self.assertEqual(failure.exception.args[1][0], IMPORTER.origin(entry))
                self.assertNotIn("_glue_run_source_entry", main.__dict__)

    def test_user_output_and_runtime_error_remain_application_owned(self):
        source = b"import sys\nprint('user stdout')\nprint('user stderr', file=sys.stderr)\nraise RuntimeError('user failure')\n"
        with application("app/entry.py", source) as (main, _):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaisesRegex(RuntimeError, "^user failure$"):
                execute(main, "app/entry.py")
            self.assertEqual(stdout.getvalue(), "user stdout\n")
            self.assertEqual(stderr.getvalue(), "user stderr\n")
            self.assertNotIn("_glue_run_source_entry", main.__dict__)

    def test_system_exit_is_not_swallowed_or_converted_by_the_launcher(self):
        for value in (None, 0, 7, "requested exit"):
            source = ("raise SystemExit(" + repr(value) + ")\n").encode()
            with self.subTest(value=value), application("app/entry.py", source) as (main, _):
                with self.assertRaises(SystemExit) as failure:
                    execute(main, "app/entry.py")
                self.assertEqual(failure.exception.code, value)
                self.assertNotIn("_glue_run_source_entry", main.__dict__)

    def test_canonical_quotes_spaces_and_brackets_cannot_inject_launcher_code(self):
        for entry in ("app/tasks/task's [draft].py", "app/task';print('INJECTED')#.py"):
            with self.subTest(entry=entry), application(entry, b"answer = 42\n") as (main, archive):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    execute(main, entry)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(main.answer, 42)
                self.assertEqual(main.__file__, IMPORTER.origin(entry))
                self.assertIn("read\t" + entry, archive.calls)


if __name__ == "__main__":
    unittest.main()
