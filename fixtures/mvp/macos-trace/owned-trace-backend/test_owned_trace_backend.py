#!/usr/bin/env python3
"""Boundary models plus SDK compile/link only; never runs a tracing provider."""
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SESSION = HERE.parent / 'trace-session' / 'trace_session.c'


def command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30)


class BackendTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == 'Darwin', 'actual Darwin SDK headers required')
    def test_source_isolated_adapter_boundaries(self):
        with tempfile.TemporaryDirectory(prefix='glue-otb-check-') as directory:
            binary = Path(directory) / 'isolated-controls'
            flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-O2']
            if os.environ.get('GLUE_OWNED_TRACE_SANITIZE') == '1':
                flags += ['-O1', '-g', '-fno-omit-frame-pointer', '-fsanitize=address,undefined']
            # Test TU defines every used dtrace symbol. No -ldtrace, provider,
            # fork, exec, child, elevation or tracing setting is involved.
            command(['/usr/bin/xcrun', '--sdk', 'macosx', 'clang', *flags,
                     str(HERE / 'test_owned_trace_backend.c'), str(SESSION), '-o', str(binary)])
            result = command([str(binary)])
            self.assertEqual(result.stdout,
                             'owned trace backend boundary controls passed (fake libdtrace only)\n')
            self.assertEqual(result.stderr, '')

    @unittest.skipUnless(platform.system() == 'Darwin', 'actual Darwin SDK/linker required')
    def test_native_sdk_compile_and_link_without_execution(self):
        with tempfile.TemporaryDirectory(prefix='glue-otb-sdk-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text('#include "owned_trace_backend.h"\nint main(void){return 0;}\n')
            output = Path(directory) / 'native-link-only'
            command(['/usr/bin/xcrun', '--sdk', 'macosx', 'clang', '-std=c11', '-Wall',
                     '-Wextra', '-Werror', '-O2', '-I', str(HERE), str(main),
                     str(HERE / 'owned_trace_backend.c'), '-ldtrace', '-o', str(output)])
            self.assertTrue(output.is_file())
            # Deliberately no subprocess call with output: this binary is NEVER run.

    @unittest.skipIf(platform.system() == 'Darwin', 'portable refusal branch only')
    def test_non_darwin_refuses_before_resources(self):
        with tempfile.TemporaryDirectory(prefix='glue-otb-refusal-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text('#include "owned_trace_backend.h"\n'
                            'int main(void){struct otb_backend *b=(void*)1;'
                            'struct ts_operations o;struct otb_error e;'
                            'return otb_create(&b,-1,0,0,0,&o,&e)==-1 && !b && '
                            '!o.context && e.system_errno==0 ? 0:1;}\n')
            binary = Path(directory) / 'refusal'
            command([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                     '-I', str(HERE), str(main), str(HERE / 'owned_trace_backend.c'), '-o', str(binary)])
            command([str(binary)])


if __name__ == '__main__':
    unittest.main()
