#!/usr/bin/env python3
"""Pure status ABI/refusal and source-isolated lifecycle models; no provider."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FLAGS = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1']
if os.environ.get('GLUE_RUNTIME_STOPPED_STATUS_SANITIZE') == '1':
    FLAGS += ['-g', '-fno-omit-frame-pointer', '-fsanitize=address,undefined']
RETAIN = os.environ.get('GLUE_RUNTIME_STOPPED_STATUS_RETAIN')
COMMAND = 0


def pins():
    names = ('runtime_trace_backend.c', 'runtime_trace_backend.h',
             'runtime_trace_program.c', 'runtime_trace_program.h',
             'runtime_stopped_trace.h', 'runtime_stopped_status.h',
             'test_runtime_stopped_backend.c', 'test_runtime_stopped_status.c',
             'test_runtime_stopped_status.py')
    paths = [HERE / name for name in names]
    paths += [HERE.parent / 'trace-session' / 'trace_session.h']
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


INITIAL = pins()


def command(argv):
    global COMMAND
    COMMAND += 1
    result = subprocess.run([str(x) for x in argv], capture_output=True,
                            timeout=45)
    if RETAIN:
        out = Path(RETAIN) / 'commands'
        out.mkdir(parents=True, exist_ok=True)
        stem = '%03d' % COMMAND
        (out / (stem + '.stdout')).write_bytes(result.stdout)
        (out / (stem + '.stderr')).write_bytes(result.stderr)
        record = {'argv': [str(x) for x in argv], 'exit': result.returncode}
        (out / (stem + '.json')).write_text(json.dumps(record, indent=2) + '\n')
        (Path(RETAIN) / 'sources.json').write_text(json.dumps(INITIAL, indent=2) + '\n')
    if pins() != INITIAL:
        raise AssertionError('status sources changed during controls')
    result.check_returncode()
    return result.stdout


def workspace(name):
    if RETAIN:
        path = Path(RETAIN) / name
        path.mkdir(parents=True, exist_ok=False)
        return path, None
    temp = tempfile.TemporaryDirectory(prefix='glue-stopped-status-')
    return Path(temp.name), temp


class PortableStatusControls(unittest.TestCase):
    def test_nonapple_status_refuses_and_clears(self):
        out, temp = workspace('nonapple')
        try:
            main = out / 'main.c'
            main.write_text(r'''#include "runtime_stopped_status.h"
#include <assert.h>
#include <string.h>
int main(void) {
 struct rt_stopped_status s;
 memset(&s,0xa5,sizeof(s));assert(rt_stopped_status(NULL,&s)==-1);
 for(size_t i=0;i<sizeof(s);i++)assert(!((unsigned char *)&s)[i]);
 memset(&s,0xa5,sizeof(s));assert(rt_stopped_status((const struct rt_backend *)1,&s)==-1);
 for(size_t i=0;i<sizeof(s);i++)assert(!((unsigned char *)&s)[i]);
 assert(rt_stopped_status(NULL,NULL)==-1);return 0;
}
''')
            binary = out / 'refuse'
            command(['cc', *FLAGS, '-U__APPLE__', '-I', HERE, main,
                     HERE / 'runtime_trace_backend.c',
                     HERE / 'runtime_trace_program.c', '-o', binary])
            self.assertEqual(command([binary]), b'')
        finally:
            if temp:
                temp.cleanup()

    def test_existing_snapshot_abi_is_not_redefined(self):
        out, temp = workspace('abi')
        try:
            body = r'''
#include <stddef.h>
#include <stdio.h>
int main(void) {
 printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu\n",sizeof(struct rt_snapshot),
 offsetof(struct rt_snapshot,binding),offsetof(struct rt_snapshot,first_error),
 offsetof(struct rt_snapshot,close_error),offsetof(struct rt_snapshot,writer_close_errno),
 offsetof(struct rt_snapshot,events),offsetof(struct rt_snapshot,start_attempted),
 offsetof(struct rt_snapshot,close_attempted),offsetof(struct rt_snapshot,resources_closed));
 return 0;
}
'''
            observed = []
            for name, header in [('old', 'runtime_trace_backend.h'),
                                 ('new', 'runtime_stopped_status.h')]:
                main = out / (name + '.c')
                main.write_text('#include "' + header + '"\n' + body)
                binary = out / name
                command(['cc', *FLAGS, '-I', HERE, main, '-o', binary])
                observed.append(command([binary]))
            self.assertEqual(observed[0], observed[1])
        finally:
            if temp:
                temp.cleanup()


@unittest.skipUnless(platform.system() == 'Darwin', 'injected native SDK record model')
class StatusLifecycleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out, cls.temp = workspace('models')
        cls.binary = cls.out / 'status-model'
        command(['cc', *FLAGS, HERE / 'test_runtime_stopped_status.c',
                 HERE / 'runtime_trace_program.c', '-o', cls.binary])

    @classmethod
    def tearDownClass(cls):
        if cls.temp:
            cls.temp.cleanup()

    def model(self, mode):
        artifact = self.out / (mode + '-artifacts')
        artifact.mkdir()
        self.assertIn(b'PASS ', command([self.binary, mode, artifact]))


for _mode in ('null-before-destroy', 'foreign-default', 'clean-final',
              'earlier-fault-cleanup', 'late-clock', 'writer-close',
              'missing-drain', 'missing-end', 'malformed-name'):
    def _test(self, mode=_mode):
        self.model(mode)
    setattr(StatusLifecycleControls, 'test_' + _mode.replace('-', '_'), _test)


if __name__ == '__main__':
    unittest.main()
