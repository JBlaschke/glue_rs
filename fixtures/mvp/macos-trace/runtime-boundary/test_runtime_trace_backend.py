#!/usr/bin/env python3
"""Portable producer and injected SDK controls; never starts a provider."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SESSION = HERE.parent / 'trace-session' / 'trace_session.c'
FLAGS = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-O2']
_COMMAND_NUMBER = 0
_WORKSPACE_NUMBER = 0


class Workspace:
    def __init__(self, prefix):
        global _WORKSPACE_NUMBER
        self.temporary = None
        retain = os.environ.get('GLUE_RUNTIME_TRACE_RETAIN')
        if retain:
            root = Path(retain)
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            _WORKSPACE_NUMBER += 1
            path = root / ('%03d-' % _WORKSPACE_NUMBER + prefix)
            path.mkdir(mode=0o700)
            self.name = str(path)
        else:
            self.temporary = tempfile.TemporaryDirectory(prefix=prefix)
            self.name = self.temporary.name

    def cleanup(self):
        if self.temporary:
            self.temporary.cleanup()

    def __enter__(self):
        return self.name

    def __exit__(self, *unused):
        self.cleanup()


def command(argv):
    global _COMMAND_NUMBER
    done = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    retain = os.environ.get('GLUE_RUNTIME_TRACE_RETAIN')
    if retain:
        root = Path(retain) / 'commands'
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _COMMAND_NUMBER += 1
        label = '%03d' % _COMMAND_NUMBER
        for stream in ('stdout', 'stderr'):
            (root/(label+'.'+stream)).write_text(getattr(done, stream))
        (root/(label+'.json')).write_text(json.dumps({'argv': argv, 'exit': done.returncode}, indent=2)+'\n')
        dependencies = [HERE/name for name in ('runtime_trace_backend.c', 'runtime_trace_backend.h', 'runtime_trace_program.c', 'runtime_trace_program.h', 'test_runtime_trace_backend.c', 'test_runtime_trace_backend.py')]
        dependencies += [SESSION, SESSION.with_suffix('.h')]
        pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in dependencies}
        source_path = root.parent/'sources.json'
        if source_path.exists() and json.loads(source_path.read_text()) != pins:
            raise AssertionError('runtime backend sources changed during controls')
        source_path.write_text(json.dumps(pins, indent=2)+'\n')
    done.check_returncode()
    return done


def compiler():
    if platform.system() == 'Darwin':
        return ['/usr/bin/xcrun', '--sdk', 'macosx', 'clang']
    return [os.environ.get('CC', 'cc')]


class ProducerTests(unittest.TestCase):
    def test_pure_program_contract(self):
        with Workspace(prefix='glue-rt-program-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text(r'''#include "runtime_trace_program.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
struct guarded { unsigned char before[16];char out[RT_PROGRAM_CAPACITY];unsigned char after[16]; };
int main(void) {
 struct guarded g;memset(&g,0x5a,sizeof(g));size_t n=99;
 assert(rt_program(0,g.out,&n)==-1&&n==0&&!g.out[0]);
 assert(rt_program(UINT32_MAX,g.out,&n)==-1&&n==0&&!g.out[0]);
 assert(rt_program((uint32_t)INT32_MAX+1,g.out,&n)==-1&&n==0&&!g.out[0]);
 assert(rt_program(1,NULL,&n)==-1&&n==0);
 assert(rt_program(1,g.out,NULL)==-1&&!g.out[0]);
 static const uint32_t pids[]={1,17,2147483647};
 for(unsigned i=0;i<sizeof(pids)/sizeof(pids[0]);i++) {
  assert(!rt_program(pids[i],g.out,&n)&&n==strlen(g.out)&&n<RT_PROGRAM_CAPACITY);
  assert(!strncmp(g.out,"#pragma D option quiet\n/* " RT_PROGRAM_PROFILE " */\n",22+sizeof("/* " RT_PROGRAM_PROFILE " */\n")-1));
  char selected[64];snprintf(selected,sizeof(selected),"BEGIN { watched[%u]=1;",pids[i]);assert(strstr(g.out,selected));
  const char *q=g.out;unsigned assignments=0;
  while((q=strstr(q,"watched[pid]=1;"))){assignments++;q++;}
  assert(assignments==3&&strstr(g.out,"trace((uint64_t)errno);")&&strstr(g.out,"p_refcount"));
  assert(!strstr(g.out,"copyinstr")&&!strstr(g.out,"proc:::exec /"));
 }
 for(unsigned i=0;i<16;i++)assert(g.before[i]==0x5a&&g.after[i]==0x5a);
 puts("pure runtime program contract passed");return 0;
}
''')
            output = Path(directory) / 'program-contract'
            command([*compiler(), *FLAGS, '-I', str(HERE), str(main),
                     str(HERE / 'runtime_trace_program.c'), '-o', str(output)])
            self.assertEqual(command([str(output)]).stdout, 'pure runtime program contract passed\n')

    def test_pure_images_program_contract(self):
        with Workspace(prefix='glue-rt-images-program-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text(r'''#include "runtime_trace_program.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
struct guarded { unsigned char before[16];char out[RT_PROGRAM_CAPACITY];unsigned char after[16]; };
int main(void) {
 struct guarded g;memset(&g,0xa5,sizeof(g));size_t n=99;char old[RT_PROGRAM_CAPACITY];size_t old_n;
 assert(rt_images_program(0,g.out,&n)==-1&&n==0&&!g.out[0]);
 assert(rt_images_program(UINT32_MAX,g.out,&n)==-1&&n==0&&!g.out[0]);
 assert(rt_images_program(1,NULL,&n)==-1&&n==0);
 assert(rt_images_program(1,g.out,NULL)==-1&&!g.out[0]);
 static const uint32_t pids[]={1,17,2147483647};
 for(unsigned i=0;i<sizeof(pids)/sizeof(pids[0]);i++) {
  assert(!rt_images_program(pids[i],g.out,&n)&&n==strlen(g.out)&&n<RT_PROGRAM_CAPACITY);
  assert(strstr(g.out,"/* glue-runtime-images-v2; quiescent-exec; no-process-creation */\n"));
  assert(!strstr(g.out,"glue-runtime-boundary-v1"));
  assert(!rt_program(pids[i],old,&old_n));
  const char *a=strchr(old,'\n'),*b=strchr(g.out,'\n');assert(a&&b);
  a=strchr(a+1,'\n');b=strchr(b+1,'\n');assert(a&&b&&!strcmp(a+1,b+1));
  assert(old_n!=n);
 }
 for(unsigned i=0;i<16;i++)assert(g.before[i]==0xa5&&g.after[i]==0xa5);
 puts("pure repeated-image program contract passed");return 0;
}
''')
            output = Path(directory) / 'images-program-contract'
            command([*compiler(), *FLAGS, '-I', str(HERE), str(main),
                     str(HERE / 'runtime_trace_program.c'), '-o', str(output)])
            self.assertEqual(command([str(output)]).stdout,
                             'pure repeated-image program contract passed\n')

    def test_images_unavailable_factory_clears_all_outputs(self):
        with Workspace(prefix='glue-rt-images-refusal-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text(r'''#include "runtime_trace_backend.h"
#include <errno.h>
#include <string.h>
int main(void) {
 struct rt_backend *b=(void*)1;struct ts_operations o;struct rt_error e;
 memset(&o,0xa5,sizeof(o));memset(&e,0xa5,sizeof(e));
 if(rt_images_create(&b,99,NULL,1,1,&o,&e)!=-1||b)return 1;
 const unsigned char *p=(const unsigned char*)&o;
 for(unsigned i=0;i<sizeof(o);i++)if(p[i])return 2;
 return e.stage==RT_CREATE&&e.system_errno==0&&e.libdtrace_code==0&&e.callback_error==ENOTSUP?0:3;
}
''')
            output = Path(directory) / 'images-refusal'
            command([*compiler(), *FLAGS, '-U__APPLE__', '-I', str(HERE), str(main),
                     str(HERE / 'runtime_trace_backend.c'), str(HERE / 'runtime_trace_program.c'),
                     '-o', str(output)])
            self.assertEqual(command([str(output)]).stdout, '')

    def test_all_unavailable_factories_keep_exact_unsupported_outputs(self):
        with Workspace(prefix='glue-rt-profile-refusal-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text(r'''#include "runtime_trace_backend.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
typedef int (*factory)(struct rt_backend **,int,const struct ts_binding *,uint64_t,int,struct ts_operations *,struct rt_error *);
int main(void) {
 factory factories[]={rt_create,rt_images_create,rt_recipe_images_create};
 for(unsigned f=0;f<3;f++)for(unsigned omitted=0;omitted<4;omitted++) {
  struct rt_backend *b=(void*)1;struct ts_operations o;struct rt_error e;
  memset(&o,0xa5,sizeof(o));memset(&e,0xa5,sizeof(e));
  assert(factories[f](omitted==1?NULL:&b,99,NULL,1,1,omitted==2?NULL:&o,omitted==3?NULL:&e)==-1);
  if(omitted!=1)assert(!b);
  if(omitted!=2){const unsigned char *p=(const unsigned char*)&o;for(unsigned i=0;i<sizeof(o);i++)assert(!p[i]);}
  if(omitted!=3){
   assert(e.stage==RT_CREATE&&e.reason==RT_ARGUMENT&&!e.system_errno&&!e.libdtrace_code&&e.callback_error==ENOTSUP);
   assert(!strcmp(e.message,"native Darwin runtime boundary backend unavailable"));
   size_t n=strlen(e.message);for(size_t i=n;i<sizeof(e.message);i++)assert(!e.message[i]);
  }
 }
 return 0;
}
''')
            output = Path(directory) / 'profile-refusal'
            command([*compiler(), *FLAGS, '-U__APPLE__', '-I', str(HERE), str(main),
                     str(HERE / 'runtime_trace_backend.c'), str(HERE / 'runtime_trace_program.c'),
                     '-o', str(output)])
            self.assertEqual(command([str(output)]).stdout, '')

    def test_unavailable_backend_refuses_before_resources(self):
        # Force only the actual backend's non-Darwin implementation on Darwin;
        # this does not simulate a successful native provider or target host.
        with Workspace(prefix='glue-rt-refusal-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text('#include "runtime_trace_backend.h"\n#include <errno.h>\n'
                            'int main(void){struct rt_backend *b=(void*)1;'
                            'struct ts_operations o;struct rt_error e;'
                            'return rt_create(&b,-1,0,0,0,&o,&e)==-1 && !b && '
                            '!o.context && e.system_errno==0 && e.callback_error==ENOTSUP ? 0:1;}\n')
            output = Path(directory) / 'refusal'
            command([*compiler(), *FLAGS, '-U__APPLE__', '-I', str(HERE), str(main),
                     str(HERE / 'runtime_trace_backend.c'), str(HERE / 'runtime_trace_program.c'),
                     '-o', str(output)])
            self.assertEqual(command([str(output)]).stdout, '')

    @unittest.skipUnless(platform.system() == 'Darwin', 'actual Darwin SDK/linker required')
    def test_native_sdk_compile_and_link_without_execution(self):
        with Workspace(prefix='glue-rt-sdk-') as directory:
            main = Path(directory) / 'main.c'
            main.write_text('#include "runtime_trace_backend.h"\nint main(void){return 0;}\n')
            output = Path(directory) / 'native-link-only'
            command([*compiler(), *FLAGS, '-I', str(HERE), str(main),
                     str(HERE / 'runtime_trace_backend.c'), str(HERE / 'runtime_trace_program.c'),
                     '-ldtrace', '-o', str(output)])
            self.assertTrue(output.is_file())
            # Link validation only: this provider-linked binary is never run.


@unittest.skipUnless(platform.system() == 'Darwin', 'actual Darwin SDK headers required')
class InjectedBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Workspace(prefix='glue-rt-injected-')
        cls.binary = Path(cls.directory.name) / 'isolated-controls'
        flags = list(FLAGS)
        if os.environ.get('GLUE_RUNTIME_TRACE_SANITIZE') == '1':
            flags += ['-O1', '-g', '-fno-omit-frame-pointer', '-fsanitize=address,undefined']
        try:
            # Every used DTrace symbol is defined in this test TU. No -ldtrace,
            # fork, exec, elevation, tracing settings or provider is involved.
            command([*compiler(), *flags, str(HERE / 'test_runtime_trace_backend.c'),
                     str(HERE / 'runtime_trace_program.c'), str(SESSION), '-o', str(cls.binary)])
        except Exception:
            cls.directory.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_group(self, name):
        selected = [name] if name in ('selected-exec', 'profile-factories', 'program-binding') else [name, 'recipe-'+name]
        for profile in selected:
            with self.subTest(profile=profile):
                result = command([str(self.binary), profile])
                self.assertEqual(result.stdout,
                                 'runtime trace backend boundary controls passed (fake libdtrace only)\n')
                self.assertEqual(result.stderr, '')

    def test_full_session_with_new_exec_tid(self):
        self.run_group('full-session')

    def test_strict_record_and_enabling_bindings(self):
        self.run_group('rejected-records')

    def test_start_and_output_failures(self):
        self.run_group('start-failures')

    def test_exact_compiled_inventory(self):
        self.run_group('compiled-matches')

    def test_bounds_faults_drops_and_early_done(self):
        self.run_group('bounds-faults')

    def test_deadline_clock_and_close_results(self):
        self.run_group('deadline-close')

    def test_unsupported_records_retained_before_refusal(self):
        self.run_group('unsupported-retention')

    def test_one_selected_exec_required(self):
        self.run_group('selected-exec')

    def test_late_records_retained_before_refusal(self):
        self.run_group('late-retention')

    def test_writer_failure_preserves_confirmed_prefix(self):
        self.run_group('writer-prefix')

    def test_fixed_images_factory_balances_one_two_and_max_images(self):
        self.run_group('images-success')

    def test_images_overlap_missing_extra_and_bound_refuse(self):
        self.run_group('images-refusals')

    def test_images_keep_drop_unsupported_and_late_failures(self):
        self.run_group('images-fail-closed')

    def test_fixed_factory_binding_ready_owner_and_deadline_matrix(self):
        self.run_group('profile-factories')

    def test_recipe_factory_uses_exact_v2_program_and_rejects_changed_start_binding(self):
        self.run_group('program-binding')


if __name__ == '__main__':
    unittest.main()
