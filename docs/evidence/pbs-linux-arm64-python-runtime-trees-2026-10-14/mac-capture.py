import hashlib, json, os, shutil, subprocess, sys
from pathlib import Path
repo=Path.cwd(); dest=Path(sys.argv[1]).absolute(); glue=repo/'target/python-runtime-trees-mac-build/debug/glue'
assert not dest.exists(); dest.mkdir()
def identity(p):
 b=p.read_bytes();return {'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def call(name,args):
 p=subprocess.run(list(map(str,args)),capture_output=True)
 (dest/(name+'.stdout.txt')).write_bytes(p.stdout);(dest/(name+'.stderr.txt')).write_bytes(p.stderr)
 (dest/(name+'.exit-status.txt')).write_text(str(p.returncode)+'\n')
 (dest/(name+'.command.json')).write_text(json.dumps(list(map(str,args)),indent=2)+'\n')
 assert p.returncode==0,(name,p.stderr.decode());return p
before={'commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),'status':subprocess.check_output(['git','status','--porcelain'],text=True),'diff':subprocess.check_output(['git','diff','--binary'],text=True)}
install=repo/'target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-install_only.tar.gz'
full=repo/'target/pbs-inspection/cpython-3.13.16+20261009-aarch64-unknown-linux-gnu-pgo+lto-full.tar.zst'
call('uv-install',[sys.executable,'-B',repo/'fixtures/python-runtime-trees/prepare.py','install','--uv','/opt/homebrew/Cellar/uv/0.12.23/bin/uv','--pbs-install-only',install,'--output',dest/'uv-input','--remove-bin'])
root=dest/'uv-input/install/cpython-3.13.16-linux-aarch64-gnu'; prefix=dest/'prepared prefix'
call('host',[glue,'python-host','--provider','host-install','--runtime-tree',root,'--output',prefix,'--json'])
call('host-audit',[sys.executable,'-B',repo/'fixtures/python-runtime-trees/prepare.py','audit-output','--runtime-tree',root,'--prefix',prefix,'--report',dest/'host.stdout.txt','--output',dest/'host-audit.json'])
call('tree-controls',[sys.executable,'-B',repo/'fixtures/python-runtime-trees/prepare.py','controls','--glue',glue,'--runtime-tree',root,'--output',dest/'tree-controls'])
source=repo/'target/python-real-package-clean-build/installed-packages'
shutil.copytree(source,dest/'installed-packages',symlinks=True)
shutil.rmtree(dest/'installed-packages/venv/bin')
assert not (dest/'installed-packages/venv/bin').exists()
archives={}; templates={}
for mode in ['bundled','host','install-host']:
 if mode=='bundled': args=['--provider','bundled','--pbs-full',full,'--frozen-bootstrap',repo/'docs/evidence/pbs-linux-arm64-python-real-packages-2026-10-14/freeze-bundle.json']
 else: args=['--provider','host-full' if mode=='host' else 'host-install','--host-prefix','/build-target/host Python metadata' if mode=='host' else '/build-target/install Python metadata']
 template=dest/('template-'+mode)
 call(mode+'.template',[glue,'python-template',*args,'--output',template,'--json'])
 archive=dest/(mode+'.glue')
 call(mode+'.build',[glue,'build-python','--provider-template',template/'manifest.json','--provider-root',template/'root','--app',dest/'installed-packages/application','--venv',dest/'installed-packages/venv','--app-id','python.real-packages','--entry','app/main.py','--output',archive,'--json'])
 call(mode+'.product-audit',[sys.executable,'-B',repo/'fixtures/python-real-packages/prepare.py','audit-build',dest/(mode+'.build.stdout.txt'),archive,'--provenance',dest/'installed-packages/installation-provenance.json'])
 previous=repo/'target/python-real-package-clean-build/relocated Python metadata'/archive.name
 assert identity(archive)==identity(previous),mode
 archives[mode]=identity(archive);templates[mode]=identity(template/'manifest.json')
receipt={'source':before,'launcher':identity(glue),'archives':archives,'templates':templates,'same_previous_archives':True,'input_interpreter_directory_absent':not(root/'bin').exists(),'package_interpreter_directory_absent':not(dest/'installed-packages/venv/bin').exists()}
(dest/'capture.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps({'archives':archives,'same_previous_archives':True,'input_interpreters_absent':True}))
