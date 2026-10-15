#!/usr/bin/env python3
"""Bounded N00 recipe. Produces local evidence, never pretends absent cells ran."""
import argparse, hashlib, json, os, platform, shutil, subprocess, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

def identity(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--node', type=Path, action='append', required=True)
    p.add_argument('--pack', type=Path, required=True)
    p.add_argument('--bridge', type=Path, required=True)
    p.add_argument('--native-dir', type=Path)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir()  # never overwrite evidence
    deploy = output / 'relocated space é'
    deploy.mkdir()
    shutil.copyfile(args.bridge, deploy / 'archive.node')
    shutil.copyfile(HERE / 'bootstrap.cjs', deploy / 'bootstrap.cjs')
    native = []
    with tempfile.TemporaryDirectory(prefix='glue-node-input-') as scratch:
        source = Path(scratch) / 'project'
        shutil.copytree(HERE / 'fixtures/project', source)
        if args.native_dir:
            (deploy / 'native').mkdir()
            for file in sorted(args.native_dir.resolve().iterdir()):
                if not file.is_file() or file.is_symlink(): raise ValueError('native input must be ordinary files')
                original = identity(file)
                target = deploy / 'native' / file.name
                shutil.copyfile(file,target)
                assert identity(file)['sha256'] == identity(target)['sha256']
                native.append({"input":original,"output":identity(target)})
            (source / 'native.cjs').write_text("const assert=require('node:assert/strict'); const a=require('./addon.node'); assert.equal(a,require('./addon.node')); assert.equal(a.answer(),42); console.log(JSON.stringify({case:'native',answer:42,cache:true}));\n")
            index = json.loads((source / 'module-index.json').read_text())
            index['files']['native.cjs'] = {"resource":"native.cjs","format":"commonjs"}
            index['files']['addon.node'] = {"deployed":"native/addon.node","format":"addon","node_api":8}
            (source / 'module-index.json').write_text(json.dumps(index))
        subprocess.run([str(args.pack.resolve()),str(source),str(deploy/'app.glue')],check=True)
        shutil.rmtree(source)
        assert not source.exists()
        source_path = str(source)
    for file in deploy.rglob('*'):
        if file.is_file(): file.chmod(0o444)
    runs=[]
    empty = output / 'empty-cwd'
    empty.mkdir()
    clean_env={"PATH":"/glue-no-tools","HOME":"/glue-no-home","TMPDIR":"/glue-no-temp","NODE_DISABLE_COMPILE_CACHE":"1","NODE_PATH":""}
    for executable in args.node:
        executable = executable.resolve()
        probe=subprocess.run([str(executable),'-p','JSON.stringify({version:process.version,versions:process.versions,platform:process.platform,arch:process.arch,registerHooks:typeof require("node:module").registerHooks})'],env=clean_env,cwd=empty,text=True,capture_output=True,check=True)
        runtime=json.loads(probe.stdout)
        for case in ['bridge','entry.cjs','entry.mjs']+(['native.cjs'] if args.native_dir else []):
            command=([str(executable),'--expose-gc',str(HERE/'test-bridge.cjs'),str(deploy/'archive.node'),str(deploy/'app.glue')] if case=='bridge' else [str(executable),str(deploy/'bootstrap.cjs'),str(deploy/'app.glue'),str(deploy/'archive.node'),case])
            run=subprocess.run(command,env=clean_env,cwd=empty,text=True,capture_output=True,timeout=30)
            runs.append({"case":case,"runtime":runtime,"runtime_identity":identity(executable),"command":command,"exit":run.returncode,"stdout":run.stdout,"stderr":run.stderr})
    receipt={"task":"N00","host":{"system":platform.system(),"machine":platform.machine(),"release":platform.release()},"source_removed":True,"source_path":source_path,"compile_cache_disabled":True,"payload_read_only":True,"native_inputs":native,"runs":runs,"checks":{"all_cases_passed":all(x['exit']==0 for x in runs),"two_major_lines":len({x['runtime']['version'].split('.')[0] for x in runs})>=2,"linux_and_macos":False},"limits":["This recipe does not trace extraction or bundle the runtime; N01/R02 own those checks.","N00 hooks implement only this spike corpus; N02 owns general package resolution."]}
    (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({"receipt":str(output/'receipt.json'),"checks":receipt['checks']}))
    if not receipt['checks']['all_cases_passed']: raise SystemExit(1)

if __name__=='__main__': main()
