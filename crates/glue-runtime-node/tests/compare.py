#!/usr/bin/env python3
"""Run one graph in stock Node and verified archive hooks, then compare stdout."""
import argparse, json, os, shutil, subprocess, tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser();p.add_argument('--node',required=True,type=Path);p.add_argument('--pack',required=True,type=Path);p.add_argument('--bridge',required=True,type=Path);args=p.parse_args()
 env={'PATH':'/no-tools','HOME':'/no-home','TMPDIR':'/no-temp','NODE_DISABLE_COMPILE_CACHE':'1'}
 with tempfile.TemporaryDirectory(prefix='glue-node-compare-') as temp:
  temp=Path(temp);src=temp/'source';src.mkdir();dest=temp/'relocated space é';dest.mkdir();empty=temp/'empty';empty.mkdir()
  sources={
   'main.cjs':'''const assert=require('node:assert/strict');const a=require('./cycle-a');assert.equal(a.name,'a');assert.equal(a.peer,'b');assert.equal(a,require('./cycle-a'));assert.equal(require('dual').mode,'require');assert.equal(require('dual/feature/answer'),42);assert.equal(require('a'),'one');assert.equal(require('b'),'two');assert.equal(require('#local').answer,42);assert.throws(()=>require('dual/blocked'),{code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});assert.throws(()=>require('missing-global'),{code:'MODULE_NOT_FOUND'});(async()=>{assert.equal((await import('dual')).default.mode,'import');console.log(JSON.stringify({entry:'cjs',cycle:true,cache:true,dual:true,wildcard:true,versions:true,imports:true,blocked:true}));})().catch(e=>{console.error(e);process.exitCode=1;});''',
   'main.mjs':'''import assert from 'node:assert/strict';import dual from 'dual';import data from './data.json' with {type:'json'};import a from 'a';import b from 'b';assert.equal(dual.mode,'import');assert.equal(data.answer,42);assert.equal(a,'one');assert.equal(b,'two');assert.equal((await import('dual')).default,dual);await assert.rejects(import('dual/blocked'),{code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});await assert.rejects(import('./cycle-a'),{code:'ERR_MODULE_NOT_FOUND'});console.log(JSON.stringify({entry:'esm',json:true,dual:true,versions:true,cache:true,blocked:true,strict_relative:true}));''',
   'cycle-a.js':"exports.name='a';exports.peer=require('./cycle-b').name;",'cycle-b.js':"exports.name='b';require('./cycle-a');",'data.json':'{"answer":42}',
   'node_modules/dual/r.cjs':"module.exports={mode:'require'};",'node_modules/dual/i.mjs':"export default {mode:'import'};",'node_modules/dual/features/answer.cjs':'module.exports=42;',
   'node_modules/a/index.js':"module.exports=require('dep');",'node_modules/b/index.js':"module.exports=require('dep');",'node_modules/a/node_modules/dep/index.js':"module.exports='one';",'node_modules/b/node_modules/dep/index.js':"module.exports='two';"
  }
  packages={
   '':{'name':'root','type':'commonjs','imports':{'#local':'./data.json'},'dependencies':{'dual':'node_modules/dual','a':'node_modules/a','b':'node_modules/b'}},
   'node_modules/dual':{'name':'dual','type':'commonjs','exports':{'.':{'import':'./i.mjs','require':'./r.cjs'},'./feature/*':'./features/*.cjs','./blocked':None},'dependencies':{}},
   'node_modules/a':{'name':'a','type':'commonjs','dependencies':{'dep':'node_modules/a/node_modules/dep'}},'node_modules/b':{'name':'b','type':'commonjs','dependencies':{'dep':'node_modules/b/node_modules/dep'}},
   'node_modules/a/node_modules/dep':{'name':'dep','type':'commonjs','dependencies':{}},'node_modules/b/node_modules/dep':{'name':'dep','type':'commonjs','dependencies':{}}
  }
  for name,text in sources.items():(src/name).parent.mkdir(parents=True,exist_ok=True);(src/name).write_text(text)
  for root,pkg in packages.items():
   metadata=dict(pkg);metadata['dependencies']={name:'1.0.0' for name in pkg['dependencies']};(src/root/'package.json').write_text(json.dumps(metadata))
  index={'schema_version':1,'entry':'main.cjs','files':{name:{'resource':name,'format':'module' if name.endswith('.mjs') else 'json' if name.endswith('.json') else 'commonjs'}for name in sources},'packages':packages}
  references={}
  for entry in ['main.cjs','main.mjs']:
   run=subprocess.run([str(args.node.resolve()),str(src/entry)],env=env,cwd=empty,text=True,capture_output=True,timeout=30);assert run.returncode==0,run.stderr;references[entry]=run.stdout
   index['entry']=entry;(src/'module-index.json').write_text(json.dumps(index));subprocess.run([str(args.pack.resolve()),str(src),str(dest/(entry+'.glue'))],check=True)
  shutil.rmtree(src)
  shutil.copyfile(args.bridge,dest/'archive.node')
  for file in ['bootstrap.cjs','resolver.cjs','resources.cjs']:shutil.copyfile(HERE.parent/'support'/file,dest/file)
  for entry in references:
   run=subprocess.run([str(args.node.resolve()),str(dest/'bootstrap.cjs'),str(dest/(entry+'.glue')),str(dest/'archive.node')],env=env,cwd=empty,text=True,capture_output=True,timeout=30)
   assert run.returncode==0,run.stderr
   assert run.stdout==references[entry],(run.stdout,references[entry])
   print(run.stdout.strip())
  print('stock/archive outputs equal; actual source removed before archive execution')
if __name__=='__main__':main()
