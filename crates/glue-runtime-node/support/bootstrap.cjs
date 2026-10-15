'use strict';
const { registerHooks, isBuiltin, createRequire } = require('node:module');
const { fileURLToPath } = require('node:url');
const path = require('node:path');
if(typeof registerHooks!=='function')throw Error('ERR_GLUE_HOOKS: synchronous Node hooks unavailable');
if(Number(process.versions.napi)<8)throw Error('ERR_GLUE_NODE_API: Node-API 8 required');
const archivePath=path.resolve(process.argv[2]);
const bridge=require(path.resolve(process.argv[3]));
const archive=bridge.open(archivePath);
const read=resource=>bridge.read(archive,resource);
const index=JSON.parse(read('module-index.json'));
const resolver=require('./resolver.cjs').createResolver(index,path.dirname(archivePath));
const deployed=Object.fromEntries(Object.entries(index.files).filter(([,f])=>f.format==='addon').map(([name,f])=>[name,path.join(path.dirname(archivePath),f.deployed)]));
const resources=require('./resources.cjs').installResources({read,list:()=>bridge.list(archive),deployed,aliases:index.aliases||{}});
registerHooks({
  resolve(specifier,context,nextResolve) {
    if(isBuiltin(specifier))return nextResolve(specifier,context);
    if(resolver.logical(specifier)!==null||context.parentURL?.startsWith(resolver.prefix)) {
      const result=resolver.resolve(specifier,context.parentURL,context.conditions);
      return result.builtin?nextResolve(result.builtin,context):result;
    }
    return nextResolve(specifier,context);
  },
  load(url,context,nextLoad) {
    const logical=resolver.logical(url);
    if(logical===null)return nextLoad(url,context);
    const file=index.files[logical];
    if(!file||file.format==='addon')throw Error('ERR_GLUE_INDEX: invalid source');
    return {format:file.format,source:read(file.resource),shortCircuit:true};
  }
});
Object.defineProperty(globalThis,'glueResources',{value:Object.freeze({root:resources.root,read:resources.read,list:resources.list,stat:resources.stat,createReadStream:resources.createReadStream})});
(async()=>{
  const entry=index.entry;const result=resolver.record(entry);
  process.argv=[process.execPath,fileURLToPath(result.url),...process.argv.slice(4)];
  if(index.files[entry].format==='commonjs')createRequire(__filename)(fileURLToPath(result.url));
  else await import(result.url);
})().catch(error=>{console.error(error);process.exitCode=1;});
