'use strict';
const path = require('node:path').posix;
const { isBuiltin } = require('node:module');
const { pathToFileURL } = require('node:url');
const PREFIX = 'file:///__glue_archive__/';
const ABS = '/__glue_archive__/';
function fail(code,message) { throw Object.assign(Error(message),{code}); }
function canonical(name,empty=false) {
  if ((name===''&&empty)) return name;
  if(typeof name!=='string'||!name||name.startsWith('/')||name.includes('\\')||name.includes('\0')||name.split('/').some(p=>!p||p==='.'||p==='..')) fail('ERR_GLUE_PATH',`Invalid logical path ${name}`);
  return name;
}
function createResolver(index,distributionRoot) {
  index={...index,files:Object.assign(Object.create(null),index.files),packages:Object.assign(Object.create(null),index.packages)};
  if(index.schema_version!==1 || !index.files || !index.packages) fail('ERR_GLUE_INDEX','Unsupported module index');
  for(const [name,file] of Object.entries(index.files)) {
    canonical(name);canonical(file.format==='addon'?file.deployed:file.resource);
    if(!['commonjs','module','json','addon'].includes(file.format)) fail('ERR_GLUE_INDEX',`Invalid format ${name}`);
    if(file.format==='addon'&&(!Number.isSafeInteger(file.node_api)||file.node_api<1)) fail('ERR_GLUE_INDEX','Invalid addon minimum Node-API');
  }
  const roots=Object.keys(index.packages).sort((a,b)=>b.length-a.length);
  for(const root of roots) {
    canonical(root,true);
    const pkg=index.packages[root];
    pkg.dependencies=Object.assign(Object.create(null),pkg.dependencies);
    if(!pkg.dependencies||!['module','commonjs'].includes(pkg.type))fail('ERR_GLUE_INDEX','Invalid package record');
    for(const target of Object.values(pkg.dependencies)) if(!Object.hasOwn(index.packages,target))fail('ERR_GLUE_INDEX',`Missing dependency package ${target}`);
  }
  canonical(index.entry);
  if(!Object.hasOwn(index.files,index.entry))fail('ERR_GLUE_INDEX','Entry absent from module index');
  const directories=new Set();for(const name of Object.keys(index.files)){let parent=path.dirname(name);while(parent!=='.'){directories.add(parent);parent=path.dirname(parent);}}
  function owner(name) {return roots.find(root=>root===''||name.startsWith(root+'/'));}
  function url(name) {return PREFIX+canonical(name).split('/').map(encodeURIComponent).join('/');}
  function logical(value) {
    if(value.startsWith(PREFIX)) {
      if(/%2f|%5c/i.test(value))fail('ERR_INVALID_MODULE_SPECIFIER','Encoded separator in archive URL');
      let name;try{name=decodeURIComponent(value.slice(PREFIX.length));}catch{fail('ERR_INVALID_MODULE_SPECIFIER','Malformed archive URL');}
      return canonical(name);
    }
    if(value.startsWith(ABS))return canonical(value.slice(ABS.length));
    return null;
  }
  function record(name) {
    const file=index.files[name];
    if(!file)fail('MODULE_NOT_FOUND',`Cannot find archived module ${name}`);
    if(file.format==='addon') {
      if(Number(process.versions.napi)<file.node_api)fail('ERR_GLUE_NODE_API',`Addon ${name} requires Node-API ${file.node_api}`);
      return {url:pathToFileURL(require('node:path').join(distributionRoot,file.deployed)).href,shortCircuit:true};
    }
    return {url:url(name),format:file.format,shortCircuit:true};
  }
  function legacy(name,seen=new Set()) {
    if(index.files[name])return name;
    for(const ext of ['.js','.json','.node'])if(index.files[name+ext])return name+ext;
    if(seen.has(name))return null;seen.add(name);
    const pkg=index.packages[name];
    if(pkg?.main) {const found=legacy(path.join(name,pkg.main),seen);if(found)return found;}
    for(const ext of ['.js','.json','.node'])if(index.files[name+'/index'+ext])return name+'/index'+ext;
    return null;
  }
  const NO_MATCH=Symbol('no conditional match');
  function packageTarget(value,root,conditions,pattern,isImports) {
    if(value===null)return null;
    if(typeof value==='string') {
      if(pattern!==null)value=value.replaceAll('*',pattern);
      if(!value.startsWith('./')) {
        if(isImports && !value.startsWith('../') && !value.startsWith('/') && !value.startsWith('file:'))return {bare:value};
        fail('ERR_INVALID_PACKAGE_TARGET',`Package target ${value} must start with ./`);
      }
      const segments=value.slice(2).split('/');
      if(segments.some(p=>{try{p=decodeURIComponent(p);}catch{fail('ERR_INVALID_PACKAGE_TARGET','Invalid encoded package target');}return p==='..'||p==='.'||p==='node_modules'||/[\\/]/.test(p);}))fail('ERR_INVALID_PACKAGE_TARGET',`Package target escapes package: ${value}`);
      const result=path.join(root,value.slice(2));canonical(result);
      if(root && !result.startsWith(root+'/'))fail('ERR_INVALID_PACKAGE_TARGET','Target escapes package');
      return {logical:result};
    }
    if(Array.isArray(value)) {
      if(value.length===0)return null;
      let last=NO_MATCH;
      for(const item of value){try{const selected=packageTarget(item,root,conditions,pattern,isImports);if(selected!==NO_MATCH&&selected!==null)return selected;if(selected===null)last=null;}catch(e){if(e.code!=='ERR_INVALID_PACKAGE_TARGET')throw e;last=e;}}
      if(last instanceof Error)throw last;return last;
    }
    if(value&&typeof value==='object') {
      for(const [condition,item]of Object.entries(value)) {
        if(/^\d+$/.test(condition))fail('ERR_INVALID_PACKAGE_CONFIG','Numeric export condition');
        if(condition==='default'||conditions.includes(condition)){const selected=packageTarget(item,root,conditions,pattern,isImports);if(selected!==NO_MATCH)return selected;}
      }
      return NO_MATCH;
    }
    fail('ERR_INVALID_PACKAGE_TARGET','Invalid package target value');
  }
  function mapped(map,key,root,conditions,isImports) {
    if(!isImports && (typeof map==='string'||map===null||Array.isArray(map)))return key==='.'?packageTarget(map,root,conditions,null,false):NO_MATCH;
    if(!map||typeof map!=='object'||Array.isArray(map))fail('ERR_INVALID_PACKAGE_CONFIG','Invalid package imports/exports');
    const keys=Object.keys(map);
    if(!isImports) {
      const dots=keys.filter(k=>k.startsWith('.'));
      if(dots.length&&dots.length!==keys.length)fail('ERR_INVALID_PACKAGE_CONFIG','Mixed package export keys');
      if(!dots.length)return key==='.'?packageTarget(map,root,conditions,null,false):NO_MATCH;
    }
    if(Object.hasOwn(map,key)&&!key.includes('*'))return packageTarget(map[key],root,conditions,null,isImports);
    const matches=keys.filter(k=>k.includes('*')&&k.indexOf('*')===k.lastIndexOf('*')).map(k=>({key:k,prefix:k.slice(0,k.indexOf('*')),suffix:k.slice(k.indexOf('*')+1)})).filter(m=>key.startsWith(m.prefix)&&key.endsWith(m.suffix)&&key.length>=m.prefix.length+m.suffix.length).sort((a,b)=>b.prefix.length-a.prefix.length||b.key.length-a.key.length);
    if(!matches.length)return NO_MATCH;
    const match=matches[0];
    return packageTarget(map[match.key],root,conditions,key.slice(match.prefix.length,key.length-match.suffix.length),isImports);
  }
  function resolve(specifier,parentURL,conditions,depth=0) {
    if(depth>32)fail('ERR_INVALID_PACKAGE_CONFIG','Package imports cycle');
    if(isBuiltin(specifier))return {builtin:specifier};
    const direct=logical(specifier);if(direct!==null)return record(direct);
    const parent=logical(parentURL||'');
    if(parent===null)fail('ERR_GLUE_RESOLUTION','An archive parent URL is required');
    const root=owner(parent);const pkg=index.packages[root];
    if(specifier.startsWith('#')) {
      if(specifier==='#'||specifier.startsWith('#/'))fail('ERR_INVALID_MODULE_SPECIFIER','Invalid package import');
      const selected=mapped(pkg?.imports||{},specifier,root,conditions,true);
      if(selected===null||selected===NO_MATCH)fail('ERR_PACKAGE_IMPORT_NOT_DEFINED',`Package import ${specifier} is not defined`);
      return selected.bare?resolve(selected.bare,parentURL,conditions,depth+1):record(selected.logical);
    }
    if(specifier.startsWith('./')||specifier.startsWith('../')) {
      const name=path.normalize(path.join(path.dirname(parent),specifier));canonical(name);
      if(conditions.includes('require'))return record(legacy(name)||name);
      if(directories.has(name))fail('ERR_UNSUPPORTED_DIR_IMPORT',`Directory import ${specifier}`);
      return record(name);
    }
    if(specifier.startsWith('/')||specifier.includes(':')||specifier.startsWith('.'))fail('ERR_GLUE_RESOLUTION',`External module path is not packaged: ${specifier}`);
    const parts=specifier.split('/');
    const name=parts[0].startsWith('@')?parts.splice(0,2).join('/'):parts.shift();
    if(!name||name.endsWith('/')||parts.some(p=>p==='.'||p==='..'||!p))fail('ERR_INVALID_MODULE_SPECIFIER',`Invalid package specifier ${specifier}`);
    const dependency=pkg?.name===name&&pkg.exports!==undefined?root:pkg?.dependencies[name];
    if(dependency===undefined)fail('MODULE_NOT_FOUND',`Undeclared dependency ${specifier}`);
    const dep=index.packages[dependency];const subpath=parts.length?'./'+parts.join('/'):'.';
    if(dep.exports!==undefined) {
      const selected=mapped(dep.exports,subpath,dependency,conditions,false);
      if(selected===null||selected===NO_MATCH)fail('ERR_PACKAGE_PATH_NOT_EXPORTED',`Package subpath ${subpath} is not exported by ${name}`);
      return record(selected.logical);
    }
    const candidate=path.join(dependency,parts.length?parts.join('/'):dep.main||'index.js');
    return record(legacy(candidate)||candidate);
  }
  return Object.freeze({prefix:PREFIX,index,logical,url,record,resolve(specifier,parent,conditions){try{return resolve(specifier,parent,conditions);}catch(error){if(error.code==='MODULE_NOT_FOUND'&&!conditions.includes('require'))error.code='ERR_MODULE_NOT_FOUND';throw error;}}});
}
module.exports={createResolver,PREFIX};
