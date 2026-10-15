'use strict';
// Spike hook: N02 expands resolution semantics; no source reads use host fs.
const { registerHooks, isBuiltin, createRequire } = require('node:module');
const { pathToFileURL, fileURLToPath } = require('node:url');
const path = require('node:path');
if (typeof registerHooks !== 'function') throw Error('ERR_GLUE_HOOKS: Node synchronous module hooks unavailable');
if (Number(process.versions.napi) < 8) throw Error('ERR_GLUE_NODE_API: Node-API 8 required');
const archivePath = path.resolve(process.argv[2]);
const bridge = require(path.resolve(process.argv[3]));
const archive = bridge.open(archivePath);
const read = resource => bridge.read(archive, resource);
const index = JSON.parse(read('module-index.json'));
if (index.schema_version !== 1) throw Error('ERR_GLUE_INDEX: unsupported index');
const prefix = 'file:///__glue_archive__/';
function canonical(value) {
  if (!value || value.startsWith('/') || value.split('/').some(p => !p || p === '.' || p === '..') || value.includes('\\') || value.includes('\0')) throw Error('ERR_GLUE_PATH: invalid logical path');
  return value;
}
for (const [name, item] of Object.entries(index.files)) {
  canonical(name);
  canonical(item.format === 'addon' ? item.deployed : item.resource);
}
function record(logical) {
  const item = index.files[logical];
  if (!item) throw Object.assign(Error(`Cannot find module ${logical}`), {code:'MODULE_NOT_FOUND'});
  if (item.format === 'addon') {
    if (Number(process.versions.napi) < item.node_api) throw Error('ERR_GLUE_NODE_API: incompatible addon');
    return {url:pathToFileURL(path.join(path.dirname(archivePath), item.deployed)).href, shortCircuit:true};
  }
  return {url:prefix + logical.split('/').map(encodeURIComponent).join('/'), format:item.format, shortCircuit:true};
}
function packageAt(logical) {
  return Object.keys(index.packages).filter(p => p === '' || logical.startsWith(p + '/')).sort((a,b) => b.length-a.length)[0];
}
function target(value, conditions) {
  if (typeof value === 'string') return value;
  if (value && !Array.isArray(value) && typeof value === 'object') {
    for (const [condition, next] of Object.entries(value)) if (condition === 'default' || conditions.includes(condition)) { const selected = target(next, conditions); if (selected) return selected; }
  }
  return null;
}
function resolveLogical(specifier, parent, conditions) {
  if (specifier.startsWith('./') || specifier.startsWith('../')) {
    const name = path.posix.normalize(path.posix.join(path.posix.dirname(parent), specifier));
    canonical(name);
    for (const candidate of [name, ...(['.js','.json','.node'].map(e=>name+e)), name+'/index.js']) if (index.files[candidate]) return record(candidate);
    return record(name);
  }
  const owner = packageAt(parent);
  const parts = specifier.split('/');
  const name = parts[0].startsWith('@') ? parts.splice(0,2).join('/') : parts.shift();
  const root = index.packages[owner]?.dependencies[name];
  if (root === undefined) throw Object.assign(Error(`Undeclared dependency ${specifier}`),{code:'MODULE_NOT_FOUND'});
  const pkg = index.packages[root];
  const subpath = parts.length ? './'+parts.join('/') : '.';
  if (pkg.exports !== undefined) {
    const exports = pkg.exports;
    const mapped = typeof exports === 'object' && exports !== null && Object.keys(exports).some(k=>k.startsWith('.')) ? exports[subpath] : subpath === '.' ? exports : null;
    const selected = target(mapped, conditions);
    if (!selected?.startsWith('./')) throw Object.assign(Error(`Package subpath ${subpath} is not exported`),{code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
    return record(path.posix.join(root, selected));
  }
  return record(path.posix.join(root, parts.length ? parts.join('/') : pkg.main || 'index.js'));
}
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (isBuiltin(specifier)) return nextResolve(specifier, context);
    if (specifier.startsWith('/__glue_archive__/')) return record(specifier.slice('/__glue_archive__/'.length));
    if (specifier.startsWith(prefix)) return record(decodeURIComponent(specifier.slice(prefix.length)));
    if (context.parentURL?.startsWith(prefix)) return resolveLogical(specifier, decodeURIComponent(context.parentURL.slice(prefix.length)), context.conditions);
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (!url.startsWith(prefix)) return nextLoad(url, context);
    const logical = decodeURIComponent(url.slice(prefix.length));
    const file = index.files[logical];
    if (!file || file.format === 'addon') throw Error('ERR_GLUE_INDEX: invalid source');
    return {format:file.format, source:read(file.resource), shortCircuit:true};
  }
});
Object.defineProperty(globalThis, 'glueResources', {value:Object.freeze({read})});
(async () => {
  const entry = index.entry;
  const result = record(entry);
  process.argv = [process.execPath, fileURLToPath(result.url), ...process.argv.slice(4)];
  if (index.files[entry].format === 'commonjs') createRequire(__filename)(fileURLToPath(result.url));
  else await import(result.url);
})().catch(error => { console.error(error); process.exitCode = 1; });
