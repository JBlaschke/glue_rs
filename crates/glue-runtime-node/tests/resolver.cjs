'use strict';
const assert=require('node:assert/strict');
const {createResolver,createAliasResolver}=require('../support/resolver.cjs');
const files={};for(const [name,format]of Object.entries({'main.cjs':'commonjs','main.mjs':'module','x.js':'commonjs','directory/index.js':'commonjs','p/r.cjs':'commonjs','p/i.mjs':'module','p/features/a.js':'module','a/index.js':'commonjs','b/index.js':'commonjs','v1/index.js':'commonjs','v2/index.js':'commonjs'}))files[name]={resource:name,format};
const packages={
 '':{name:'root',type:'commonjs',imports:{'#x':'./x.js','#dependency':'dual','#missing':null},dependencies:{dual:'p',a:'a',b:'b'}},
 p:{name:'dual',type:'module',exports:{'.':{import:'./i.mjs',require:'./r.cjs'},'./feature/*':'./features/*.js','./blocked':null,'./invalid':'../outside.js'},dependencies:{}},
 a:{name:'a',type:'commonjs',dependencies:{dep:'v1'}},b:{name:'b',type:'commonjs',dependencies:{dep:'v2'}},
 v1:{name:'dep',type:'commonjs',dependencies:{}},v2:{name:'dep',type:'commonjs',dependencies:{}}
};
const aliases={link:{target:'x.js',directory:false,link_size:4},folder:{target:'p',directory:true,link_size:1}};
const r=createResolver({schema_version:1,entry:'main.cjs',files,packages,aliases},'/deployed');
const parent=r.url('main.cjs');const req=['node','require'];const imp=['node','import'];
assert.equal(r.resolve('dual',parent,req).format,'commonjs');
assert.equal(r.resolve('dual',parent,imp).format,'module');
assert.equal(r.resolve('dual/feature/a',parent,imp).url,r.url('p/features/a.js'));
assert.equal(r.resolve('dep',r.url('a/index.js'),req).url,r.url('v1/index.js'));
assert.equal(r.resolve('dep',r.url('b/index.js'),req).url,r.url('v2/index.js'));
assert.equal(r.resolve('#x',parent,req).url,r.url('x.js'));
assert.equal(r.resolve('#dependency',parent,req).url,r.url('p/r.cjs'));
assert.equal(r.resolve('dual',r.url('p/i.mjs'),imp).url,r.url('p/i.mjs'));
assert.equal(r.resolve('./x',parent,req).url,r.url('x.js'));
assert.equal(r.resolve('./directory',parent,req).url,r.url('directory/index.js'));
assert.throws(()=>r.resolve('./directory',parent,imp),{code:'ERR_UNSUPPORTED_DIR_IMPORT'});
assert.throws(()=>r.resolve('./x',parent,imp),{code:'ERR_MODULE_NOT_FOUND'});
assert.throws(()=>r.resolve('dual/blocked',parent,req),{code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
assert.throws(()=>r.resolve('dual/private',parent,imp),{code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
assert.throws(()=>r.resolve('dual/invalid',parent,req),{code:'ERR_INVALID_PACKAGE_TARGET'});
assert.throws(()=>r.resolve('#missing',parent,imp),{code:'ERR_PACKAGE_IMPORT_NOT_DEFINED'});
assert.throws(()=>r.resolve('undeclared',parent,req),{code:'MODULE_NOT_FOUND'});
assert.throws(()=>r.resolve('/tmp/host.js',parent,req),{code:'ERR_GLUE_RESOLUTION'});
assert.throws(()=>r.resolve('file:///tmp/host.js',parent,imp),{code:'ERR_GLUE_RESOLUTION'});
assert.throws(()=>r.resolve('file:///__glue_archive__/p%2fr.cjs',parent,req),{code:'ERR_INVALID_MODULE_SPECIFIER'});
assert.throws(()=>r.resolve('../../escape',parent,req),{code:'ERR_GLUE_PATH'});
assert.equal(r.resolve('./link',parent,req).url,r.url('x.js'));assert.equal(r.resolve('./folder/i.mjs',parent,imp).url,r.url('p/i.mjs'));assert.throws(()=>createAliasResolver({a:{target:'b',directory:true,link_size:1},b:{target:'a',directory:true,link_size:1}})('a'),{code:'ELOOP'});
console.log('resolver: 24 semantic checks passed');
