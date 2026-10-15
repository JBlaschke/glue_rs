const assert = require('node:assert/strict');
const a = require('./cached.cjs');
assert.equal(a, require('./cached.cjs'));
assert.equal(a.count, 1);
assert.equal(require('probe-package').mode, 'require');
assert.throws(()=>require('probe-package/private'), {code:'ERR_PACKAGE_PATH_NOT_EXPORTED'});
assert.deepEqual(require('./config.json'), {answer:42});
assert.equal(glueResources.read('asset.txt').toString(), 'archived resource\n');
(async () => {
  assert.equal((await import('./value.mjs')).value,42);
  console.log(JSON.stringify({case:'cjs',cache:true,package_exports:true,json:true,resource:true,dynamic_import:true}));
})();
