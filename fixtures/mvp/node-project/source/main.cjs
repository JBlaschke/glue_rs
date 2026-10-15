const assert=require('node:assert/strict');
const dep=require('dep');assert.equal(dep,require('dep'));assert.equal(dep,require('./dep-alias'));assert.equal(dep.answer,42);
assert.equal(process.argv[2],'argument with spaces');
console.log(JSON.stringify({language:'node',entry:'cjs',answer:dep.answer,asset:dep.asset,argument:process.argv[2]}));
