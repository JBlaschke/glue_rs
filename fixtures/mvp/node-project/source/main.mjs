import assert from 'node:assert/strict';
import dep from 'dep';
assert.equal((await import('dep')).default,dep);assert.equal((await import('./dep-alias/index.js')).default,dep);assert.equal(dep.answer,42);
assert.equal(process.argv[2],'argument with spaces');
console.log(JSON.stringify({language:'node',entry:'esm',answer:dep.answer,asset:dep.asset,argument:process.argv[2]}));
