import assert from 'node:assert/strict';
import value from 'probe-package';
import data from './config.json' with { type: 'json' };
import { value as answer } from './value.mjs';
assert.equal(value.mode,'import');
assert.equal(data.answer,answer);
assert.equal((await import('./value.mjs')).value,42);
assert.equal(glueResources.read('asset.txt').toString(),'archived resource\n');
console.log(JSON.stringify({case:'esm',package_exports:true,json:true,resource:true,relative:true,dynamic_import:true}));
