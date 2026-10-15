'use strict';
// Test layout preparation copies independently built inputs; it never compiles.
const fs=require('node:fs');const path=require('node:path');
const source=process.argv[2],project=process.argv[3];
const destination=path.join(project,'node_modules/prepared');fs.mkdirSync(destination,{recursive:true});
for(const entry of fs.readdirSync(source,{withFileTypes:true})){if(!entry.isFile())throw Error('native fixture must contain regular files');fs.copyFileSync(path.join(source,entry.name),path.join(destination,entry.name));}
fs.writeFileSync(path.join(destination,'package.json'),JSON.stringify({name:'prepared',version:'1.0.0',main:'addon.node'}));
