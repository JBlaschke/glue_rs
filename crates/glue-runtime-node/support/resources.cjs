'use strict';
const fs=require('node:fs');
const promises=require('node:fs/promises');
const {fileURLToPath}=require('node:url');
const {Readable}=require('node:stream');
const {syncBuiltinESMExports}=require('node:module');
const ROOT='/__glue_archive__';
function failure(code,syscall,path,message=code){return Object.assign(Error(`${code}: ${message}, ${syscall} '${path}'`),{code,syscall,path});}
function installResources({read,list,deployed={},aliases={}}) {
 const unalias=require('./resolver.cjs').createAliasResolver(aliases);
 const hostRead=fs.readFileSync;
 const archiveRead=read;read=name=>{name=unalias(name);return Object.hasOwn(deployed,name)?hostRead(deployed[name]):archiveRead(name);};
 const names=[...new Set([...JSON.parse(list()),...Object.keys(deployed),...Object.keys(aliases)])];
 function exists(name){name=unalias(name);return sizes.has(name)||directories.has(name);}
 const sizes=new Map();const directories=new Map([['',new Map()]]);
 for(const name of names){let parent='';const parts=name.split('/');for(let i=0;i<parts.length;i++){const dir=i<parts.length-1;directories.get(parent).set(parts[i],{directory:dir,name:parts[i],path:parent,link:i===parts.length-1&&Object.hasOwn(aliases,name)});parent=parent?parent+'/'+parts[i]:parts[i];if(dir&&!directories.has(parent))directories.set(parent,new Map());}sizes.set(name,null);}
 function virtual(input) {
  let value=input;
  if(value instanceof URL){if(value.protocol!=='file:')return null;value=fileURLToPath(value);}
  if(Buffer.isBuffer(value))value=value.toString();
  if(typeof value!=='string'||(value!==ROOT&&!value.startsWith(ROOT+'/')))return null;
  const name=value.slice(ROOT.length).replace(/^\//,'');
  if(name.split('/').some(p=>p==='.'||p==='..')||name.includes('\\')||name.includes('\0'))throw failure('EPERM','resolve',value,'virtual path traversal denied');
  return name.replace(/\/$/,'');
 }
 function bytes(name,syscall='readFile') {
  name=unalias(name);
  if(directories.has(name))throw failure('EISDIR',syscall,ROOT+'/'+name,'illegal operation on a directory');
  if(!sizes.has(name))throw failure('ENOENT',syscall,ROOT+'/'+name,'no such archived file');
  const result=read(name);sizes.set(name,result.length);return result;
 }
 function stat(name,options={},follow=true) {
  const link=!follow&&Object.hasOwn(aliases,name)?aliases[name]:null;
  if(!link)name=unalias(name);
  const directory=directories.has(name);
  if(!directory&&!sizes.has(name))throw failure('ENOENT','stat',ROOT+'/'+name,'no such archived file');
  const size=link?link.link_size:directory?0:(sizes.get(name)??bytes(name,'stat').length);
  const integer=n=>options?.bigint?BigInt(n):n;
  return {dev:integer(0),ino:integer(0),mode:integer((link?0o120000:directory?0o40000:0o100000)|0o444|(directory?0o111:0)),nlink:integer(1),uid:integer(0),gid:integer(0),rdev:integer(0),size:integer(size),blksize:integer(4096),blocks:integer(Math.ceil(size/512)),atimeMs:integer(0),mtimeMs:integer(0),ctimeMs:integer(0),birthtimeMs:integer(0),atime:new Date(0),mtime:new Date(0),ctime:new Date(0),birthtime:new Date(0),...(options?.bigint?{atimeNs:0n,mtimeNs:0n,ctimeNs:0n,birthtimeNs:0n}:{}),isFile:()=>!link&&!directory,isDirectory:()=>!link&&directory,isSymbolicLink:()=>!!link,isSocket:()=>false,isFIFO:()=>false,isBlockDevice:()=>false,isCharacterDevice:()=>false};
 }
 function options(value){return typeof value==='string'?{encoding:value}:value||{};}
 function decode(buffer,encoding){return encoding&&encoding!=='buffer'?buffer.toString(encoding):buffer;}
 function readFile(name,opts){opts=options(opts);if(opts.signal?.aborted)throw Object.assign(Error('The operation was aborted'),{name:'AbortError',code:'ABORT_ERR'});if(opts.flag&&opts.flag!=='r'&&opts.flag!=='rs')throw failure('EROFS','readFile',ROOT+'/'+name,'read-only archive');return decode(bytes(name),opts.encoding);}
 function readdir(name,opts){opts=options(opts);name=unalias(name);const children=directories.get(name);if(!children){if(sizes.has(name))throw failure('ENOTDIR','scandir',ROOT+'/'+name);throw failure('ENOENT','scandir',ROOT+'/'+name);}if(opts.recursive)throw failure('ENOTSUP','scandir',ROOT+'/'+name,'recursive readdir is unsupported');return [...children.values()].sort((a,b)=>a.name.localeCompare(b.name,'en')).map(child=>{const value=opts.encoding==='buffer'?Buffer.from(child.name):child.name;if(!opts.withFileTypes)return value;return {name:value,path:ROOT+'/'+name,parentPath:ROOT+'/'+name,isFile:()=>!child.link&&!child.directory,isDirectory:()=>!child.link&&child.directory,isSymbolicLink:()=>!!child.link,isSocket:()=>false,isFIFO:()=>false,isBlockDevice:()=>false,isCharacterDevice:()=>false};});}
 function stream(name,opts={}) {
  opts=options(opts);if(opts.fd!==undefined)throw failure('ENOTSUP','open',ROOT+'/'+name,'virtual file descriptors are unsupported');
  if(opts.flags&&opts.flags!=='r'&&opts.flags!=='rs')throw failure('EROFS','open',ROOT+'/'+name,'read-only archive');
  const start=opts.start??0,end=opts.end??Infinity;
  if(!Number.isSafeInteger(start)||start<0||!(end===Infinity||Number.isSafeInteger(end))||end<start)throw Object.assign(new RangeError('invalid stream range'),{code:'ERR_OUT_OF_RANGE'});
  let data,offset=start;
  const result=new Readable({highWaterMark:opts.highWaterMark,encoding:opts.encoding,signal:opts.signal,emitClose:opts.emitClose??true,read(size){try{if(data===undefined)data=bytes(name,'open');const limit=Math.min(data.length,end===Infinity?Infinity:end+1);if(offset>=limit){this.push(null);return;}const next=Math.min(limit,offset+Math.max(size,1));const chunk=data.subarray(offset,next);offset=next;this.bytesRead+=chunk.length;this.push(chunk);}catch(error){this.destroy(error);}}});
  result.path=ROOT+'/'+name;result.bytesRead=0;result.pending=false;return result;
 }
 const saved=[];
 function replace(object,name,fn){if(typeof object[name]!=='function')return;saved.push([object,name,object[name]]);Object.assign(fn,object[name]);object[name]=fn;}
 function readMethod(name,fn){const sync=fs[name+'Sync'],callback=fs[name],promise=promises[name];
  replace(fs,name+'Sync',function(input,...rest){const p=virtual(input);return p===null?sync.call(this,input,...rest):fn(p,...rest);});
  replace(fs,name,function(input,...rest){const p=virtual(input);if(p===null)return callback.call(this,input,...rest);const cb=rest.pop();if(typeof cb!=='function')throw new TypeError('callback must be a function');process.nextTick(()=>{let value;try{value=fn(p,...rest);}catch(error){cb(error);return;}cb(null,value);});});
  replace(promises,name,async function(input,...rest){const p=virtual(input);return p===null?promise.call(this,input,...rest):fn(p,...rest);});
 }
 readMethod('readFile',readFile);readMethod('stat',stat);readMethod('lstat',(name,opts)=>stat(name,opts,false));readMethod('readdir',readdir);
 readMethod('access',(name,mode=fs.constants.F_OK)=>{stat(name);if(mode&(fs.constants.W_OK|fs.constants.X_OK))throw failure('EROFS','access',ROOT+'/'+name);});
 const realExists=fs.existsSync;replace(fs,'existsSync',function(input){try{const name=virtual(input);return name===null?realExists.call(this,input):exists(name);}catch{return false;}});
 const realExistsAsync=fs.exists;replace(fs,'exists',function(input,callback){let name;try{name=virtual(input);}catch{process.nextTick(()=>callback(false));return;}if(name===null)return realExistsAsync.call(this,input,callback);process.nextTick(()=>callback(exists(name)));});
 const realStream=fs.createReadStream;replace(fs,'createReadStream',function(input,...rest){const name=virtual(input);return name===null?realStream.call(this,input,...rest):stream(name,...rest);});
 const writes=['writeFile','appendFile','truncate','unlink','rm','rmdir','mkdir','rename','copyFile','cp','symlink','link','chmod','chown','utimes','lchmod','lchown','lutimes','mkdtemp','createWriteStream'];
 const unsupported=['open','opendir','readlink','realpath','watch','watchFile','unwatchFile','statfs'];
 for(const name of [...writes,...unsupported])for(const [object,key,style]of [[fs,name+'Sync','sync'],[fs,name,'callback'],[promises,name,'promise']]){
  const original=object[key];const multi=['rename','copyFile','cp','symlink','link'].includes(name);
  replace(object,key,function(...args){let found;for(const arg of args.slice(0,multi?2:1)){const candidate=virtual(arg);if(candidate!==null){found=candidate;break;}}if(found===undefined)return original.apply(this,args);const err=failure(writes.includes(name)?'EROFS':'ENOTSUP',name,ROOT+'/'+found,'operation unsupported on read-only archive');if(style==='promise')return Promise.reject(err);if(style==='callback'&&!['createWriteStream','watch','watchFile','unwatchFile'].includes(name)){const callback=args.at(-1);if(typeof callback!=='function')throw new TypeError('callback must be a function');process.nextTick(()=>callback(err));return;}throw err;});
 }
 syncBuiltinESMExports();
 return Object.freeze({root:ROOT,read,stat:path=>stat(path),list:()=>names.slice(),createReadStream:stream,restore(){for(const [object,key,value]of saved.reverse())object[key]=value;syncBuiltinESMExports();}});
}
module.exports={installResources,ROOT};
