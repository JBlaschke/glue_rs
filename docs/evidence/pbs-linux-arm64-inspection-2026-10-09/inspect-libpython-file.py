import json,pathlib,struct,subprocess,tarfile,hashlib,collections
root=pathlib.Path(__file__).parent
import sys
path=pathlib.Path(sys.argv[1])
assert path.stat().st_size==95632430
with path.open('rb') as src: assert hashlib.file_digest(src,'sha256').hexdigest()=='8907ec2f181f0fc5cd08b9d897d36159432405af78f68f8faca728f48940e0ca'
proc=subprocess.Popen(['zstd','-dc',str(path)],stdout=subprocess.PIPE)
t=tarfile.open(fileobj=proc.stdout,mode='r|'); image=None; config=None
for member in t:
 if member.name=='python/install/lib/libpython3.13.so.1.0':image=t.extractfile(member).read()
 if member.name=='python/build/Modules/config.c':config=t.extractfile(member).read()
t.close();assert proc.wait()==0
assert image is not None and config is not None
# config.c stays in memory; only its digest is reported.
e=struct.unpack_from('<16sHHIQQQIHHHHHH',image)
assert e[0][:6]==b'\x7fELF\x02\x01' and e[1]==3 and e[2]==183
ph=[struct.unpack_from('<IIQQQQQQ',image,e[5]+i*e[9]) for i in range(e[10])]
sh=[struct.unpack_from('<IIQQQQIIQQ',image,e[6]+i*e[11]) for i in range(e[12])]
def segment(v,n=1):
 p=next(p for p in ph if p[0]==1 and p[3]<=v and v+n<=p[3]+p[5]);return p[2]+v-p[3]
def cstr(offset):
 end=image.index(b'\0',offset);return image[offset:end].decode('ascii')
def readptr(v):return struct.unpack_from('<Q',image,segment(v,8))[0]
shnames=sh[e[13]]
names=[cstr(shnames[4]+s[0]) for s in sh]
symbols={}
for i,s in enumerate(sh):
 if s[1] in [2,11]:
  strings=sh[s[6]]
  entries=[]
  for at in range(s[4],s[4]+s[5],s[9]):
   x=struct.unpack_from('<IBBHQQ',image,at);name=cstr(strings[4]+x[0]);v={'name':name,'info':x[1],'other':x[2],'section':x[3],'value':x[4],'size':x[5]};entries.append(v)
  symbols[i]=entries
dynindex=next(i for i,s in enumerate(sh) if s[1]==11)
dynsym=symbols[dynindex]; dynmap={x['name']:x for x in dynsym}
allmap={x['name']:x for table in symbols.values() for x in table}
rels={};types=collections.Counter()
for s in sh:
 if s[1]==4:
  for at in range(s[4],s[4]+s[5],s[9]):
   offset,info,addend=struct.unpack_from('<QQq',image,at);typ=info&0xffffffff;idx=info>>32;types[str(typ)]+=1
   if typ==1027:rels[offset]=addend
   elif typ==257:rels[offset]=symbols[s[6]][idx]['value']+addend
   else:rels[offset]=None
def relocatedptr(v):return rels.get(v,readptr(v))
init=allmap.get('_PyImport_Inittab')
builtins=[]
if init:
 for slot in range(init['value'],init['value']+init['size'],16):
  name=relocatedptr(slot);func=relocatedptr(slot+8)
  if name==0:break
  if name is None:raise ValueError('unresolved init name')
  builtins.append({'name':cstr(segment(name)),'function_address':func,'slot_address':slot})
pdynamic=next(p for p in ph if p[0]==2)
dynamic=[struct.unpack_from('<qQ',image,at) for at in range(pdynamic[2],pdynamic[2]+pdynamic[5],16)]
dyntags={k:v for k,v in dynamic}
strtab=segment(dyntags[5])
needed=[cstr(strtab+v) for k,v in dynamic if k==1]
versions=[]
for i,s in enumerate(sh):
 if s[1]==0x6ffffffe:
  strings=sh[s[6]];at=s[4]
  while True:
   version,count,filename,aux,nxt=struct.unpack_from('<HHIII',image,at);aa=at+aux
   for j in range(count):
    hashval,flags,other,name,anext=struct.unpack_from('<IHHII',image,aa)
    versions.append({'library':cstr(strings[4]+filename),'version':cstr(strings[4]+name),'flags':flags})
    if not anext:break
    aa+=anext
   if not nxt:break
   at+=nxt
selected={name:{k:v for k,v in dynmap.get(name,{}).items() if k!='name'} for name in ['Py_InitializeFromConfig','Py_PreInitialize','PyConfig_InitIsolatedConfig','PyConfig_SetString','PyImport_AppendInittab','PyImport_Inittab','_PyImport_Inittab','PyInit_math','PyInit__ssl','PyInit__hashlib','PyRun_SimpleStringFlags','Py_FinalizeEx']}
report={'source_artifact':path.name,'image_sha256':hashlib.sha256(image).hexdigest(),'elf_class':2,'elf_data':1,'elf_machine':e[2],'elf_type':e[1],'image_size':len(image),'needed':needed,'soname':cstr(strtab+dyntags[14]) if 14 in dyntags else None,'rpath':cstr(strtab+dyntags[15]) if 15 in dyntags else None,'runpath':cstr(strtab+dyntags[29]) if 29 in dyntags else None,'program_headers':[{'type':p[0],'flags':p[1],'offset':p[2],'vaddr':p[3],'file_size':p[5],'memory_size':p[6],'alignment':p[7]} for p in ph],'dynamic_tags':[{'tag':k,'value':v} for k,v in dynamic if k!=0],'symbol_version_requirements':versions,'relocation_type_counts':dict(types),'selected_dynamic_exports':selected,'inittab_symbol':init,'builtin_modules':builtins,'inittab_source_sha256':hashlib.sha256(config).hexdigest()}
print(json.dumps(report,indent=2,sort_keys=True))
