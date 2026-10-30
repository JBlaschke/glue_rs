#include "runtime_catalog.h"
#include "runtime_request.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define SPAN(s) {(const uint8_t*)(s),sizeof(s)-1}
static struct br_request request(void){
 static const uint8_t executable[]="/System/Volumes/Data/Library/GlueMVPFixtures/fixture/glue",cwd[]="/System/Volumes/Data/Library/GlueMVPFixtures/unrelated";
 struct br_request r={0};r.fixture=2;r.argv_template=2;r.credentials.uid=501;r.credentials.gid=20;r.credentials.group_count=1;r.credentials.groups[0]=20;
 r.signal_policy=r.stdio_policy=r.release_action=1;r.max_live_fds=4096;r.attempt_ms=10000;r.cleanup_ms=2000;r.cwd_device=9;r.cwd_inode=88;
 r.executable=(struct br_span){executable,sizeof(executable)-1};r.cwd=(struct br_span){cwd,sizeof(cwd)-1};return r;
}
static void wire(void){
 struct br_request r=request(),got;uint8_t bytes[BR_MAX_WIRE],legacy[BR_MAX_WIRE];size_t n;struct br_error e;
 assert(rr_request_encode(&r,bytes,&n,&e)==BR_OK);assert(rr_request_decode(bytes,n,&got,&e)==BR_OK);
 assert(got.fixture==2&&got.argv_template==2&&!got.environment_count&&got.executable.bytes==bytes+BR_HEADER_SIZE&&got.cwd.bytes==bytes+BR_HEADER_SIZE+r.executable.length);
 assert(!memcmp(got.executable.bytes,r.executable.bytes,r.executable.length));
 assert(br_request_decode(bytes,n,&got,&e)!=BR_OK&&!got.fixture);
 r.fixture=r.argv_template=1;assert(br_request_encode(&r,legacy,&n,&e)==BR_OK);assert(rr_request_decode(legacy,n,&got,&e)!=BR_OK&&!got.fixture);
 r=request();assert(rr_request_encode(&r,bytes,&n,&e)==BR_OK);
 for(size_t i=0;i<n;i++){memset(&got,0xa5,sizeof(got));assert(rr_request_decode(bytes,i,&got,&e)!=BR_OK&&!got.fixture&&!got.executable.bytes);}
 bytes[123]=1;assert(rr_request_decode(bytes,n,&got,&e)!=BR_OK);bytes[123]=2;bytes[127]=1;assert(rr_request_decode(bytes,n,&got,&e)!=BR_OK);
 r.environment_count=1;memset(bytes,0xa5,sizeof(bytes));assert(rr_request_encode(&r,bytes,&n,&e)!=BR_OK&&!n);for(size_t i=0;i<sizeof(bytes);i++)assert(!bytes[i]);
 puts("runtime request exact binding, borrowed consumed spans, legacy separation, every truncation");
}
static void catalog(void){
 static const struct tl_span args[]={SPAN("run"),SPAN("/System/Volumes/Data/Library/GlueMVPFixtures/fixture/app.glue"),SPAN("--"),SPAN("argument with spaces")};
 struct nrr_catalog c={0};c.launcher_bytes=5000000;c.deployment=(struct ba_deployment){{1,{1,2}},{2,{3,4}}};
 strcpy(c.build_id,"fixture");strcpy(c.leaf,"glue");strcpy(c.cwd_name,"unrelated");c.launch=(struct tl_recipe){TL_AARCH64_DARWIN,args,4,0};
 uint8_t bytes[NRR_CATALOG_CAPACITY],again[NRR_CATALOG_CAPACITY];size_t n,m;
 assert(!nrr_catalog_bytes(&c,bytes,&n)&&n>256);assert(!nrr_catalog_bytes(&c,again,&m)&&n==m&&!memcmp(bytes,again,n));
 c.r01_lock_sha256[31]=1;assert(!nrr_catalog_bytes(&c,again,&m)&&memcmp(bytes,again,n));c.r01_lock_sha256[31]=0;
 c.launch.target=2;assert(nrr_catalog_bytes(&c,again,&m)&&!m);c.launch.target=TL_AARCH64_DARWIN;
 strcpy(c.cwd_name,"fixture");assert(nrr_catalog_bytes(&c,again,&m)&&!m);strcpy(c.cwd_name,"unrelated");
 c.launcher_bytes=NRR_MAX_LAUNCHER_BYTES+1;assert(nrr_catalog_bytes(&c,again,&m)&&!m);c.launcher_bytes=5000000;
 char exe[BA_PATH_MAX],cwd[BA_PATH_MAX];assert(!nrr_catalog_paths(&c,exe,cwd)&&!strcmp(exe,"/System/Volumes/Data/Library/GlueMVPFixtures/fixture/glue")&&!strcmp(cwd,"/System/Volumes/Data/Library/GlueMVPFixtures/unrelated"));
 strcpy(c.leaf,"../glue");assert(nrr_catalog_paths(&c,exe,cwd)&&!exe[0]&&!cwd[0]);
 assert(!nrr_compiled_catalog());puts("runtime catalog binds general argv and R01 identity; unrelated cwd and finite launcher; default unconfigured");
}
int main(int argc,char **argv){assert(argc==2);if(!strcmp(argv[1],"wire"))wire();else if(!strcmp(argv[1],"catalog"))catalog();else return 2;return 0;}
