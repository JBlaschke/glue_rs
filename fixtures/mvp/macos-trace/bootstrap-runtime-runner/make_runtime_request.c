/* Ordinary-user request declarations only; the root controller independently
 * admits the actual launcher/CWD. No target, signal or credential mutation. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "runtime_catalog.h"
#include "runtime_request.h"
#include "../bootstrap-kit/request_catalog.h"
#include <string.h>
#include <unistd.h>
#if defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))
#include <CommonCrypto/CommonDigest.h>
static int prepare(const struct nrr_catalog*c,uint8_t out[BR_MAX_WIRE],size_t*used){
 char exe[BA_PATH_MAX],cwd[BA_PATH_MAX];uint8_t catalog[NRR_CATALOG_CAPACITY],sha[32];size_t n;
 if(nrr_catalog_paths(c,exe,cwd)||nrr_catalog_bytes(c,catalog,&n)||CC_SHA256(catalog,(CC_LONG)n,sha)!=sha)return -1;
 struct br_request r;memset(&r,0,sizeof(r));
 if(!getuid()||getuid()!=geteuid()||!getgid()||getgid()!=getegid())return -1;
 r.credentials.uid=getuid();r.credentials.gid=getgid();gid_t groups[16];int count=getgroups(16,groups);if(count<1||count>16)return -1;
 r.credentials.group_count=(size_t)count;for(int i=0;i<count;i++)r.credentials.groups[i]=groups[i];struct tc_error te;if(tc_validate_request(&r.credentials,&te))return -1;
 const struct ba_operations*ops=ba_native_operations();int held[7]={-1,-1,-1,-1,-1,-1,-1};int result=0;
 const char*names[]={"/","System","Volumes","Data","Library","GlueMVPFixtures",c->cwd_name};
 struct ba_metadata metadata;struct ba_probe_error error;
 for(unsigned i=0;i<7;i++){
  int saved=0;held[i]=i?ops->openat_fn(ops->context,held[i-1],names[i],0,&saved):ops->open_root_fn(ops->context,&saved);
  if(held[i]<0||ops->inspect_fn(ops->context,held[i],&metadata,&error)||!bk_directory_metadata_valid(&metadata,&c->deployment,i)){result=-1;break;}
 }
 if(!result){r.cwd_device=metadata.device;r.cwd_inode=metadata.inode;}
 for(unsigned i=0;i<7;i++)if(held[i]>=0&&close(held[i]))result=-1;
 if(result)return -1;
 r.fixture=r.argv_template=2;r.signal_policy=r.stdio_policy=r.release_action=1;r.max_live_fds=4096;r.attempt_ms=10000;r.cleanup_ms=2000;
 r.executable=(struct br_span){(const uint8_t*)exe,strlen(exe)};r.cwd=(struct br_span){(const uint8_t*)cwd,strlen(cwd)};memcpy(r.catalog_sha256,sha,32);
 struct br_error e;return rr_request_encode(&r,out,used,&e)==BR_OK?0:-1;
}
#endif
int main(int argc,char**argv){(void)argv;if(argc!=1)return 2;
#if defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))
 const struct nrr_catalog*c=nrr_compiled_catalog();if(!c)return 2;
 uint8_t bytes[BR_MAX_WIRE];size_t n;if(prepare(c,bytes,&n))return 2;
 for(size_t offset=0;offset<n;){ssize_t amount=write(1,bytes+offset,n-offset);if(amount<=0)return 2;offset+=(size_t)amount;}return 0;
#else
 return 2;
#endif
}
