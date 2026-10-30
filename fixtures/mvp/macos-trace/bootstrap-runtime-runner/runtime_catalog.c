#include "runtime_catalog.h"
#include <string.h>
static size_t name(const char *s){
 size_t n=0;for(;n<65&&s[n];n++){unsigned char c=(unsigned char)s[n];
 if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||(n&&(c=='_'||c=='-'||c=='.'))))return 0;}
 return n&&n<=64?n:0;
}
static int valid(const struct nrr_catalog *c){
 return c&&c->launcher_bytes&&c->launcher_bytes<=NRR_MAX_LAUNCHER_BYTES&&name(c->build_id)&&name(c->leaf)&&name(c->cwd_name)&&
 strcmp(c->build_id,c->cwd_name)&&c->deployment.root.device&&c->deployment.data.device&&
 (c->deployment.root.fsid[0]||c->deployment.root.fsid[1])&&(c->deployment.data.fsid[0]||c->deployment.data.fsid[1])&&
 (c->deployment.root.device!=c->deployment.data.device||c->deployment.root.fsid[0]!=c->deployment.data.fsid[0]||c->deployment.root.fsid[1]!=c->deployment.data.fsid[1]);
}
int nrr_catalog_paths(const struct nrr_catalog *c,char exe[BA_PATH_MAX],char cwd[BA_PATH_MAX]){
 if(exe)memset(exe,0,BA_PATH_MAX);
 if(cwd)memset(cwd,0,BA_PATH_MAX);
 if(!exe||!cwd||!valid(c))return -1;
 size_t p=sizeof(BA_PREFIX)-1,a=name(c->build_id),b=name(c->leaf),d=name(c->cwd_name);
 if(p+a+1+b>=BA_PATH_MAX||p+d>=BA_PATH_MAX)return -1;
 memcpy(exe,BA_PREFIX,p);memcpy(exe+p,c->build_id,a);exe[p+a]='/';memcpy(exe+p+a+1,c->leaf,b);
 memcpy(cwd,BA_PREFIX,p);memcpy(cwd+p,c->cwd_name,d);return 0;
}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(24-8*i));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(56-8*i));}
int nrr_catalog_bytes(const struct nrr_catalog *c,uint8_t out[NRR_CATALOG_CAPACITY],size_t *used){
 if(out)memset(out,0,NRR_CATALOG_CAPACITY);
 if(used)*used=0;
 if(!out||!used||!valid(c))return -1;
 char exe[BA_PATH_MAX],cwd[BA_PATH_MAX];if(nrr_catalog_paths(c,exe,cwd))return -1;
 struct tl_plan plan;struct tl_error e;struct tl_span executable={(const uint8_t*)exe,strlen(exe)};
 if(tl_prepare(&c->launch,executable,&plan,&e))return -1;
 uint8_t canonical[TL_CANONICAL_CAPACITY];size_t n=0;if(tl_canonical(&plan,canonical,sizeof(canonical),&n))return -1;
 size_t a=name(c->build_id),b=name(c->leaf),d=name(c->cwd_name),total=256+a+b+d+n;
 if(total>NRR_CATALOG_CAPACITY)return -1;
 memcpy(out,"GLUERC01",8);put32(out+8,1);put32(out+12,(uint32_t)total);put64(out+16,c->launcher_bytes);
 put64(out+24,c->deployment.root.device);put32(out+32,(uint32_t)c->deployment.root.fsid[0]);put32(out+36,(uint32_t)c->deployment.root.fsid[1]);
 put64(out+40,c->deployment.data.device);put32(out+48,(uint32_t)c->deployment.data.fsid[0]);put32(out+52,(uint32_t)c->deployment.data.fsid[1]);
 memcpy(out+56,c->launcher_sha256,32);memcpy(out+88,c->sources_sha256,32);memcpy(out+120,c->recipe_sha256,32);memcpy(out+152,c->r01_lock_sha256,32);
 put32(out+184,(uint32_t)a);put32(out+188,(uint32_t)b);put32(out+192,(uint32_t)d);put32(out+196,(uint32_t)n);
 memcpy(out+256,c->build_id,a);memcpy(out+256+a,c->leaf,b);memcpy(out+256+a+b,c->cwd_name,d);memcpy(out+256+a+b+d,canonical,n);*used=total;return 0;
}
