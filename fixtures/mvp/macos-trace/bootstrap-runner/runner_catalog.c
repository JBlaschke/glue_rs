#include "runner_catalog.h"
#include <string.h>
static int alnum_ascii(unsigned char c) {
    return (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9');
}
static size_t name_size(const char s[65]) {
    size_t n=0;
    for(;n<65 && s[n];n++) {
        unsigned char c=(unsigned char)s[n];
        if(!alnum_ascii(c) && (n==0 || (c!='_' && c!='-' && c!='.')))return 0;
    }
    return n>0 && n<=64 ? n : 0;
}
static int profile(const struct ba_deployment *p) {
    return p->root.device && p->data.device &&
        (p->root.fsid[0] || p->root.fsid[1]) && (p->data.fsid[0] || p->data.fsid[1]) &&
        (p->root.device!=p->data.device || p->root.fsid[0]!=p->data.fsid[0] || p->root.fsid[1]!=p->data.fsid[1]);
}
static int valid(const struct nr_catalog *c) {
    return c && c->probe_bytes && c->probe_bytes<=NR_MAX_PROBE_BYTES &&
        name_size(c->build_id) && name_size(c->leaf)==13 && !memcmp(c->leaf,"context-probe",14) && profile(&c->deployment);
}
static void p16(uint8_t *p,uint32_t n) {p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n;}
static void p32(uint8_t *p,uint32_t n) {for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(24-8*i));}
static void p64(uint8_t *p,uint64_t n) {for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(56-8*i));}
int nr_catalog_bytes(const struct nr_catalog *c,uint8_t out[NR_CATALOG_CAPACITY],size_t *used) {
    if(out)memset(out,0,NR_CATALOG_CAPACITY);
    if(used)*used=0;
    if(!out || !used || !valid(c))return -1;
    size_t a=name_size(c->build_id),b=name_size(c->leaf),n=NR_CATALOG_HEADER_BYTES+a+b;
    memcpy(out,"GLUENC01",8);p16(out+8,1);p16(out+10,NR_CATALOG_HEADER_BYTES);p32(out+12,(uint32_t)n);
    p64(out+16,c->probe_bytes);p64(out+24,c->deployment.root.device);
    p32(out+32,(uint32_t)c->deployment.root.fsid[0]);p32(out+36,(uint32_t)c->deployment.root.fsid[1]);
    p64(out+40,c->deployment.data.device);p32(out+48,(uint32_t)c->deployment.data.fsid[0]);p32(out+52,(uint32_t)c->deployment.data.fsid[1]);
    memcpy(out+56,c->probe_sha256,32);memcpy(out+88,c->probe_sources_sha256,32);
    memcpy(out+120,c->runner_static_sources_sha256,32);memcpy(out+152,c->build_recipe_sha256,32);
    p16(out+184,(uint32_t)a);p16(out+186,(uint32_t)b);
    memcpy(out+192,c->build_id,a);memcpy(out+192+a,c->leaf,b);*used=n;return 0;
}
int nr_catalog_paths(const struct nr_catalog *c,char executable[BA_PATH_MAX],char cwd[BA_PATH_MAX]) {
    if(executable)memset(executable,0,BA_PATH_MAX);
    if(cwd)memset(cwd,0,BA_PATH_MAX);
    if(!executable || !cwd || !valid(c))return -1;
    size_t prefix=sizeof(BA_PREFIX)-1,n=name_size(c->build_id),leaf=name_size(c->leaf);
    if(prefix+n+1+leaf>=BA_PATH_MAX)return -1;
    memcpy(cwd,BA_PREFIX,prefix);memcpy(cwd+prefix,c->build_id,n);
    memcpy(executable,cwd,prefix+n);executable[prefix+n]='/';memcpy(executable+prefix+n+1,c->leaf,leaf);
    return 0;
}
