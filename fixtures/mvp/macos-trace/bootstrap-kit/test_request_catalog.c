#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "request_catalog.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
static struct ba_metadata directory(const struct ba_deployment *d,size_t i) {
    struct ba_metadata m={0};const struct ba_mount_id *p=i<3?&d->root:&d->data;
    m.device=p->device;m.inode=123;m.uid=0;m.gid=0;m.mode=S_IFDIR|0755;m.populated=7;
    m.filesec_mode=m.mode;m.acl_present=0;m.descriptor_flags=FD_CLOEXEC;m.status_flags=O_RDONLY;
    m.fsid[0]=p->fsid[0];m.fsid[1]=p->fsid[1];m.mount_policy=BA_MOUNT_LOCAL|(i<3?BA_MOUNT_ROOTFS:0);
    strcpy(m.filesystem,"apfs");strcpy(m.mountpoint,i<3?"/":"/System/Volumes/Data");return m;
}
int main(int argc,char **argv) {
    assert(argc==2);
    struct bk_request_catalog v={0};v.length=BK_CATALOG_LENGTH;
    assert(fread(v.bytes,1,BK_CATALOG_LENGTH,stdin)==BK_CATALOG_LENGTH&&getchar()==EOF);
    struct bk_catalog_context c;assert(!bk_catalog_decode(&v,&c));
    uint64_t ids[4]={501,501,20,20},groups[TC_MAX_GROUPS]={20,0,80};
    uint8_t sha[32];for(size_t i=0;i<32;i++)sha[i]=(uint8_t)i;
    struct ba_metadata m=directory(&c.deployment,6);struct br_request r;struct br_error e;
    if(!strcmp(argv[1],"emit-request")) {
        assert(!bk_request_prepare(&c,ids,groups,3,&m,BR_SEND_GO,sha,&r));
        uint8_t out[BR_MAX_WIRE];size_t n=0;assert(br_request_encode(&r,out,&n,&e)==BR_OK);
        assert(fwrite(out,1,n,stdout)==n);return 0;
    }
    assert(!strcmp(argv[1],"controls"));
    for(size_t i=0;i<7;i++) { struct ba_metadata x=directory(&c.deployment,i);assert(bk_directory_metadata_valid(&x,&c.deployment,i)); }
    struct ba_metadata x=m;
#define BAD(field,value) do { x=m;x.field=value;assert(!bk_directory_metadata_valid(&x,&c.deployment,6)); } while(0)
    BAD(populated,0);BAD(populated,15);BAD(filesec_uid,1);BAD(filesec_gid,1);BAD(filesec_mode,S_IFDIR|0700);
    BAD(acl_present,-1);BAD(acl_present,1);BAD(mode,S_IFDIR|0777);BAD(mode,S_IFDIR|04755);BAD(mode,S_IFREG|0555);
    BAD(uid,501);BAD(descriptor_flags,0);BAD(descriptor_flags,-1);BAD(status_flags,O_WRONLY);BAD(status_flags,O_ASYNC);
    BAD(mount_policy,BA_MOUNT_LOCAL|BA_MOUNT_ROOTFS);BAD(mount_owner,501);BAD(device,m.device+1);
    x=m;x.fsid[0]++;assert(!bk_directory_metadata_valid(&x,&c.deployment,6));
    x=m;memset(x.filesystem,'x',sizeof(x.filesystem));assert(!bk_directory_metadata_valid(&x,&c.deployment,6));
    x=m;strcpy(x.mountpoint,"/");assert(!bk_directory_metadata_valid(&x,&c.deployment,6));
    assert(!bk_directory_metadata_valid(&m,&c.deployment,7));
    assert(!bk_request_prepare(&c,ids,groups,3,&m,BR_SIMULATED_PROVIDER_FAILURE,sha,&r));
    for(size_t i=0;i<4;i++) { uint64_t hold=ids[i];ids[i]=0;assert(bk_request_prepare(&c,ids,groups,3,&m,1,sha,&r));ids[i]=hold; }
    ids[1]++;assert(bk_request_prepare(&c,ids,groups,3,&m,1,sha,&r));ids[1]--;
    groups[2]=20;assert(bk_request_prepare(&c,ids,groups,3,&m,1,sha,&r));groups[2]=80;
    assert(bk_request_prepare(&c,ids,groups,0,&m,1,sha,&r));assert(bk_request_prepare(&c,ids,groups,17,&m,1,sha,&r));
    assert(bk_request_prepare(&c,ids,groups,3,&m,3,sha,&r));
    for(size_t i=0;i<BK_CATALOG_LENGTH;i++) {
        uint8_t saved=v.bytes[i];v.bytes[i]^=0xff;
        int rc=bk_catalog_decode(&v,&c);
        /* Opaque digests and valid range/profile changes may remain canonical;
         * every accepted tuple must still derive the exact fixed paths. */
        if(!rc)assert(!strncmp(c.cwd,BA_PREFIX,sizeof(BA_PREFIX)-1)&&!strcmp(c.executable+strlen(c.cwd),"/context-probe"));
        v.bytes[i]=saved;
    }
    v.bytes[319]=1;memset(&c,0x55,sizeof(c));assert(bk_catalog_decode(&v,&c));
    for(size_t i=0;i<sizeof(c);i++)assert(((unsigned char *)&c)[i]==0);
    v.bytes[319]=0;v.length=SIZE_MAX;assert(bk_catalog_decode(&v,&c));
    assert(bk_catalog_decode(NULL,&c));assert(bk_catalog_decode(&v,NULL));return 0;
}
