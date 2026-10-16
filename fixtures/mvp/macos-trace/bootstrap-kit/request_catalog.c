#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "request_catalog.h"
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
static uint32_t g32(const uint8_t *p) { uint32_t n=0;for(unsigned i=0;i<4;i++)n=(n<<8)|p[i];return n; }
static uint64_t g64(const uint8_t *p) { uint64_t n=0;for(unsigned i=0;i<8;i++)n=(n<<8)|p[i];return n; }
static int32_t signed32(uint32_t n) { return n<=INT32_MAX?(int32_t)n:(int32_t)(-INT64_C(1)-(int64_t)(UINT32_MAX-n)); }
int bk_catalog_decode(const struct bk_request_catalog *v,struct bk_catalog_context *out) {
    if(!out)return -1;
    memset(out,0,sizeof(*out));
    if(!v||v->length!=BK_CATALOG_LENGTH)return -1;
    const uint8_t *p=v->bytes;
    if(memcmp(p,"GLUENC01\0\1\0\300",12)||g32(p+12)!=BK_CATALOG_LENGTH||
       !g64(p+16)||g64(p+16)>UINT64_C(4194304)||memcmp(p+184,"\0\100\0\15\0\0\0\0",8))return -1;
    for(size_t i=0;i<64;i++)if(!((p[192+i]>='0'&&p[192+i]<='9')||(p[192+i]>='a'&&p[192+i]<='f')))return -1;
    if(memcmp(p+256,"context-probe",13))return -1;
    for(size_t i=BK_CATALOG_LENGTH;i<BK_CATALOG_CAPACITY;i++)if(p[i])return -1;
    struct ba_deployment d={{g64(p+24),{signed32(g32(p+32)),signed32(g32(p+36))}},
                            {g64(p+40),{signed32(g32(p+48)),signed32(g32(p+52))}}};
    if(!d.root.device||!d.data.device||(!d.root.fsid[0]&&!d.root.fsid[1])||(!d.data.fsid[0]&&!d.data.fsid[1])||
       (d.root.device==d.data.device&&d.root.fsid[0]==d.data.fsid[0]&&d.root.fsid[1]==d.data.fsid[1]))return -1;
    out->deployment=d;
    size_t n=sizeof(BA_PREFIX)-1;
    memcpy(out->cwd,BA_PREFIX,n);memcpy(out->cwd+n,p+192,64);
    memcpy(out->executable,out->cwd,n+64);memcpy(out->executable+n+64,"/context-probe",14);
    return 0;
}
int bk_directory_metadata_valid(const struct ba_metadata *m,const struct ba_deployment *d,size_t i) {
    if(!m||!d||i>6)return 0;
    const struct ba_mount_id *wanted=i<3?&d->root:&d->data;
    int forbidden=O_ASYNC;
#ifdef O_EVTONLY
    forbidden|=O_EVTONLY;
#endif
#ifdef O_PATH
    forbidden|=O_PATH;
#endif
    return m->descriptor_flags>=0&&(m->descriptor_flags&FD_CLOEXEC)&&m->status_flags>=0&&
        (m->status_flags&O_ACCMODE)==O_RDONLY&&!(m->status_flags&forbidden)&&
        !(m->mode&~(uint32_t)(S_IFMT|07777))&&S_ISDIR(m->mode)&&m->uid==0&&
        !(m->mode&(S_IWGRP|S_IWOTH|S_ISUID|S_ISGID))&&m->populated==7&&
        m->filesec_uid==m->uid&&m->filesec_gid==m->gid&&m->filesec_mode==m->mode&&m->acl_present==0&&
        m->mount_policy==(uint32_t)(BA_MOUNT_LOCAL|(i<3?BA_MOUNT_ROOTFS:0))&&m->mount_owner==0&&
        memchr(m->filesystem,0,sizeof(m->filesystem))&&memchr(m->mountpoint,0,sizeof(m->mountpoint))&&
        !strcmp(m->filesystem,"apfs")&&!strcmp(m->mountpoint,i<3?"/":"/System/Volumes/Data")&&
        m->device==wanted->device&&m->fsid[0]==wanted->fsid[0]&&m->fsid[1]==wanted->fsid[1];
}
int bk_request_prepare(const struct bk_catalog_context *c,const uint64_t ids[4],const uint64_t groups[TC_MAX_GROUPS],
                       size_t count,const struct ba_metadata *cwd,uint64_t release,const uint8_t sha[32],struct br_request *out) {
    if(!out)return -1;
    memset(out,0,sizeof(*out));
    if(!c||!ids||!groups||!cwd||!sha||count<1||count>TC_MAX_GROUPS||ids[0]!=ids[1]||ids[2]!=ids[3]||
       (release!=BR_SEND_GO&&release!=BR_SIMULATED_PROVIDER_FAILURE)||!bk_directory_metadata_valid(cwd,&c->deployment,6))return -1;
    struct tc_request r={0};r.uid=ids[0];r.gid=ids[2];r.group_count=count;
    memcpy(r.groups,groups,count*sizeof(*groups));
    struct tc_error e;if(tc_validate_request(&r,&e))return -1;
    size_t a=strnlen(c->executable,sizeof(c->executable)),b=strnlen(c->cwd,sizeof(c->cwd));
    if(a==sizeof(c->executable)||b==sizeof(c->cwd))return -1;
    out->fixture=1;out->credentials=r;out->signal_policy=1;out->stdio_policy=1;out->release_action=release;
    out->max_live_fds=4096;out->attempt_ms=10000;out->cleanup_ms=2000;out->argv_template=1;
    memcpy(out->catalog_sha256,sha,32);out->cwd_device=cwd->device;out->cwd_inode=cwd->inode;
    out->executable=(struct br_span){(const uint8_t *)c->executable,a};out->cwd=(struct br_span){(const uint8_t *)c->cwd,b};
    return 0;
}
