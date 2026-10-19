#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "request_catalog.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#include <grp.h>
static int make_request(uint64_t release) {
    const struct bk_request_catalog *v=bk_compiled_request_catalog();
    struct bk_catalog_context c;
    if(bk_catalog_decode(v,&c)) { fputs("make-request: unconfigured catalog\n",stderr);return 1; }
    uint64_t ids[4]={(uint64_t)getuid(),(uint64_t)geteuid(),(uint64_t)getgid(),(uint64_t)getegid()};
    if(!ids[0]||!ids[2]||ids[0]!=ids[1]||ids[2]!=ids[3]||ids[0]>TC_ID_MAX||ids[2]>TC_ID_MAX) {
        fputs("make-request: ordinary equal IDs required\n",stderr);return 1;
    }
    gid_t raw[TC_MAX_GROUPS]={0};uint64_t groups[TC_MAX_GROUPS]={0};
    int n=getgroups(0,NULL);
    if(n<1||n>TC_MAX_GROUPS||getgroups(TC_MAX_GROUPS,raw)!=n) {
        fputs("make-request: actual groups incompatible\n",stderr);return 1;
    }
    for(int i=0;i<n;i++)groups[i]=(uint64_t)raw[i];
    struct tc_request creds={0};creds.uid=ids[0];creds.gid=ids[2];creds.group_count=(size_t)n;
    memcpy(creds.groups,groups,sizeof(groups));struct tc_error ce;
    if(tc_validate_request(&creds,&ce)) { fputs("make-request: actual groups noncanonical\n",stderr);return 1; }
    const struct ba_operations *o=ba_native_operations();
    static const char *const fixed[]={"/","System","Volumes","Data","Library","GlueMVPFixtures"};
    int fds[7]={-1,-1,-1,-1,-1,-1,-1};size_t owned=0;int failed=0,saved=0;
    struct ba_metadata m={0};
    for(size_t i=0;i<7;i++) {
        const char *name=i<6?fixed[i]:c.cwd+sizeof(BA_PREFIX)-1;
        int fd=i?o->openat_fn(o->context,fds[i-1],name,0,&saved):o->open_root_fn(o->context,&saved);
        if(fd<0) { failed=1;break; }
        /* Real native callbacks cannot alias a live FD. Refuse without guessing
         * cleanup if that invariant is ever violated. No user callbacks exist. */
        for(size_t j=0;j<owned;j++)if(fds[j]==fd)_exit(1);
        fds[owned++]=fd;struct ba_probe_error pe={BA_META_NONE,0};
        if(o->inspect_fn(o->context,fd,&m,&pe)||!bk_directory_metadata_valid(&m,&c.deployment,i)) { failed=1;break; }
    }
    /* Query success alone never attests complete filesec properties. Above uses
     * population, typed scalar equality, ACL and full mount/flag policy. */
    while(owned) { owned--;if(close(fds[owned]))failed=1; }
    if(failed) { fputs("make-request: protected cwd observation or close failed\n",stderr);return 1; }
    if(ids[0]!=(uint64_t)getuid()||ids[1]!=(uint64_t)geteuid()||ids[2]!=(uint64_t)getgid()||ids[3]!=(uint64_t)getegid()||
       getgroups(TC_MAX_GROUPS,raw)!=n) { fputs("make-request: identity changed\n",stderr);return 1; }
    for(int i=0;i<n;i++)if(groups[i]!=(uint64_t)raw[i]) { fputs("make-request: groups changed\n",stderr);return 1; }
    uint8_t digest[32]={0};
    if(!CC_SHA256(v->bytes,(CC_LONG)v->length,digest))return 1;
    struct br_request request;struct br_error error;uint8_t wire[BR_MAX_WIRE];size_t length=0;
    if(bk_request_prepare(&c,ids,groups,(size_t)n,&m,release,digest,&request)||
       br_request_encode(&request,wire,&length,&error)!=BR_OK) { fputs("make-request: canonical request failed\n",stderr);return 1; }
    /* A single write, no retry/replay. A failure may already expose a prefix.
     * Exact bytes plus normal exit are required; this never executes a target. */
    ssize_t written=write(STDOUT_FILENO,wire,length);
    if(written<0||(size_t)written!=length) { fputs("make-request: incomplete output\n",stderr);return 1; }
    return 0;
}
#endif
int main(int argc,char **argv) {
    uint64_t release=BR_SEND_GO;
    if(argc==2&&!strcmp(argv[1],"--simulate-provider-failure"))release=BR_SIMULATED_PROVIDER_FAILURE;
    else if(argc!=1) { fputs("make-request: closed arguments required\n",stderr);return 2; }
#if defined(__APPLE__)
    return make_request(release);
#else
    (void)release;fputs("make-request: native Darwin required\n",stderr);return 1;
#endif
}
