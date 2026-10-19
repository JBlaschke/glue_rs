#define _DEFAULT_SOURCE 1
#include "runner_catalog.h"
#include "runner_protocol.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
struct model {uint8_t data[1024];size_t length,offset;uint64_t now;int late_eof,late_progress;};
static int clk(void *c,struct bio_time *t,int *e){struct model*m=c;(void)e;*t=(struct bio_time){m->now,0};return 0;}
static int shape(void*c,int f,mode_t*t,int*e){(void)c;(void)f;(void)e;*t=S_IFIFO;return 0;}
static int flags(void*c,int f,int*e){(void)c;(void)f;(void)e;return O_RDONLY|O_NONBLOCK;}
static int poller(void*c,int f,short events,int ms,short*out,int*e){(void)c;(void)f;(void)ms;(void)e;*out=events;return 1;}
static ssize_t reader(void*c,int f,void*p,size_t n,int*e){struct model*m=c;(void)f;(void)e;size_t left=m->length-m->offset;if(n>left)n=left;memcpy(p,m->data+m->offset,n);m->offset+=n;if(!n&&m->late_eof)m->now=20;if(n&&m->late_progress)m->now=20;return (ssize_t)n;}
static ssize_t writer(void*c,int f,const void*p,size_t n,int*e){(void)c;(void)f;(void)p;(void)n;*e=EIO;return -1;}
static struct bio_operations ops(struct model*m){return(struct bio_operations){m,clk,shape,flags,poller,reader,writer};}
static struct bw_binding binding(void){struct bw_binding b={100,200,{0}};for(unsigned i=0;i<32;i++)b.request_sha256[i]=(uint8_t)i;return b;}
static struct bw_status ready(void){struct bw_status s={0};s.binding=binding();s.kind=BW_READY;s.detail=-1;s.mutation_flags=3;s.real_uid=s.effective_uid=501;s.real_gid=s.effective_gid=20;s.group_count=2;s.groups[0]=20;s.groups[1]=0;s.cwd_device=77;s.cwd_inode=88;for(unsigned i=0;i<5;i++)s.kept_fds[i]=i;s.kept_fds[3]=8;s.kept_fds[4]=9;return s;}
static struct bw_status attempt(void){struct bw_status s={0};s.binding=binding();s.kind=BW_EXEC_ATTEMPT;s.sequence=1;s.stage=BW_EXEC;s.detail=-1;s.mutation_flags=3;return s;}
static struct bw_status error_record(unsigned seq,unsigned stage){struct bw_status s={0};s.binding=binding();s.kind=BW_ERROR;s.sequence=seq;s.stage=stage;s.detail=-1;s.reason=BW_SYSCALL;s.system_errno=EIO;s.mutation_flags=stage>=BW_DESCRIPTORS?3:stage>=BW_CREDENTIALS?1:0;return s;}
static void add(struct model*m,struct bw_status s){assert(m->length+256<=sizeof(m->data));assert(bw_status_encode(&s,m->data+m->length)==BW_OK);m->length+=256;}
static void start(struct model*m,struct nr_status_stream*s){memset(m,0,sizeof(*m));m->now=1;struct bw_binding b=binding();assert(nr_status_init(s,&b)==0);}
static int next(struct model*m,struct nr_status_stream*s){struct bio_operations o=ops(m);return nr_status_next(s,7,(struct bio_time){10,0},&o);}
static void streams(void){
 struct model m;struct nr_status_stream s;
 start(&m,&s);add(&m,ready());add(&m,attempt());assert(next(&m,&s)==0);assert(next(&m,&s)==0);assert(next(&m,&s)==1);assert(s.used==512&&s.end==BW_END_ATTEMPT_WITHOUT_REPORTED_EXEC_ERROR);assert(next(&m,&s)==-1&&s.failed);
 start(&m,&s);add(&m,error_record(0,BW_REQUEST));assert(next(&m,&s)==0);assert(next(&m,&s)==1);assert(s.end==BW_END_REPORTED_ERROR&&s.wire.has_reported_error);
 start(&m,&s);add(&m,ready());add(&m,error_record(1,BW_GO_IO));assert(!next(&m,&s));assert(!next(&m,&s));assert(next(&m,&s)==1&&s.end==BW_END_REPORTED_ERROR);
 start(&m,&s);add(&m,ready());add(&m,attempt());add(&m,error_record(2,BW_EXEC));for(unsigned i=0;i<3;i++)assert(!next(&m,&s));assert(next(&m,&s)==1&&s.used==768&&s.end==BW_END_REPORTED_ERROR);
 start(&m,&s);assert(next(&m,&s)==1&&s.end==BW_END_INCOMPLETE);
 start(&m,&s);add(&m,ready());assert(!next(&m,&s));assert(next(&m,&s)==1&&s.end==BW_END_INCOMPLETE);
 puts("sequences");
}
static void hostile_streams(void){
 struct model m;struct nr_status_stream s;
 start(&m,&s);add(&m,ready());m.length=23;assert(next(&m,&s)==-1&&s.used==23&&s.first_io_error.reason==BIO_REASON_TRUNCATED);assert(next(&m,&s)==-1);
 start(&m,&s);add(&m,ready());add(&m,attempt());add(&m,error_record(2,BW_EXEC));m.data[m.length++]=42;for(unsigned i=0;i<3;i++)assert(!next(&m,&s));assert(next(&m,&s)==-1&&s.used==769&&s.wire.has_reported_error);
 start(&m,&s);add(&m,ready());m.data[16]^=1;assert(next(&m,&s)==-1&&s.first_wire_error==BW_FAULT_BINDING);
 start(&m,&s);add(&m,attempt());assert(next(&m,&s)==-1&&s.first_wire_error==BW_FAULT_ORDER);
 start(&m,&s);add(&m,error_record(0,BW_REQUEST));add(&m,ready());assert(!next(&m,&s));assert(next(&m,&s)==-1&&s.wire.has_reported_error);
 puts("malformed-prefix-extra-poison");
}
static void late_eof(void){
 struct model m;struct nr_status_stream s;
 start(&m,&s);m.late_eof=1;assert(next(&m,&s)==-1&&s.failed&&s.first_io_error.reason==BIO_REASON_DEADLINE&&!s.ended);
 start(&m,&s);add(&m,ready());add(&m,attempt());assert(!next(&m,&s));assert(!next(&m,&s));m.late_eof=1;assert(next(&m,&s)==-1&&!s.ended&&s.used==512);
 start(&m,&s);add(&m,ready());m.late_progress=1;assert(next(&m,&s)==-1&&s.wire.accepted_records==0&&s.used==256);
 puts("late-eof-and-complete-prefix");
}
static struct br_request request(void){static const uint8_t exe[]="/x/context-probe",cwd[]="/x";struct br_request r={0};r.fixture=1;r.credentials.uid=501;r.credentials.gid=20;r.credentials.group_count=2;r.credentials.groups[0]=20;r.signal_policy=r.stdio_policy=r.argv_template=1;r.release_action=1;r.max_live_fds=4096;r.attempt_ms=100;r.cleanup_ms=100;r.cwd_device=77;r.cwd_inode=88;r.executable=(struct br_span){exe,sizeof(exe)-1};r.cwd=(struct br_span){cwd,sizeof(cwd)-1};return r;}
static struct np_report report(void){struct np_report p={0};struct bw_binding b=binding();memcpy(p.request_sha256,b.request_sha256,32);p.pids[0]=200;p.pids[1]=100;p.pids[2]=200;p.ids[0]=p.ids[1]=p.post_ids[0]=p.post_ids[1]=501;p.ids[2]=p.ids[3]=p.post_ids[2]=p.post_ids[3]=20;p.group_count=2;p.groups[0]=20;p.cwd_device=77;p.cwd_inode=88;p.fd_count=3;for(unsigned i=0;i<3;i++)p.fds[i]=i;p.status_flags[1]=p.status_flags[2]=1;p.root_regain_result=-1;p.root_regain_errno=1;p.signal_policy=1;return p;}
static void comparisons(void){
 struct br_request r=request();struct bw_binding b=binding();struct np_report p=report();uint64_t f[]={0,1,1};assert(nr_probe_compare(&r,&b,f,&p)==0);
 struct np_report q=p;q.pids[1]=101;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.pids[0]=q.pids[2]=201;assert(nr_probe_compare(&r,&b,f,&q));
 q=p;q.ids[0]=q.ids[1]=q.post_ids[0]=q.post_ids[1]=502;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.cwd_inode++;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.groups[1]=1;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.request_sha256[0]^=1;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.status_flags[1]|=8;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.descriptor_flags[2]=1;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.environment_count=1;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.signal_policy=0;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.root_regain_errno=13;assert(nr_probe_compare(&r,&b,f,&q));q=p;q.post_ids[0]++;assert(nr_probe_compare(&r,&b,f,&q));
 struct bw_status s=ready();struct br_ready_context c={0};c.binding=b;for(unsigned i=0;i<5;i++)c.kept_fds[i]=s.kept_fds[i];struct br_error e;assert(br_ready_compare(&r,&c,&s,&e)==BR_OK);s.cwd_inode++;assert(br_ready_compare(&r,&c,&s,&e)==BR_MISMATCH);s=ready();s.signal_policy_sha256[2]=1;assert(br_ready_compare(&r,&c,&s,&e)==BR_MISMATCH);s=ready();s.mutation_flags=1;assert(br_ready_compare(&r,&c,&s,&e)==BR_MISMATCH);
 puts("requested-ready-and-probe-comparisons");
}
static struct nr_catalog catalog(void){struct nr_catalog c={0};c.probe_bytes=123;c.deployment.root=(struct ba_mount_id){1,{2,-3}};c.deployment.data=(struct ba_mount_id){4,{-5,6}};strcpy(c.build_id,"build-1");strcpy(c.leaf,"context-probe");for(unsigned i=0;i<32;i++){c.probe_sha256[i]=(uint8_t)i;c.probe_sources_sha256[i]=(uint8_t)(32+i);c.runner_static_sources_sha256[i]=(uint8_t)(64+i);c.build_recipe_sha256[i]=(uint8_t)(96+i);}return c;}
static void catalogs(void){struct nr_catalog c=catalog();uint8_t out[NR_CATALOG_CAPACITY];size_t n;char exe[BA_PATH_MAX],cwd[BA_PATH_MAX];assert(!nr_catalog_bytes(&c,out,&n)&&n==212);assert(!nr_catalog_paths(&c,exe,cwd));assert(!strcmp(cwd,BA_PREFIX "build-1")&&!strcmp(exe,BA_PREFIX "build-1/context-probe"));for(size_t i=n;i<sizeof(out);i++)assert(out[i]==0);
 for(unsigned which=0;which<6;which++){struct nr_catalog bad=c;if(which==0)bad.probe_bytes=0;if(which==1)bad.probe_bytes=NR_MAX_PROBE_BYTES+1;if(which==2)strcpy(bad.build_id,"../bad");if(which==3)strcpy(bad.leaf,"other");if(which==4)bad.deployment.data=bad.deployment.root;if(which==5)memset(bad.build_id,'x',sizeof(bad.build_id));memset(out,0xa5,sizeof(out));n=3;assert(nr_catalog_bytes(&bad,out,&n)&&n==0);for(size_t i=0;i<sizeof(out);i++)assert(!out[i]);}
 puts("catalog-canonical-bounds");
}
int main(int argc,char**argv){if(argc==2&&!strcmp(argv[1],"catalog")){struct nr_catalog c=catalog();uint8_t b[NR_CATALOG_CAPACITY];size_t n;assert(!nr_catalog_bytes(&c,b,&n));return fwrite(b,1,n,stdout)==n?0:2;}assert(argc==1);streams();hostile_streams();late_eof();comparisons();catalogs();return 0;}
