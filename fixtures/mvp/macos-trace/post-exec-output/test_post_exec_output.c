#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "post_exec_output_test.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#endif
#define ASSERT(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); return 1; } } while (0)
#define OWNER 0x1234u
#define CHILD 0x3456u
#define STOP_STATUS ((17<<8)|0x7f)
static void be32(uint8_t *b,uint32_t n){for(unsigned i=0;i<4;i++)b[i]=(uint8_t)(n>>(24-8*i));}
static void be64(uint8_t *b,uint64_t n){for(unsigned i=0;i<8;i++)b[i]=(uint8_t)(n>>(56-8*i));}
static uint16_t rd16(const uint8_t *b){return (uint16_t)((uint16_t)b[0]<<8|b[1]);}
static uint32_t rd32(const uint8_t *b){uint32_t n=0;for(unsigned i=0;i<4;i++)n=(n<<8)|b[i];return n;}
static uint64_t rd64(const uint8_t *b){uint64_t n=0;for(unsigned i=0;i<8;i++)n=(n<<8)|b[i];return n;}
static void le(uint8_t *b,uint64_t n,unsigned width){for(unsigned i=0;i<width;i++)b[i]=(uint8_t)(n>>(8*i));}
static int zero(const uint8_t *b,size_t n){for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;}
static int save(const char *path,const void *bytes,size_t count){FILE *f=fopen(path,"wb");if(!f)return -1;int ok=fwrite(bytes,1,count,f)==count;if(fclose(f))ok=0;return ok?0:-1;}
static void original(struct px_plan *p,uint32_t owner,uint32_t child,int fd0,int fd1,uint64_t dev0,uint64_t ino0,uint64_t dev1,uint64_t ino1,uint32_t mode0,uint32_t mode1,uint32_t fl0,uint32_t fl1){
 uint8_t *b=p->original;memset(b,0,320);memcpy(b,"GLUERW01",8);be32(b+8,1);be32(b+12,320);be32(b+16,owner);be32(b+20,child);be32(b+24,4);
 memcpy(b+32,p->digests[0],32);memcpy(b+64,p->digests[1],32);memcpy(b+96,p->digests[2],32);be32(b+140,UINT32_MAX);be32(b+144,UINT32_MAX);
 for(unsigned i=0;i<4;i++){unsigned role=i%2;uint8_t *v=b+160+i*40;be32(v,(uint32_t)(role?fd1:fd0));be32(v+4,1);be32(v+8,role?fl1:fl0);be32(v+12,role?mode1:mode0);be64(v+16,role?dev1:dev0);be64(v+24,role?ino1:ino0);be64(v+32,1);}
}
static struct px_plan plan(void){
 struct px_plan p;memset(&p,0,sizeof(p));p.child=CHILD;p.held[0]=17;p.held[1]=23;p.sequence=UINT64_C(0x0123456789abcdef);p.deadline=1000000;p.exec_ordinal=7;p.new_tid=UINT64_C(0xaabbccddeeff0011);
 for(unsigned i=0;i<4;i++)for(unsigned j=0;j<32;j++)p.digests[i][j]=(uint8_t)(i*64+j);
 const uint8_t hash[32]={0xa2,0x3f,0x35,0x0c,0x99,0xfe,0x9a,0x51,0x0e,0xd8,0xcc,0x58,0x3d,0x70,0xa6,0x33,0x36,0xe3,0x6c,0x4f,0xf8,0x7f,0x53,0x8e,0xb4,0xc8,0xa4,0x1a,0xb5,0x8c,0xfb,0x1f};memcpy(p.digests[4],hash,32);
 original(&p,OWNER,CHILD,17,23,UINT64_C(0xfffffffffedcba98),UINT64_C(0x0123456789abc001),UINT64_C(0xfffffffffedcba98),UINT64_C(0x0123456789abc002),0100600,0100600,1,1);return p;
}
static void fields(uint8_t *b,unsigned q){
 unsigned role=(q==1||q==3||q==5||q==7)?2:1;memset(b,0,176);le(b,2u|(q%2?0x10000u:0),4);le(b+4,(q<2||q>=6?2u:0u)|(q%2?1u:0u),4);le(b+8,UINT64_C(0x8102030405060708)+q,8);le(b+16,1,4);
 le(b+24,0xfedcba98,4);le(b+28,0100600,2);le(b+30,1,2);le(b+32,UINT64_C(0x0123456789abc000)+role,8);le(b+40,0x89abcdef,4);le(b+44,0xfedcba98,4);
 for(unsigned off=48;off<=120;off+=8)le(b+off,UINT64_C(0x9100000000000000)+((uint64_t)off<<16)+q,8);
 le(b+128,0x81234567,4);le(b+132,0x87654321,4);le(b+136,0xdabef00d,4);le(b+140,0xf0010203,4);le(b+144,UINT64_C(0xfedcba9876543210),8);le(b+152,UINT64_C(0x89abcdef01234567),8);le(b+160,1,4);le(b+164,0x91abcdef,4);le(b+168,0x89abcdef,4);le(b+172,0xfedcba98,4);
}
struct model {
 pid_t owner;unsigned policies,clocks,waits,queries;uint64_t now,lastclock;
 unsigned fail_clock,late_clock,back_clock,fail_query,fail_policy,advance_policy;int owner_after_queries;int query_return,query_errno,policy_return,policy_errno;
 int wait_return,wait_status,wait_errno;unsigned zero_waits,eintr_waits;
 int mutation,mutation_row;unsigned bad_call;uintptr_t addresses[8];uint64_t before[8],after[8],wait_before,wait_after;
 int pending;uint8_t raw[8][176];
};
static struct model model(void){struct model m;memset(&m,0,sizeof(m));m.owner=OWNER;m.now=100;m.wait_return=CHILD;m.wait_status=STOP_STATUS;m.query_return=176;m.query_errno=EIO;m.policy_errno=EACCES;return m;}
static pid_t mpid(void *c){return ((struct model *)c)->owner;}
static int mpolicy(void *c,int *e){struct model *m=c;m->policies++;if(m->policies==m->advance_policy)m->now=1000001;if(m->policy_return||m->policies==m->fail_policy){*e=m->policy_errno;return -1;}return 0;}
static int mclock(void *c,uint64_t *out,int *e){struct model *m=c;unsigned n=++m->clocks;if(n==m->fail_clock){*e=EIO;return -1;}uint64_t v=m->now;m->now+=10;if(n==m->late_clock)v=1000001;if(n==m->back_clock)v=1;m->lastclock=v;*out=v;if(m->pending==-1)m->wait_after=v;else if(m->pending>0)m->after[(unsigned)m->pending-1]=v;m->pending=0;return 0;}
static pid_t mwait(void *c,pid_t child,int *status,int options,int *e){struct model *m=c;m->waits++;if(child!=CHILD||options!=(WNOHANG|WUNTRACED))m->bad_call=1;m->wait_before=m->lastclock;m->pending=-1;
 if(m->waits<=m->zero_waits)return 0;
 if(m->waits<=m->zero_waits+m->eintr_waits){*e=EINTR;return -1;}
 *status=m->wait_status;if(m->wait_return<0)*e=m->wait_errno;return (pid_t)m->wait_return;}
static int mquery(void *c,pid_t pid,int fd,uint8_t b[176],int *e){struct model *m=c;unsigned q=m->queries++;if(q>=8){m->bad_call=1;*e=EOVERFLOW;return -1;}int expected_fd=(q==0||q==6)?17:(q==1||q==7)?23:(q%2?2:1);pid_t expected_pid=(q<2||q>=6)?OWNER:CHILD;
 if(pid!=expected_pid||fd!=expected_fd||!zero(b,176))m->bad_call=1;
 for(unsigned i=0;i<q;i++)if(m->addresses[i]==(uintptr_t)b)m->bad_call=1;
 m->addresses[q]=(uintptr_t)b;m->before[q]=m->lastclock;m->pending=(int)q+1;fields(b,q);
 if((int)q==m->mutation_row){switch(m->mutation){case 1:le(b,1,4);break;case 2:le(b,0x40000002,4);break;case 3:le(b,0x80000002,4);break;case 4:le(b,10,4);break;case 5:le(b+4,0,4);break;case 6:le(b+4,2,4);break;case 7:le(b+4,6,4);break;case 8:le(b+20,1,4);break;case 9:le(b+16,2,4);break;case 10:le(b+160,2,4);break;case 11:le(b+28,0040600,2);break;case 12:le(b+30,2,2);break;case 13:le(b+24,0x7edcba98,4);break;case 14:le(b+32,UINT64_C(0x0123456789abcdef),8);break;case 15:le(b+32,UINT64_C(0x0123456789abc001),8);break;}}
 memcpy(m->raw[q],b,176);if(m->owner_after_queries&&m->queries==8)m->owner++;if(m->queries==m->fail_query){*e=m->query_errno;return m->query_return;}return 176;}
static struct px_test_operations operations(struct model *m){struct px_test_operations o={m,mpid,mpolicy,mclock,mwait,mquery};return o;}
static struct px_observer *start(struct model *m,struct px_plan *p,struct px_error *e){struct px_test_operations o=operations(m);return px_observer_model_new(p,&o,e);}
static unsigned calls(const struct model *m){return m->policies+m->clocks+m->waits+m->queries;}
static int no_replay(struct px_observer *o,struct model *m){struct px_error e;unsigned n=calls(m);return px_observer_poll(o,&e)==-1&&calls(m)==n;}
static int encode(struct px_observer *o,uint8_t b[4096]){struct px_error e;memset(b,0xa5,4096);return px_observer_encode(o,b,&e);}
static int success(const char *path){struct model m=model();struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);ASSERT(px_observer_poll(o,&e)==1);ASSERT(m.waits==1&&m.queries==8&&!m.bad_call);ASSERT(px_observer_owns_child(o));ASSERT(no_replay(o,&m));uint8_t b[4096];ASSERT(encode(o,b)==0);ASSERT(rd16(b+56)==8&&rd16(b+58)==1&&rd16(b+60)==PX_COMPLETE);ASSERT(rd32(b+68)==(PX_OWNED|PX_STOPPED|PX_ATTEMPTED|PX_MATCHED));ASSERT(rd16(b+80)==1&&rd16(b+82)==0);ASSERT(zero(b+84,12));ASSERT(zero(b+2080,2016));
 for(unsigned q=0;q<8;q++){const uint8_t *v=b+256+q*224;ASSERT(rd16(v+40)==(PX_Q_ATTEMPTED|PX_Q_FULL|PX_Q_AFTER));ASSERT(rd64(v+24)==m.addresses[q]);ASSERT(rd64(v+8)==m.before[q]&&rd64(v+16)==m.after[q]);ASSERT(rd32(v+32)==176&&rd32(v+36)==0);ASSERT(zero(v+44,4));}
 if(path){ASSERT(save(path,b,sizeof(b))==0);char name[PATH_MAX];ASSERT(snprintf(name,sizeof(name),"%s.original",path)>0);ASSERT(save(name,p.original,sizeof(p.original))==0);ASSERT(snprintf(name,sizeof(name),"%s.meta",path)>0);FILE *f=fopen(name,"w");ASSERT(f);fprintf(f,"{\"lastclock\":%" PRIu64 ",\"wait_before\":%" PRIu64 ",\"wait_after\":%" PRIu64 ",\"addresses\":[",m.lastclock,m.wait_before,m.wait_after);for(unsigned q=0;q<8;q++)fprintf(f,"%s%" PRIuPTR,q?",":"",m.addresses[q]);fprintf(f,"],\"before\":[");for(unsigned q=0;q<8;q++)fprintf(f,"%s%" PRIu64,q?",":"",m.before[q]);fprintf(f,"],\"after\":[");for(unsigned q=0;q<8;q++)fprintf(f,"%s%" PRIu64,q?",":"",m.after[q]);fprintf(f,"]}\n");ASSERT(fclose(f)==0);}
 px_observer_free(o);return 0;}
static int query_failures(void){const int values[]={-1,0,1,175,177,INT_MAX};for(unsigned qi=1;qi<=8;qi++)for(unsigned j=0;j<sizeof(values)/sizeof(values[0]);j++){struct model m=model();m.fail_query=qi;m.query_return=values[j];struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);ASSERT(px_observer_poll(o,&e)==-1);ASSERT(m.queries==qi&&m.waits==1&&!m.bad_call);ASSERT(px_observer_owns_child(o));ASSERT(no_replay(o,&m));uint8_t b[4096];ASSERT(encode(o,b)==0);ASSERT(rd16(b+56)==qi);const uint8_t *v=b+256+(qi-1)*224;ASSERT((int32_t)rd32(v+32)==values[j]);ASSERT(rd16(v+40)==(PX_Q_ATTEMPTED|PX_Q_OPAQUE|PX_Q_AFTER));ASSERT(memcmp(v+48,m.raw[qi-1],176)==0);ASSERT(zero(v+224,(8-qi)*224));px_observer_free(o);}return 0;}
static int mutations(void){for(int k=1;k<=15;k++){struct model m=model();m.mutation=k;m.mutation_row=(k==6)?2:(k==15)?1:0;struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);ASSERT(px_observer_poll(o,&e)==-1);ASSERT(m.queries>0&&m.queries<=8&&!m.bad_call);ASSERT(px_observer_owns_child(o));ASSERT(no_replay(o,&m));uint8_t b[4096];ASSERT(encode(o,b)==0);ASSERT(!(rd32(b+68)&PX_MATCHED));px_observer_free(o);}return 0;}
static int waits(void){for(unsigned kind=0;kind<8;kind++){struct model m=model();struct px_plan p=plan();struct px_error e;if(kind==0)m.zero_waits=2;if(kind==1)m.eintr_waits=2;if(kind==2){m.wait_return=-1;m.wait_errno=ECHILD;}if(kind==3)m.wait_status=42<<8;if(kind==4)m.wait_status=SIGTERM;if(kind==5)m.wait_status=(18<<8)|0x7f;if(kind==6)m.wait_return=CHILD+1;if(kind==7)m.wait_status=(int32_t)UINT32_C(0x8000117f);struct px_observer *o=start(&m,&p,&e);ASSERT(o);int result=px_observer_poll(o,&e);if(kind<2){ASSERT(result==0&&m.queries==0);ASSERT(px_observer_poll(o,&e)==0);ASSERT(px_observer_poll(o,&e)==1);ASSERT(m.waits==3&&m.queries==8);ASSERT(px_observer_owns_child(o));}else{ASSERT(result==-1&&m.queries==0);ASSERT(px_observer_owns_child(o)==(kind>=5));ASSERT(no_replay(o,&m));}uint8_t b[4096];ASSERT(encode(o,b)==0);if(kind==2)ASSERT(rd32(b+68)&PX_LOST);if(kind==3||kind==4)ASSERT(rd32(b+68)&PX_REAPED);if(kind==7){ASSERT(!(rd32(b+68)&(PX_STOPPED|PX_ATTEMPTED)));ASSERT(rd32(b+2068)==UINT32_C(0x8000117f));}px_observer_free(o);}return 0;}
static int journal(void){struct model m=model();m.zero_waits=100;struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);for(unsigned i=0;i<64;i++){int result=px_observer_poll(o,&e);ASSERT(result==0||(i==63&&result==-1));}ASSERT(m.waits==64&&m.queries==0);ASSERT(px_observer_poll(o,&e)==-1);ASSERT(m.waits==64);ASSERT(no_replay(o,&m));uint8_t b[4096];ASSERT(encode(o,b)==0&&rd16(b+58)==64);px_observer_free(o);return 0;}
static int clocks(void){for(unsigned kind=0;kind<3;kind++)for(unsigned n=(kind==2?2:1);n<=19;n++){struct model m=model();struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);unsigned at=m.clocks+n;if(kind==0)m.fail_clock=at;if(kind==1)m.late_clock=at;if(kind==2)m.back_clock=at;ASSERT(px_observer_poll(o,&e)==-1);ASSERT(px_observer_owns_child(o));ASSERT(no_replay(o,&m));uint8_t b[4096];ASSERT(encode(o,b)==0);ASSERT(!(rd32(b+68)&PX_MATCHED));if(m.queries){const uint8_t *v=b+256+(m.queries-1)*224;ASSERT(rd32(v+32)==176);ASSERT(rd16(v+40)&PX_Q_FULL);}px_observer_free(o);}for(unsigned loss=0;loss<2;loss++){struct model m=model();if(loss){m.wait_return=-1;m.wait_errno=ECHILD;}else m.wait_status=42<<8;struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);m.fail_clock=m.clocks+2;ASSERT(px_observer_poll(o,&e)==-1);ASSERT(!px_observer_owns_child(o));ASSERT(no_replay(o,&m));uint8_t b[4096];ASSERT(encode(o,b)==0);ASSERT(rd32(b+68)&(loss?PX_LOST:PX_REAPED));px_observer_free(o);}return 0;}
static int arguments(void){struct px_plan p=plan();struct px_error e;struct model m=model();struct px_test_operations ops=operations(&m);ASSERT(!px_observer_model_new(NULL,&ops,&e));ASSERT(!px_observer_model_new(&p,NULL,&e));ASSERT(!px_observer_model_new(&p,&ops,NULL));for(unsigned k=0;k<5;k++){struct px_test_operations bad=ops;if(k==0)bad.getpid_fn=NULL;if(k==1)bad.policy_fn=NULL;if(k==2)bad.clock_fn=NULL;if(k==3)bad.wait_fn=NULL;if(k==4)bad.query_fn=NULL;ASSERT(!px_observer_model_new(&p,&bad,&e));}
 for(unsigned k=0;k<12;k++){struct px_plan bad=p;switch(k){case 0:bad.child=0;break;case 1:bad.child=OWNER;break;case 2:bad.held[0]=2;break;case 3:bad.held[1]=17;break;case 4:bad.sequence=0;break;case 5:bad.deadline=0;break;case 6:bad.exec_ordinal=0;break;case 7:bad.new_tid=0;break;case 8:memset(bad.digests[3],0,32);break;case 9:bad.original[0]^=1;break;case 10:bad.original[167]=0;break;case 11:bad.original[319]^=1;break;}ASSERT(!px_observer_model_new(&bad,&ops,&e));}
 m=model();m.owner=OWNER+1;ops=operations(&m);ASSERT(!px_observer_model_new(&p,&ops,&e));m=model();m.policy_return=-1;ops=operations(&m);ASSERT(!px_observer_model_new(&p,&ops,&e));m=model();struct px_observer *o=start(&m,&p,&e);ASSERT(o);m.owner++;ASSERT(px_observer_poll(o,&e)==-1&&m.waits==0&&m.queries==0);ASSERT(no_replay(o,&m));px_observer_free(o);uint8_t b[4096];memset(b,1,sizeof(b));ASSERT(px_observer_encode(NULL,b,&e)==-1&&zero(b,sizeof(b)));ASSERT(px_observer_encode(NULL,NULL,&e)==-1);ASSERT(px_observer_poll(NULL,&e)==-1);ASSERT(!px_observer_owns_child(NULL));px_observer_free(NULL);return 0;}
static int codec(const char *path){uint8_t raw[176],out[176];for(unsigned i=0;i<176;i++)raw[i]=(uint8_t)(i*53+11);ASSERT(px_codec_native_lp64le(raw,out)==0);if(path)ASSERT(save(path,out,sizeof(out))==0);memset(out,1,sizeof(out));ASSERT(px_codec_native_lp64le(NULL,out)==-1);ASSERT(zero(out,sizeof(out)));ASSERT(px_codec_native_lp64le(raw,NULL)==-1);return 0;}

static int final_guards(void){
 for(unsigned k=0;k<5;k++){
  struct model m=model();struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);
  if(k<3)m.fail_policy=m.policies+1+k;else if(k==3)m.owner_after_queries=1;else m.advance_policy=m.policies+3;
  ASSERT(px_observer_poll(o,&e)==-1);ASSERT(m.queries==(k>=2?8u:0u));ASSERT(m.waits==(k==0?0u:1u));ASSERT(no_replay(o,&m));
  uint8_t b[4096];ASSERT(encode(o,b)==0);ASSERT(!(rd32(b+68)&PX_MATCHED));ASSERT(rd16(b+56)==m.queries);if(k>0)ASSERT(rd32(b+68)&PX_ATTEMPTED);px_observer_free(o);
 }
 return 0;
}
static int failure_record(unsigned kind,const char *path){
 struct model m=model();struct px_plan p=plan();struct px_error e;struct px_observer *o=start(&m,&p,&e);ASSERT(o);
 if(kind==0){m.fail_query=3;m.query_return=175;}
 if(kind==1)m.fail_clock=m.clocks+4;
 if(kind==2){m.wait_status=42<<8;m.fail_clock=m.clocks+2;}
 if(kind==3){m.wait_return=-1;m.wait_errno=ECHILD;m.fail_clock=m.clocks+2;}
 if(kind==4)m.wait_status=(int32_t)UINT32_C(0x8000117f);
 if(kind==5)m.back_clock=m.clocks+4;
 if(kind==6)m.late_clock=m.clocks+4;
 if(kind==7)m.advance_policy=m.policies+3;
 ASSERT(px_observer_poll(o,&e)==-1);ASSERT(no_replay(o,&m));ASSERT(px_observer_owns_child(o)==(kind!=2&&kind!=3));
 uint8_t b[4096];ASSERT(encode(o,b)==0);ASSERT(save(path,b,sizeof(b))==0);char name[PATH_MAX];ASSERT(snprintf(name,sizeof(name),"%s.original",path)>0);ASSERT(save(name,p.original,sizeof(p.original))==0);px_observer_free(o);return 0;
}

#if defined(__APPLE__)
static int native_child(void){
 if(getuid()==0||getuid()!=geteuid())return 90;
 if(raise(SIGSTOP))return 91;
 const char a[]="owned child stdout\n",b[]="owned child stderr\n";
 if(write(1,a,sizeof(a)-1)!=(ssize_t)(sizeof(a)-1)||write(2,b,sizeof(b)-1)!=(ssize_t)(sizeof(b)-1))return 92;
 return 0;
}
static uint64_t monotonic(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;}
static int native(const char *self,const char *path){
 if(getuid()==0||getuid()!=geteuid())return 77;
 char dir[PATH_MAX],a[PATH_MAX],b[PATH_MAX];int fds[2]={-1,-1},failed=0,status=0,reaped=0,continued=0,lost=0,killed=0;
 const char *phase="open";pid_t child=-1;struct px_observer *o=NULL;struct px_error e;uint8_t packet[4096];struct px_plan p=plan();
 if(snprintf(dir,sizeof(dir),"%s.native-XXXXXX",path)<0||!mkdtemp(dir))return 1;
 if(snprintf(a,sizeof(a),"%s/stdout",dir)<0||snprintf(b,sizeof(b),"%s/stderr",dir)<0)return 1;
 fds[0]=open(a,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);fds[1]=open(b,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
 if(fds[0]<3||fds[1]<3){failed=1;goto cleanup;}
 struct stat s[2];if(fstat(fds[0],&s[0])||fstat(fds[1],&s[1])){failed=1;goto cleanup;}
 int before_fd[2]={fcntl(fds[0],F_GETFD),fcntl(fds[1],F_GETFD)},before_fl[2]={fcntl(fds[0],F_GETFL),fcntl(fds[1],F_GETFL)};
 if(before_fd[0]<0||before_fd[1]<0||before_fl[0]<0||before_fl[1]<0){failed=1;goto cleanup;}
 child=fork();if(child==-1){failed=1;goto cleanup;}
 if(child==0){
  if(dup2(fds[0],1)!=1||dup2(fds[1],2)!=2)_exit(93);
  if(close(fds[0])||close(fds[1]))_exit(94);
  char *args[]={(char *)self,"--native-child",NULL};char *environment[]={NULL};execve(self,args,environment);_exit(95);
 }
 p.child=(uint32_t)child;p.held[0]=fds[0];p.held[1]=fds[1];p.deadline=monotonic()+UINT64_C(5000000000);
 original(&p,(uint32_t)getpid(),p.child,fds[0],fds[1],(uint64_t)s[0].st_dev,(uint64_t)s[0].st_ino,(uint64_t)s[1].st_dev,(uint64_t)s[1].st_ino,s[0].st_mode,s[1].st_mode,(uint32_t)before_fl[0],(uint32_t)before_fl[1]);
 if(!CC_SHA256(p.original,sizeof(p.original),p.digests[4])){failed=1;goto cleanup;}
 phase="constructor";o=px_observer_new(&p,&e);if(!o){fprintf(stderr,"native constructor reason=%d errno=%d\n",e.reason,e.system_errno);failed=1;goto cleanup;}
 phase="observer-poll";
 for(;;){
  int r=px_observer_poll(o,&e);if(r==1)break;
  if(r<0){fprintf(stderr,"native poll reason=%d errno=%d\n",e.reason,e.system_errno);failed=1;goto cleanup;}
  struct timespec t={0,10000000};(void)nanosleep(&t,NULL);
 }
 phase="observer-output-check";
 if(!px_observer_owns_child(o)||px_observer_encode(o,packet,&e)){failed=1;goto cleanup;}
 if(rd16(packet+56)!=8||rd16(packet+60)!=PX_COMPLETE||(rd32(packet+68)&PX_MATCHED)==0){failed=1;goto cleanup;}
 phase="retain-packet";
 if(save(path,packet,sizeof(packet))){failed=1;goto cleanup;}
 char original_path[PATH_MAX];if(snprintf(original_path,sizeof(original_path),"%s.original",path)<0||save(original_path,p.original,sizeof(p.original))){failed=1;goto cleanup;}
 phase="query-metadata-check";
 for(unsigned q=0;q<8;q++){
  const uint8_t *row=packet+256+q*224;
  if(rd32(row+32)!=176||rd16(row+40)!=(PX_Q_ATTEMPTED|PX_Q_FULL|PX_Q_AFTER)||!rd64(row+24)){failed=1;goto cleanup;}
  for(unsigned j=0;j<q;j++)if(rd64(row+24)==rd64(packet+256+j*224+24)){failed=1;goto cleanup;}
 }
 phase="parent-reference-check";
 for(unsigned i=0;i<2;i++){
  int d=fcntl(fds[i],F_GETFD),f=fcntl(fds[i],F_GETFL);struct stat again;
  /* Child/runtime startup may set FWASWRITTEN before self-stop. The library
   * preserves contemporaneous raw flags; stale pre-exec F_GETFL is not a seed. */
  if(d!=before_fd[i]||f<0||((before_fl[i]^f)&~0x10000)!=0||fstat(fds[i],&again)||again.st_dev!=s[i].st_dev||again.st_ino!=s[i].st_ino||again.st_mode!=s[i].st_mode||again.st_nlink!=s[i].st_nlink){failed=1;goto cleanup;}
  if(f!=before_fl[i])fprintf(stderr,"ref[%u] observed status before=%x after=%x; descriptor/backing retained\n",i,before_fl[i],f);
 }
 if(kill(child,SIGCONT)){failed=1;goto cleanup;}continued=1;
cleanup:
 if(failed)fprintf(stderr,"native failed phase=%s\n",phase);
 if(child>0){
  if(o&&!px_observer_owns_child(o)){lost=1;failed=1;}
  uint64_t until=monotonic()+UINT64_C(5000000000);unsigned cleanup_polls=0;
  while(!reaped&&!lost&&cleanup_polls++<5000){
   int observed=0;pid_t w=waitpid(child,&observed,WNOHANG|WUNTRACED);
   if(w==child){
    if(WIFEXITED(observed)||WIFSIGNALED(observed)){status=observed;reaped=1;break;}
    if(WIFSTOPPED(observed)){
     if(kill(child,SIGCONT))failed=1;
     else continued=1;
    }else failed=1;
   }else if(w==-1&&errno!=EINTR){if(errno==ECHILD)lost=1;failed=1;break;}
   if(monotonic()>=until){failed=1;break;}
   struct timespec t={0,1000000};(void)nanosleep(&t,NULL);
  }
  if(!reaped&&!lost){
   failed=1;
   /* Final bounded failure cleanup only for the actual still-owned child. */
   if(kill(child,SIGKILL)){failed=1;}else killed=1;
   until=monotonic()+UINT64_C(5000000000);cleanup_polls=0;
   while(!reaped&&!lost&&cleanup_polls++<5000){
    int observed=0;pid_t w=waitpid(child,&observed,WNOHANG);
    if(w==child){status=observed;reaped=1;break;}
    if(w==-1&&errno!=EINTR){if(errno==ECHILD)lost=1;failed=1;break;}
    if(monotonic()>=until){failed=1;break;}
    struct timespec t={0,1000000};(void)nanosleep(&t,NULL);
   }
  }
 }
 px_observer_free(o);
 for(unsigned i=0;i<2;i++)if(fds[i]>=0&&close(fds[i]))failed=1;
 if(child>0&&reaped&&(!WIFEXITED(status)||WEXITSTATUS(status)))failed=1;
 if(!failed&&(!continued||!reaped||lost||killed))failed=1;
 printf("native continued=%d actual_child_reap=%d ownership_lost=%d killed=%d status=%d failed=%d\n",continued,reaped,lost,killed,status,failed);
 return failed?1:0;
}
#else
static int native(const char *self,const char *path){(void)self;(void)path;struct px_plan p=plan();struct px_error e;struct px_observer *o=px_observer_new(&p,&e);if(o){px_observer_free(o);return 1;}return e.reason==PX_UNSUPPORTED&&e.system_errno==ENOTSUP?77:1;}
#endif
int main(int argc,char **argv){
 if(argc<2)return 2;
#if defined(__APPLE__)
 if(!strcmp(argv[1],"--native-child"))return native_child();
#endif
 const char *path=argc>2?argv[2]:NULL;
 if(!strcmp(argv[1],"success"))return success(path);
 if(!strcmp(argv[1],"queries"))return query_failures();
 if(!strcmp(argv[1],"mutations"))return mutations();
 if(!strcmp(argv[1],"waits"))return waits();
 if(!strcmp(argv[1],"journal"))return journal();
 if(!strcmp(argv[1],"clocks"))return clocks();
 if(!strcmp(argv[1],"arguments"))return arguments();
 if(!strcmp(argv[1],"final-guards"))return final_guards();
 if(!strcmp(argv[1],"failure-short"))return path?failure_record(0,path):2;
 if(!strcmp(argv[1],"failure-clock"))return path?failure_record(1,path):2;
 if(!strcmp(argv[1],"terminal-clock"))return path?failure_record(2,path):2;
 if(!strcmp(argv[1],"lost-clock"))return path?failure_record(3,path):2;
 if(!strcmp(argv[1],"high-stop"))return path?failure_record(4,path):2;
 if(!strcmp(argv[1],"rollback-clock"))return path?failure_record(5,path):2;
 if(!strcmp(argv[1],"late-clock"))return path?failure_record(6,path):2;
 if(!strcmp(argv[1],"final-deadline"))return path?failure_record(7,path):2;
 if(!strcmp(argv[1],"codec"))return codec(path);
 if(!strcmp(argv[1],"native"))return path?native(argv[0],path):2;
 return 2;
}
