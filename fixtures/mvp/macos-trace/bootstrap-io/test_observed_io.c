#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include "bootstrap_io.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
struct model {
 uint64_t now, expected_deadline;
 unsigned clocks, polls, reads, writes, pumps; size_t moved;
 int writing,eof,sequence,storm,frozen,poll_fault,clock_bad,after_poll_fault;
 int fail_first,bad_return,fail_partial,fail_full,fail_eof,late_full,late_first,rollback;
 int io_error,truncated,trailing,flags_bad,eof_seen,max_timeout;
};
static struct bio_time when(uint64_t n) {struct bio_time t={n/1000000000,n%1000000000};return t;}
static struct model fresh(void) {struct model m;memset(&m,0,sizeof(m));m.now=1000000000;m.expected_deadline=1200000000;return m;}
static int clock_cb(void *v,struct bio_time *t,int *e) {
 struct model *m=v;m->clocks++;if(m->clock_bad){*e=EIO;return -1;}*t=when(m->now);return 0;
}
static int stat_cb(void *v,int fd,mode_t *mode,int *e) {(void)v;(void)e;CHECK(fd==9);*mode=S_IFIFO|0600;return 0;}
static int flags_cb(void *v,int fd,int *e) {struct model *m=v;(void)e;CHECK(fd==9);return O_NONBLOCK|(m->flags_bad?O_RDWR:m->writing?O_WRONLY:O_RDONLY);}
static int poll_cb(void *v,int fd,short wanted,int timeout,short *events,int *e) {
 struct model *m=v;CHECK(fd==9&&timeout>0);m->polls++;
 if(timeout>m->max_timeout)m->max_timeout=timeout;
 if(!m->frozen)m->now+=(uint64_t)timeout*1000000;
 *events=0;
 if(m->poll_fault) {
  m->clock_bad=1;
  switch(m->poll_fault) {
   case 1:*e=EACCES;return -1;
   case 2:return 2;
   case 3:*events=wanted;return 0;
   case 4:*events=POLLNVAL;return 1;
   case 5:*events=POLLERR;return 1;
   case 6:*events=0x4000;return 1;
   default:return 1;
  }
 }
 if(m->storm)return 0;
 if(m->sequence&&m->polls==1)return 0;
 if(m->sequence&&m->polls==2){*e=EINTR;return -1;}
 *events=wanted;return 1;
}
static ssize_t read_cb(void *v,int fd,void *p,size_t n,int *e) {
 struct model *m=v;CHECK(fd==9);m->reads++;
 if(m->io_error){m->clock_bad=1;*e=EACCES;return -1;}
 if(m->sequence&&m->reads==1){*e=EAGAIN;return -1;}
 if(m->eof){CHECK(n==1);if(m->trailing){*(unsigned char *)p=0x5a;m->moved=1;return 1;}m->eof_seen=1;return 0;}
 if(m->truncated)return 0;
 size_t amount=m->fail_partial?16:n;CHECK(amount<=n);memset(p,0x5a,amount);m->moved+=amount;return (ssize_t)amount;
}
static ssize_t write_cb(void *v,int fd,const void *p,size_t n,int *e) {
 struct model *m=v;(void)e;CHECK(fd==9);m->writes++;CHECK(n>0&&((const unsigned char *)p)[0]==(unsigned char)m->moved);
 m->moved+=n;return (ssize_t)n;
}
static int progress_cb(void *v,struct bio_time d) {
 struct model *m=v;m->pumps++;CHECK(d.seconds==m->expected_deadline/1000000000&&d.nanoseconds==m->expected_deadline%1000000000);
 if(m->rollback)m->now=0;
 if(m->late_first||(m->late_full&&m->moved==64))m->now=m->expected_deadline;
 if(m->bad_return)return 7;
 if(m->fail_first||(m->after_poll_fault&&m->polls)||(m->fail_partial&&m->moved)||
    (m->fail_full&&m->moved==64)||(m->fail_eof&&m->eof_seen)){m->clock_bad=1;return -1;}
 return 0;
}
static int run(struct model *m,int legacy,struct bio_result *r,struct bio_error *e) {
 struct bio_operations o={m,clock_cb,stat_cb,flags_cb,poll_cb,read_cb,write_cb};
 struct bio_observer v={m,progress_cb};struct bio_time d=when(m->expected_deadline);
 unsigned char input[64];for(unsigned i=0;i<64;i++)input[i]=(unsigned char)i;
 if(m->writing)return legacy?bio_write_record(9,input,64,d,&o,r,e):bio_write_record_observed(9,input,64,d,&o,&v,r,e);
 if(m->eof)return legacy?bio_require_eof(9,d,&o,r,e):bio_require_eof_observed(9,d,&o,&v,r,e);
 return legacy?bio_read_record(9,256,d,&o,r,e):bio_read_record_observed(9,256,d,&o,&v,r,e);
}
static void arguments(void) {
 struct model m=fresh();struct bio_operations o={&m,clock_cb,stat_cb,flags_cb,poll_cb,read_cb,write_cb};
 struct bio_observer v={&m,NULL};struct bio_result r;struct bio_error e;
 CHECK(bio_read_record_observed(9,256,when(m.expected_deadline),&o,NULL,&r,&e)==-1&&e.stage==BIO_STAGE_OPERATIONS);
 CHECK(bio_require_eof_observed(9,when(m.expected_deadline),&o,&v,&r,&e)==-1&&m.clocks==0);
 CHECK(BIO_STAGE_OBSERVER==9&&BIO_REASON_OBSERVER==20);
 CHECK(!strcmp(bio_stage_name(BIO_STAGE_OBSERVER),"observer")&&!strcmp(bio_reason_name(BIO_REASON_OBSERVER),"observer"));
 m.flags_bad=1;CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_ACCESS&&m.pumps==0);
}
static void success(void) {
 struct bio_result r;struct bio_error e;struct model m=fresh();
 CHECK(run(&m,0,&r,&e)==0&&r.bytes_moved==256&&m.reads==1&&m.pumps>=3&&m.max_timeout==20);
 for(size_t i=0;i<256;i++)CHECK(r.prefix[i]==0x5a);
 m=fresh();m.writing=1;CHECK(run(&m,0,&r,&e)==0&&r.bytes_moved==64&&m.writes==1);
 m=fresh();m.frozen=1;CHECK(run(&m,1,&r,&e)==0&&m.pumps==0&&m.max_timeout==200);
}
static void progress(void) {
 struct model m=fresh();m.sequence=1;struct bio_result r;struct bio_error e;
 CHECK(run(&m,0,&r,&e)==0&&m.polls==4&&m.reads==2&&m.pumps>=m.polls&&m.max_timeout==20&&r.bytes_moved==256);
}
static void observer_failures(void) {
 struct model m=fresh();m.fail_first=1;struct bio_result r;struct bio_error e;
 CHECK(run(&m,0,&r,&e)==-1&&e.stage==BIO_STAGE_OBSERVER&&e.reason==BIO_REASON_OBSERVER&&e.system_errno==0&&r.bytes_moved==0&&m.polls==0);
 m=fresh();m.bad_return=1;CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_ADAPTER&&e.system_errno==0&&m.polls==0);
}
static void confirmed_prefix(void) {
 struct bio_result r;struct bio_error e;struct model m=fresh();m.fail_partial=1;
 CHECK(run(&m,0,&r,&e)==-1&&r.bytes_moved==16&&e.bytes_moved==16&&e.stage==BIO_STAGE_OBSERVER&&m.reads==1);
 for(size_t i=0;i<256;i++)CHECK(r.prefix[i]==(i<16?0x5a:0));
 m=fresh();m.writing=1;m.fail_full=1;CHECK(run(&m,0,&r,&e)==-1&&r.bytes_moved==64&&e.bytes_moved==64&&e.reason==BIO_REASON_OBSERVER&&m.writes==1);
 for(size_t i=0;i<256;i++)CHECK(r.prefix[i]==(i<64?(unsigned char)i:0));
 m=fresh();m.writing=1;m.late_full=1;CHECK(run(&m,0,&r,&e)==-1&&r.bytes_moved==64&&e.reason==BIO_REASON_DEADLINE&&m.writes==1);
}
static void poll_priority(void) {
 struct bio_result r;struct bio_error e;
 for(int fault=1;fault<=7;fault++) {
  struct model m=fresh();m.poll_fault=fault;m.after_poll_fault=1;
  CHECK(run(&m,0,&r,&e)==-1&&e.stage==BIO_STAGE_POLL&&m.pumps==1&&m.reads==0&&m.writes==0);
  CHECK(e.reason==(fault==1?BIO_REASON_SYSCALL:fault==2?BIO_REASON_ADAPTER:fault==4?BIO_REASON_POLL_INVALID:fault==5?BIO_REASON_POLL_ERROR:BIO_REASON_POLL_EVENT));
  CHECK(e.system_errno==(fault==1?EACCES:0));
 }
 struct model m=fresh();m.io_error=1;CHECK(run(&m,0,&r,&e)==-1&&e.stage==BIO_STAGE_READ&&e.system_errno==EACCES);
 m=fresh();m.truncated=1;CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_TRUNCATED);
}
static void deadlines(void) {
 struct bio_result r;struct bio_error e;struct model m=fresh();m.storm=1;
 CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_DEADLINE&&m.polls==10&&m.pumps>=10&&m.reads==0);
 m=fresh();m.late_first=1;CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_DEADLINE&&m.polls==0);
 m=fresh();m.rollback=1;CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_CLOCK_ROLLBACK&&m.polls==0);
 m=fresh();m.storm=1;m.expected_deadline=m.now+10500000;
 CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_DEADLINE&&m.max_timeout==11&&m.reads==0);
}
static void bounds(void) {
 struct bio_result r;struct bio_error e;struct model m=fresh();m.storm=m.frozen=1;
 CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_RETRY_LIMIT&&m.polls==BIO_MAX_STEPS&&m.pumps==2*BIO_MAX_STEPS);
 m=fresh();m.expected_deadline=m.now;CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_DEADLINE&&m.pumps==0);
 struct bio_operations o={&m,clock_cb,stat_cb,flags_cb,poll_cb,read_cb,write_cb};struct bio_observer v={&m,progress_cb};
 CHECK(bio_read_record_observed(9,256,(struct bio_time){UINT64_MAX,0},&o,&v,&r,&e)==-1&&e.reason==BIO_REASON_TIME_OVERFLOW&&m.pumps==0);
}
static void eof(void) {
 struct bio_result r;struct bio_error e;struct model m=fresh();m.eof=1;
 CHECK(run(&m,0,&r,&e)==0&&m.reads==1&&m.pumps>=3&&r.bytes_moved==0);
 m=fresh();m.eof=m.fail_eof=1;CHECK(run(&m,0,&r,&e)==-1&&e.reason==BIO_REASON_OBSERVER&&m.reads==1&&r.bytes_moved==0);
 m=fresh();m.eof=m.trailing=m.fail_partial=1;
 CHECK(run(&m,0,&r,&e)==-1&&e.stage==BIO_STAGE_EOF&&e.reason==BIO_REASON_TRAILING&&r.bytes_moved==1&&r.prefix[0]==0x5a&&m.pumps==2);
}
int main(int argc,char **argv) {
 CHECK(argc==2);
 struct entry {const char *name;void (*fn)(void);} cases[]={
 {"arguments",arguments},{"success",success},{"progress",progress},{"observer-failures",observer_failures},
 {"confirmed-prefix",confirmed_prefix},{"poll-priority",poll_priority},{"deadlines",deadlines},{"bounds",bounds},{"eof",eof}};
 for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++)if(!strcmp(argv[1],cases[i].name)){cases[i].fn();puts(argv[1]);return 0;}
 return 2;
}
