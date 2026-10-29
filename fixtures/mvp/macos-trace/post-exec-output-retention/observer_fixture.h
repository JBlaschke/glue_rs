/* Small untrusted source fixture: actual opaque observer/encoder, modeled wait,
 * query and child ownership. No native child/provider/stop claim is made. */
#ifndef GLUE_RETENTION_OBSERVER_FIXTURE_H
#define GLUE_RETENTION_OBSERVER_FIXTURE_H
#include "../post-exec-output/post_exec_output_test.h"
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
struct observer_fixture { struct px_plan plan; unsigned queries; int state,real_time; uint64_t now; };
static void fixture_put(uint8_t *p,uint64_t n,unsigned width,int little){for(unsigned i=0;i<width;i++)p[i]=(uint8_t)(n>>(8*(little?i:width-i-1)));}
static uint64_t fixture_now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;}
static pid_t fixture_owner(void *c){(void)c;return getpid();}
static int fixture_policy(void *c,int *e){(void)c;(void)e;return 0;}
static int fixture_clock(void *c,uint64_t *out,int *e){(void)e;struct observer_fixture *f=c;*out=f->real_time?fixture_now():++f->now;return 0;}
static pid_t fixture_wait(void *c,pid_t child,int *status,int options,int *e){
 (void)options;struct observer_fixture *f=c;
 if(f->state==2){*e=ECHILD;return -1;}if(f->state==3){*status=0;return child;}
 *status=(17<<8)|0x7f;return child;
}
static int fixture_query(void *c,pid_t pid,int fd,uint8_t out[176],int *e){
 (void)pid;(void)fd;struct observer_fixture *f=c;unsigned q=f->queries++,role=q&1u;
 memset(out,0,176);fixture_put(out,2,4,1);fixture_put(out+4,q<2||q>=6?2:0,4,1);
 fixture_put(out+16,1,4,1);fixture_put(out+24,9,4,1);fixture_put(out+28,0100600,2,1);
 fixture_put(out+30,1,2,1);fixture_put(out+32,11+role,8,1);fixture_put(out+160,1,4,1);
 if(f->state==1){*e=EIO;return 175;}return 176;
}
static struct px_observer *fixture_observer(struct observer_fixture *f,int state,int real_time){
 memset(f,0,sizeof(*f));f->state=state;f->real_time=real_time;f->now=100;
 struct px_plan *p=&f->plan;p->child=(uint32_t)getpid()+1;p->held[0]=17;p->held[1]=23;
 p->sequence=1;p->deadline=real_time?fixture_now()+UINT64_C(10000000000):1000000;p->exec_ordinal=7;p->new_tid=99;
 for(unsigned i=0;i<5;i++)memset(p->digests[i],(int)i+1,32);
 uint8_t *b=p->original;memcpy(b,"GLUERW01",8);fixture_put(b+8,1,4,0);fixture_put(b+12,320,4,0);
 fixture_put(b+16,(uint32_t)getpid(),4,0);fixture_put(b+20,p->child,4,0);fixture_put(b+24,4,4,0);
 memcpy(b+32,p->digests,96);fixture_put(b+140,UINT32_MAX,4,0);fixture_put(b+144,UINT32_MAX,4,0);
 for(unsigned i=0;i<4;i++){unsigned role=i&1u;uint8_t *r=b+160+40*i;
  fixture_put(r,role?23:17,4,0);fixture_put(r+4,1,4,0);fixture_put(r+8,1,4,0);
  fixture_put(r+12,0100600,4,0);fixture_put(r+16,9,8,0);fixture_put(r+24,11+role,8,0);fixture_put(r+32,1,8,0);}
 struct px_test_operations ops={f,fixture_owner,fixture_policy,fixture_clock,fixture_wait,fixture_query};
 struct px_error error;struct px_observer *o=px_observer_model_new(p,&ops,&error);
 if(o&&state!=4)(void)px_observer_poll(o,&error);return o;
}
#endif
