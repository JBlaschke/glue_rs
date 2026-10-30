#include "runtime_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include "runtime_witness.h"
#include <limits.h>
#include <string.h>
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(n>>(24-8*i));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(n>>(56-8*i));}
static int binding_valid(const struct nrw_binding *b){
 return b&&b->owner&&b->owner<=INT_MAX&&b->child&&b->child<=INT_MAX&&b->owner!=b->child;
}
static void header(uint8_t *out,const char magic[8],uint32_t size,const struct nrw_binding *b){
 memcpy(out,magic,8);put32(out+8,1);put32(out+12,size);put32(out+16,b->owner);put32(out+20,b->child);
 memcpy(out+32,b->request_sha,32);memcpy(out+64,b->catalog_sha,32);memcpy(out+96,b->ready_sha,32);
}
int nrw_output_encode(const struct nrw_binding *b,const struct tfo_reference_observation *o,
 const struct tfo_error *e,uint8_t out[NRW_OUTPUT_BYTES]){
 if(out)memset(out,0,NRW_OUTPUT_BYTES);
 if(!out||!binding_valid(b)||!o||!e||o->completed_samples>4||
    (unsigned)e->stage>TFO_STAGE_MATCH||(unsigned)e->reason>TFO_REASON_MISMATCH||
    e->system_errno<0||e->role < -1||e->role>4||e->fd < -1)return -1;
 for(unsigned i=0;i<o->completed_samples;i++){
  const struct tfo_entry *v=&o->samples[i];
  if(v->fd<3||v->descriptor_flags<0||v->status_flags<0)return -1;
 }
 header(out,"GLUERW01",NRW_OUTPUT_BYTES,b);put32(out+24,o->completed_samples);
 put32(out+128,(uint32_t)e->stage);put32(out+132,(uint32_t)e->reason);put32(out+136,(uint32_t)e->system_errno);
 put32(out+140,(uint32_t)e->role);put32(out+144,(uint32_t)e->fd);
 for(unsigned i=0;i<o->completed_samples;i++){
  const struct tfo_entry *v=&o->samples[i];uint8_t *row=out+160+40*i;
  put32(row,(uint32_t)v->fd);put32(row+4,(uint32_t)v->descriptor_flags);put32(row+8,(uint32_t)v->status_flags);
  put32(row+12,v->backing.mode);put64(row+16,v->backing.device);put64(row+24,v->backing.inode);put64(row+32,v->backing.links);
 }
 return 0;
}
int nrw_delivery_encode(const struct nrw_binding *b,unsigned action,int attempted,
 const struct bio_result *r,const struct bio_error *e,int written,int close_attempted,
 int closed,int close_errno,uint8_t out[NRW_DELIVERY_BYTES]){
 if(out)memset(out,0,NRW_DELIVERY_BYTES);
 if(!out||!binding_valid(b)||!r||!e||(action!=BR_SEND_GO&&action!=BR_SIMULATED_PROVIDER_FAILURE)||
    (attempted!=0&&attempted!=1)||r->bytes_moved>BIO_GO_RECORD_BYTES||
    (unsigned)e->stage>BIO_STAGE_OBSERVER||(unsigned)e->reason>BIO_REASON_OBSERVER||
    e->system_errno<0||e->bytes_moved>BIO_GO_RECORD_BYTES||(written!=0&&written!=-1)||
    close_attempted!=1||(closed!=0&&closed!=-1)||close_errno<0)return -1;
 header(out,"GLUERD01",NRW_DELIVERY_BYTES,b);put32(out+24,action);put32(out+28,(uint32_t)attempted);
 put32(out+128,(uint32_t)r->bytes_moved);put32(out+132,(uint32_t)e->stage);put32(out+136,(uint32_t)e->reason);
 put32(out+140,(uint32_t)e->system_errno);put32(out+144,(uint32_t)e->bytes_moved);put32(out+148,(uint32_t)written);
 put32(out+152,(uint32_t)close_attempted);put32(out+156,(uint32_t)closed);put32(out+160,(uint32_t)close_errno);
 memcpy(out+176,r->prefix,r->bytes_moved);return 0;
}
static int actual_binding(struct nr_attempt *a,struct nrw_binding *b){
 if(a->owner<=0||a->child<=0||a->owner>INT_MAX||a->child>INT_MAX||a->stream.used<BOW_STATUS_SIZE)
  return nr_fail(a,NR_READY,NR_INVALID,0,-1);
 memset(b,0,sizeof(*b));b->owner=(uint32_t)a->owner;b->child=(uint32_t)a->child;
 memcpy(b->request_sha,a->request_sha,32);memcpy(b->catalog_sha,a->catalog_sha,32);
 if(nr_sha_bytes(a->stream.raw,BOW_STATUS_SIZE,b->ready_sha))return nr_fail(a,NR_READY,NR_HELPER,0,-1);
 return 0;
}
int nrw_record_ready(struct nr_attempt *a,const struct tfo_reference_observation *o){
 struct nrw_binding b;uint8_t bytes[NRW_OUTPUT_BYTES];
 if(a->runtime_witness_attempted)return nr_fail(a,NR_READY,NR_INVALID,0,-1);
 a->runtime_witness_attempted=1;
 if(a->runtime_witness_written||actual_binding(a,&b)||nrw_output_encode(&b,o,&a->object_match_error,bytes))
  return nr_fail(a,NR_READY,NR_INVALID,0,-1);
 if(nr_write_new(a,"output-witness.bin",bytes,sizeof(bytes)))return -1;
 a->runtime_witness_written=1;return 0;
}
int nrw_record_delivery(struct nr_attempt *a,int written,int closed,int close_errno){
 struct nrw_binding b;uint8_t bytes[NRW_DELIVERY_BYTES];
 if(a->runtime_delivery_attempted)return nr_fail(a,NR_GO,NR_INVALID,0,-1);
 a->runtime_delivery_attempted=1;
 if(a->runtime_delivery_written||!a->runtime_witness_written||actual_binding(a,&b)||
    nrw_delivery_encode(&b,a->request.release_action,a->go_attempted,&a->go_result,&a->go_error,
                        written,1,closed,close_errno,bytes))return nr_fail(a,NR_GO,NR_INVALID,0,-1);
 if(nr_write_new(a,"go-prefix.bin",a->go_result.prefix,a->go_result.bytes_moved)||
    nr_write_new(a,"gate-delivery.bin",bytes,sizeof(bytes)))return -1;
 a->runtime_delivery_written=1;return 0;
}
