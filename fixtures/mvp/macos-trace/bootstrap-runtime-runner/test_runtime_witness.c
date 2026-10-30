/* Portable source controls: real witness module, explicit hash/write/error stubs.
 * No child, privilege, descriptor, provider or filesystem operation is modeled
 * as having occurred: retained observations are deliberately synthetic inputs. */
#include "runtime_profile.h"
#include "../bootstrap-runner/runner_internal.h"
#include "runtime_witness.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct retained { char name[32]; size_t used; unsigned char bytes[512]; int succeeded; };
static struct retained retained[8];
static unsigned writes, hashes, fail_write;
static int fail_hash;
static const struct nr_attempt *hash_attempt;

int nr_fail(struct nr_attempt *a,enum nr_stage stage,enum nr_reason reason,int saved,int detail)
{
    if(a->error.stage==NR_NONE)a->error=(struct nr_error){stage,reason,saved,detail};
    return -1;
}
int nr_sha_bytes(const uint8_t *bytes,size_t length,uint8_t out[32])
{
    ++hashes;
    assert(hash_attempt && bytes==hash_attempt->stream.raw && length==512);
    if(fail_hash)return -1;
    for(unsigned i=0;i<32;i++)out[i]=(uint8_t)(bytes[(i*7)%512]^i^0xa5);
    return 0;
}
int nr_write_new(struct nr_attempt *a,const char *name,const uint8_t *bytes,size_t length)
{
    assert(writes<8 && strlen(name)<sizeof(retained[0].name) && length<=512);
    struct retained *r=&retained[writes++];
    strcpy(r->name,name);r->used=length;
    if(length)memcpy(r->bytes,bytes,length);
    if(writes==fail_write)return nr_fail(a,NR_FINALIZE,NR_SYSCALL,ENOSPC,(int)writes);
    r->succeeded=1;return 0;
}
static void reset(void)
{
    memset(retained,0,sizeof(retained));writes=hashes=fail_write=0;fail_hash=0;hash_attempt=NULL;
}
static struct nrw_binding binding(void)
{
    struct nrw_binding b={0};b.owner=0x1234;b.child=0x3456;
    for(unsigned i=0;i<32;i++){b.request_sha[i]=(uint8_t)i;b.catalog_sha[i]=(uint8_t)(0x40+i);b.ready_sha[i]=(uint8_t)(0x80+i);}
    return b;
}
static struct tfo_reference_observation observation(unsigned count)
{
    struct tfo_reference_observation o;memset(&o,0xff,sizeof(o));o.completed_samples=count;
    for(unsigned i=0;i<4;i++){
        struct tfo_entry *v=&o.samples[i];v->fd=(i%2)?23:17;
        v->descriptor_flags=0x12345678+(int)i;v->status_flags=0x71234567+(int)i;
        v->backing.mode=UINT32_C(0xfedcba98)+i;
        v->backing.device=UINT64_C(0x0123456789abcdef)+i;
        v->backing.inode=UINT64_C(0xfedcba9876543210)+i;
        v->backing.links=UINT64_C(0x1122334455667788)+i;
    }
    return o;
}
static struct tfo_error sample_error(void)
{
    return (struct tfo_error){TFO_STAGE_REFERENCE_SECOND,TFO_REASON_SYSCALL,EIO,1,17};
}
static void emit(const void *bytes,size_t length)
{
    assert(fwrite(bytes,1,length,stdout)==length);
}
static void zero(const uint8_t *out,size_t n)
{
    for(size_t i=0;i<n;i++)assert(out[i]==0);
}
static void output_vector(unsigned count)
{
    assert(count<=4);struct nrw_binding b=binding();struct tfo_reference_observation o=observation(count);
    struct tfo_error e=sample_error();uint8_t out[NRW_OUTPUT_BYTES];
    assert(!nrw_output_encode(&b,&o,&e,out));
    for(size_t i=160+40*count;i<sizeof(out);i++)assert(out[i]==0);
    emit(out,sizeof(out));
}
static void output_refusals(void)
{
    struct nrw_binding good=binding(),b;struct tfo_reference_observation original=observation(4),o;
    struct tfo_error original_error=sample_error(),e;uint8_t out[NRW_OUTPUT_BYTES];
    for(unsigned control=0;control<18;control++){
        b=good;o=original;e=original_error;memset(out,0xa5,sizeof(out));
        switch(control){
        case 0:b.owner=0;break;case 1:b.child=0;break;
        case 2:b.owner=(uint32_t)INT_MAX+1u;break;case 3:b.child=b.owner;break;
        case 4:o.completed_samples=5;break;case 5:e.stage=(enum tfo_stage)-1;break;
        case 6:e.reason=(enum tfo_reason)(TFO_REASON_MISMATCH+1);break;
        case 7:e.system_errno=-1;break;case 8:e.role=-2;break;case 9:e.role=5;break;
        case 10:e.fd=-2;break;case 11:o.samples[3].fd=2;break;
        case 12:o.samples[1].descriptor_flags=-1;break;case 13:o.samples[2].status_flags=-1;break;
        default:break;
        }
        assert(nrw_output_encode(control==14?NULL:&b,control==15?NULL:&o,
                                 control==16?NULL:&e,control==17?NULL:out)==-1);
        if(control!=17)zero(out,sizeof(out));
    }
    b=good;b.owner=INT_MAX;b.child=INT_MAX-1;
    for(unsigned i=0;i<4;i++){o.samples[i]=original.samples[i];o.samples[i].descriptor_flags=INT_MAX;
        o.samples[i].status_flags=INT_MAX;o.samples[i].backing.mode=UINT32_MAX;
        o.samples[i].backing.device=o.samples[i].backing.inode=o.samples[i].backing.links=UINT64_MAX;}
    o.completed_samples=4;assert(!nrw_output_encode(&b,&o,&original_error,out));
    puts("output refusal clears complete advertised output; full integer widths retained");
}
static void delivery(unsigned mode,unsigned *action,int *attempted,struct bio_result *r,
                     struct bio_error *e,int *written,int *closed,int *saved)
{
    memset(r,0,sizeof(*r));memset(e,0,sizeof(*e));*action=BR_SEND_GO;*attempted=1;*written=*closed=*saved=0;
    r->bytes_moved=64;for(unsigned i=0;i<sizeof(r->prefix);i++)r->prefix[i]=(uint8_t)(i*3+7);
    if(mode==1){r->bytes_moved=19;*written=-1;*e=(struct bio_error){BIO_STAGE_WRITE,BIO_REASON_SYSCALL,EPIPE,19};}
    if(mode==2){*written=-1;*e=(struct bio_error){BIO_STAGE_OBSERVER,BIO_REASON_OBSERVER,0,64};}
    if(mode==3){*closed=-1;*saved=EIO;}
    if(mode==4){*action=BR_SIMULATED_PROVIDER_FAILURE;*attempted=0;r->bytes_moved=0;}
}
static void delivery_vector(unsigned mode)
{
    assert(mode<=4);struct nrw_binding b=binding();struct bio_result r;struct bio_error e;
    unsigned action;int attempted,written,closed,saved;uint8_t out[NRW_DELIVERY_BYTES];
    delivery(mode,&action,&attempted,&r,&e,&written,&closed,&saved);
    assert(!nrw_delivery_encode(&b,action,attempted,&r,&e,written,1,closed,saved,out));
    for(size_t i=176+r.bytes_moved;i<sizeof(out);i++)assert(!out[i]);
    emit(out,sizeof(out));
}
static void delivery_refusals(void)
{
    struct nrw_binding good=binding(),b;struct bio_result r;struct bio_error e;uint8_t out[NRW_DELIVERY_BYTES];
    unsigned action;int attempted,written,closed,saved,close_attempted;
    for(unsigned control=0;control<17;control++){
        b=good;delivery(0,&action,&attempted,&r,&e,&written,&closed,&saved);close_attempted=1;
        switch(control){
        case 0:action=0;break;case 1:attempted=2;break;case 2:r.bytes_moved=65;break;
        case 3:e.stage=(enum bio_stage)-1;break;case 4:e.reason=(enum bio_reason)(BIO_REASON_OBSERVER+1);break;
        case 5:e.system_errno=-1;break;case 6:e.bytes_moved=65;break;case 7:written=1;break;
        case 8:close_attempted=0;break;case 9:closed=1;break;case 10:saved=-1;break;
        case 11:b.owner=b.child;break;case 12:b.child=(uint32_t)INT_MAX+1u;break;
        default:break;
        }
        memset(out,0xa5,sizeof(out));
        assert(nrw_delivery_encode(control==13?NULL:&b,action,attempted,control==14?NULL:&r,
            control==15?NULL:&e,written,close_attempted,closed,saved,control==16?NULL:out)==-1);
        if(control<16)zero(out,sizeof(out));
    }
    puts("delivery bounds and null inputs refuse with complete cleared output");
}
static void attempt(struct nr_attempt *a,int changed)
{
    reset();memset(a,0,sizeof(*a));a->owner=0x1234;a->child=0x3456;a->stream.used=1024;
    for(unsigned i=0;i<32;i++){a->request_sha[i]=(uint8_t)i;a->catalog_sha[i]=(uint8_t)(0x40+i);}
    for(unsigned i=0;i<512;i++)a->stream.raw[i]=(uint8_t)(11+i*9+(changed?1:0));
    memset(a->stream.raw+512,0xee,512);a->request.release_action=BR_SEND_GO;hash_attempt=a;
}
static void ready_adapter(int changed,int prefix)
{
    struct nr_attempt a;attempt(&a,changed);struct tfo_reference_observation o=observation(prefix?2:4);
    a.object_match_error=prefix?sample_error():(struct tfo_error){TFO_STAGE_NONE,TFO_REASON_NONE,0,-1,-1};
    if(prefix)a.error=(struct nr_error){NR_READY,NR_HELPER,EIO,55};
    assert(!nrw_record_ready(&a,&o));assert(a.runtime_witness_attempted && a.runtime_witness_written && writes==1 && hashes==1);
    assert(!strcmp(retained[0].name,"output-witness.bin") && retained[0].used==320 && retained[0].succeeded);
    if(prefix)assert(a.error.stage==NR_READY && a.error.reason==NR_HELPER && a.error.detail==55);
    assert(nrw_record_ready(&a,&o)==-1);assert(writes==1 && hashes==1);
    if(prefix)assert(a.error.reason==NR_HELPER && a.error.detail==55);
    emit(retained[0].bytes,retained[0].used);
}
static void delivery_adapter(unsigned mode)
{
    struct nr_attempt a;attempt(&a,0);struct tfo_reference_observation o=observation(4);
    a.object_match_error=(struct tfo_error){TFO_STAGE_NONE,TFO_REASON_NONE,0,-1,-1};assert(!nrw_record_ready(&a,&o));
    unsigned action;int attempted,written,closed,saved;
    delivery(mode,&action,&attempted,&a.go_result,&a.go_error,&written,&closed,&saved);
    a.request.release_action=action;a.go_attempted=attempted;
    if(written)a.error=(struct nr_error){NR_GO,NR_HELPER,a.go_error.system_errno,77};
    assert(!nrw_record_delivery(&a,written,closed,saved));assert(a.runtime_delivery_attempted && a.runtime_delivery_written && writes==3 && hashes==2);
    assert(!strcmp(retained[1].name,"go-prefix.bin") && retained[1].used==a.go_result.bytes_moved);
    assert(!memcmp(retained[1].bytes,a.go_result.prefix,retained[1].used));
    assert(!strcmp(retained[2].name,"gate-delivery.bin") && retained[2].used==240);
    if(written)assert(a.error.stage==NR_GO && a.error.detail==77);
    assert(nrw_record_delivery(&a,written,closed,saved)==-1);assert(writes==3 && hashes==2);
    if(written)assert(a.error.detail==77);
    emit(retained[2].bytes,retained[2].used);
}
static void adapter_refusals(void)
{
    struct nr_attempt a;struct tfo_reference_observation o=observation(4);
    for(unsigned mode=0;mode<9;mode++){
        attempt(&a,0);a.object_match_error=(struct tfo_error){TFO_STAGE_NONE,TFO_REASON_NONE,0,-1,-1};
        if(mode==0)a.stream.used=511;
        if(mode==1)a.owner=0;
        if(mode==2)a.child=a.owner;
        if(mode==3)fail_hash=1;
        if(mode==4)fail_write=1;
        if(mode<=4){
            assert(nrw_record_ready(&a,&o)==-1 && !a.runtime_witness_written);
            assert(writes==(mode==4?1u:0u));
            if(mode==3)assert(a.error.stage==NR_READY && a.error.reason==NR_HELPER);
            if(mode==4)assert(a.error.stage==NR_FINALIZE && a.error.saved_errno==ENOSPC);
            assert(a.runtime_witness_attempted);
            unsigned prior_writes=writes,prior_hashes=hashes;struct nr_error first=a.error;
            fail_hash=0;fail_write=0;
            assert(nrw_record_ready(&a,&o)==-1 && writes==prior_writes && hashes==prior_hashes);
            assert(a.error.stage==first.stage && a.error.reason==first.reason && a.error.saved_errno==first.saved_errno && a.error.detail==first.detail);
            continue;
        }
        if(mode==5){
            assert(nrw_record_delivery(&a,0,0,0)==-1 && !writes && !hashes && a.runtime_delivery_attempted);
            assert(nrw_record_delivery(&a,0,0,0)==-1 && !writes && !hashes);continue;
        }
        assert(!nrw_record_ready(&a,&o));
        unsigned action;int attempted,written,closed,saved;
        delivery(0,&action,&attempted,&a.go_result,&a.go_error,&written,&closed,&saved);a.go_attempted=attempted;
        fail_write=mode==6?2:3;
        if(mode==8)a.error=(struct nr_error){NR_GO,NR_HELPER,EPIPE,99};
        assert(nrw_record_delivery(&a,written,closed,saved)==-1 && !a.runtime_delivery_written);
        assert(writes==(mode==6?2u:3u));
        assert(!retained[writes-1].succeeded);
        if(mode==6)assert(!strcmp(retained[1].name,"go-prefix.bin"));
        else assert(retained[1].succeeded && !strcmp(retained[2].name,"gate-delivery.bin"));
        if(mode==8)assert(a.error.stage==NR_GO && a.error.saved_errno==EPIPE && a.error.detail==99);
        else assert(a.error.stage==NR_FINALIZE && a.error.saved_errno==ENOSPC);
        assert(a.runtime_delivery_attempted);
        unsigned prior_writes=writes,prior_hashes=hashes;struct nr_error first=a.error;fail_write=0;
        assert(nrw_record_delivery(&a,written,closed,saved)==-1 && writes==prior_writes && hashes==prior_hashes);
        assert(a.error.stage==first.stage && a.error.reason==first.reason && a.error.saved_errno==first.saved_errno && a.error.detail==first.detail);
    }
    puts("actual adapter refuses short READY and invalid PIDs, preserves first error and failed retention, no successful written flag");
}
int main(int argc,char **argv)
{
    assert(argc>=2);
    if(!strcmp(argv[1],"output")){assert(argc==3);output_vector((unsigned)strtoul(argv[2],NULL,10));}
    else if(!strcmp(argv[1],"output-refusals"))output_refusals();
    else if(!strcmp(argv[1],"delivery")){assert(argc==3);delivery_vector((unsigned)strtoul(argv[2],NULL,10));}
    else if(!strcmp(argv[1],"delivery-refusals"))delivery_refusals();
    else if(!strcmp(argv[1],"ready"))ready_adapter(0,0);
    else if(!strcmp(argv[1],"ready-changed"))ready_adapter(1,0);
    else if(!strcmp(argv[1],"ready-prefix"))ready_adapter(0,1);
    else if(!strcmp(argv[1],"adapter-delivery")){assert(argc==3);delivery_adapter((unsigned)strtoul(argv[2],NULL,10));}
    else if(!strcmp(argv[1],"adapter-refusals"))adapter_refusals();
    else assert(!"unknown source control");
    return 0;
}
