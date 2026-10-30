#include "runtime_request.h"
#include <string.h>
static const uint8_t magic[8]={'G','L','U','E','R','R','0','1'};
static enum br_fault bad(struct br_error *e,enum br_fault f){
 if(e)*e=(struct br_error){f,BR_FIELD_HEADER,BR_NO_INDEX,BW_OK};
 return f;
}
static int selected(const struct br_request *r){return r&&r->fixture==2&&r->argv_template==2&&!r->environment_count;}
enum br_fault rr_request_encode(const struct br_request *r,uint8_t out[BR_MAX_WIRE],size_t *used,struct br_error *e){
 if(out)memset(out,0,BR_MAX_WIRE);
 if(used)*used=0;
 if(!out||!used||!e||!selected(r))return bad(e,BR_SELECTOR);
 struct br_request inner=*r;inner.fixture=1;inner.argv_template=1;
 enum br_fault f=br_request_encode(&inner,out,used,e);if(f!=BR_OK)return f;
 memcpy(out,magic,8);out[19]=2;out[123]=2;return BR_OK;
}
enum br_fault rr_request_decode(const uint8_t *in,size_t n,struct br_request *out,struct br_error *e){
 if(out)memset(out,0,sizeof(*out));
 if(!in||!out||!e)return bad(e,BR_ARGUMENT);
 if(n<BR_HEADER_SIZE||n>BR_MAX_WIRE)return bad(e,BR_LENGTH);
 if(memcmp(in,magic,8))return bad(e,BR_MAGIC);
 if(memcmp(in+16,"\0\0\0\2",4)||memcmp(in+120,"\0\0\0\2",4))return bad(e,BR_SELECTOR);
 uint8_t bytes[BR_MAX_WIRE];memcpy(bytes,in,n);memcpy(bytes,"GLUENR01",8);bytes[19]=1;bytes[123]=1;
 struct br_request inner;enum br_fault f=br_request_decode(bytes,n,&inner,e);if(f!=BR_OK)return f;
 /* Decoded spans must borrow the actual immutable consumed request, not stack. */
 inner.executable.bytes=in+(inner.executable.bytes-bytes);inner.cwd.bytes=in+(inner.cwd.bytes-bytes);
 inner.fixture=2;inner.argv_template=2;*out=inner;return BR_OK;
}
enum br_fault rr_ready_compare(const struct br_request *r,const struct br_ready_context *c,const struct bw_status *s,struct br_error *e){
 if(!selected(r))return bad(e,BR_SELECTOR);
 struct br_request inner=*r;inner.fixture=1;inner.argv_template=1;return br_ready_compare(&inner,c,s,e);
}
