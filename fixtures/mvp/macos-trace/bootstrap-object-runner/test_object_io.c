/* Reuse independent legacy callback models, not its transfer implementation. */
#define main legacy_observed_models_main
#include "../bootstrap-io/test_observed_io.c"
#undef main

static int chunked;
static ssize_t object_read(void *p,int fd,void *out,size_t n,int *e) {
 if(chunked&&n>17)n=17;
 return read_cb(p,fd,out,n,e);
}
static int object_progress(void *p,struct bio_time d) {
 struct model *m=p;
 m->pumps++;
 CHECK(d.seconds==m->expected_deadline/1000000000&&d.nanoseconds==m->expected_deadline%1000000000);
 if(m->late_full&&m->moved==512)m->now=m->expected_deadline;
 if(m->fail_first||(m->fail_partial&&m->moved)||(m->fail_full&&m->moved==512))return -1;
 if(m->bad_return)return 7;
 return 0;
}
static int object_run(struct model *m,int observed,struct bio_object_result *r,struct bio_error *e) {
 struct bio_operations o={m,clock_cb,stat_cb,flags_cb,poll_cb,object_read,write_cb};
 struct bio_observer v={m,object_progress};
 struct bio_time d=when(m->expected_deadline);
 unsigned char input[512];
 for(unsigned i=0;i<512;i++)input[i]=(unsigned char)i;
 if(m->writing)return observed?bio_write_object_status_observed(9,input,d,&o,&v,r,e):bio_write_object_status(9,input,d,&o,r,e);
 return observed?bio_read_object_status_observed(9,d,&o,&v,r,e):bio_read_object_status(9,d,&o,r,e);
}
static void sizes_and_preflight(void) {
 CHECK(sizeof(((struct bio_result*)0)->prefix)==256&&BIO_MAX_RECORD_BYTES==256);
 CHECK(sizeof(((struct bio_object_result*)0)->prefix)==512);
 struct model m=fresh();
 struct bio_result small;
 struct bio_error e;
 struct bio_operations o={&m,clock_cb,stat_cb,flags_cb,poll_cb,object_read,write_cb};
 CHECK(bio_read_record(9,512,when(m.expected_deadline),&o,&small,&e)==-1&&e.reason==BIO_REASON_LENGTH&&m.clocks==0);
 unsigned char input[512]={0};
 m.writing=1;
 CHECK(bio_write_record(9,input,512,when(m.expected_deadline),&o,&small,&e)==-1&&e.reason==BIO_REASON_LENGTH&&m.clocks==0);
 struct bio_object_result r;
 memset(&r,0xa5,sizeof(r));
 CHECK(bio_read_object_status(9,when(m.expected_deadline),&o,&r,NULL)==-1&&!r.bytes_moved);
 for(unsigned i=0;i<512;i++)CHECK(!r.prefix[i]);
 CHECK(bio_read_object_status(9,when(m.expected_deadline),&o,NULL,&e)==-1);
 CHECK(bio_read_object_status_observed(9,when(m.expected_deadline),&o,NULL,&r,&e)==-1&&e.stage==BIO_STAGE_OPERATIONS);
 CHECK(m.clocks==0);
}
static void complete_and_fragmented(void) {
 for(int writing=0;writing<2;writing++)for(int observed=0;observed<2;observed++){
  struct model m=fresh();
  m.writing=writing;
  m.frozen=1;
  struct bio_object_result r;
  struct bio_error e;
  CHECK(!object_run(&m,observed,&r,&e)&&r.bytes_moved==512&&m.moved==512);
  for(unsigned i=0;i<512;i++)CHECK(r.prefix[i]==(writing?(unsigned char)i:0x5a));
  CHECK(observed?m.pumps>=3:m.pumps==0);
 }
 struct model m=fresh();
 m.frozen=1;
 struct bio_object_result r;
 struct bio_error e;
 chunked=1;
 CHECK(!object_run(&m,1,&r,&e)&&r.bytes_moved==512&&m.reads==31&&m.max_timeout==20);
 chunked=0;
}
static void confirmed_failures(void) {
 for(int writing=0;writing<2;writing++){
  struct model m=fresh();
  m.writing=writing;
  m.fail_full=1;
  struct bio_object_result r;
  struct bio_error e;
  CHECK(object_run(&m,1,&r,&e)==-1&&e.reason==BIO_REASON_OBSERVER&&r.bytes_moved==512&&e.bytes_moved==512);
  CHECK((writing?m.writes:m.reads)==1);
  m=fresh();
  m.writing=writing;
  m.late_full=1;
  CHECK(object_run(&m,1,&r,&e)==-1&&e.reason==BIO_REASON_DEADLINE&&r.bytes_moved==512);
  CHECK((writing?m.writes:m.reads)==1);
 }
 struct model m=fresh();
 m.fail_partial=1;
 struct bio_object_result r;
 struct bio_error e;
 CHECK(object_run(&m,1,&r,&e)==-1&&e.reason==BIO_REASON_OBSERVER&&r.bytes_moved==16);
 for(unsigned i=0;i<512;i++)CHECK(r.prefix[i]==(i<16?0x5a:0));
}
static void deadline_and_error_policy(void) {
 struct bio_object_result r;
 struct bio_error e;
 struct model m=fresh();
 m.storm=1;
 CHECK(object_run(&m,1,&r,&e)==-1&&e.reason==BIO_REASON_DEADLINE&&m.polls==10&&!m.reads);
 m=fresh();
 m.io_error=1;
 CHECK(object_run(&m,1,&r,&e)==-1&&e.stage==BIO_STAGE_READ&&e.system_errno==EACCES);
 m=fresh();
 m.poll_fault=1;
 CHECK(object_run(&m,1,&r,&e)==-1&&e.stage==BIO_STAGE_POLL&&e.system_errno==EACCES&&!m.reads);
 m=fresh();
 m.fail_first=1;
 CHECK(object_run(&m,1,&r,&e)==-1&&e.stage==BIO_STAGE_OBSERVER&&!m.polls);
 m=fresh();
 m.bad_return=1;
 CHECK(object_run(&m,1,&r,&e)==-1&&e.reason==BIO_REASON_ADAPTER&&!m.polls);
}
int main(void) {
 sizes_and_preflight();
 complete_and_fragmented();
 confirmed_failures();
 deadline_and_error_policy();
 puts("object-io fixed512 legacy256 original-deadline complete-prefix-failure no-replay");
 return 0;
}
