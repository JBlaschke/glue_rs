/* Reuse the reviewed owned-child native test utilities, not a wire/IO model. */
#define main target_fd_models_main
#include "../target-fd-objects/test_target_fd_objects.c"
#undef main
#include "objects_profile.h"
#include "../bootstrap-runner/runner_protocol.h"

static struct bio_time native_deadline(void){int64_t n=milliseconds()+4000;
assert(n>4000);
return (struct bio_time){(uint64_t)n/1000,((uint64_t)n%1000)*1000000};
}
static int native_exchange(const char *name){
 if(getuid()==0||geteuid()==0)return 77;
 struct rlimit lim;
 if(getrlimit(RLIMIT_NOFILE,&lim)||lim.rlim_cur<32)return 77;
 gid_t groups[16];
 int count=getgroups(16,groups);
 if(count<1||count>16||groups[0]!=getgid()||!getuid()||!getgid())return 77;
 char directory[]="/tmp/glue-object-ready-XXXXXX";
 if(!mkdtemp(directory))return 1;
 char paths[4][256];
 const char*names[]={"input","stdout","stderr","wrong"};
 int files[4]={-1,-1,-1,-1};
 for(unsigned i=0;i<4;i++){assert(snprintf(paths[i],sizeof(paths[i]),"%s/%s",directory,names[i])>0);
 files[i]=open(paths[i],(i?O_WRONLY:O_RDONLY)|O_CREAT|O_EXCL|O_CLOEXEC,0600);
 assert(files[i]>=3);
 }
 int gate[2],status_pipe[2];
 assert(!pipe(gate)&&!pipe(status_pipe));
 for(unsigned i=0;i<2;i++){int g=fcntl(gate[i],F_GETFL),s=fcntl(status_pipe[i],F_GETFL);
 assert(g>=0&&s>=0&&!fcntl(gate[i],F_SETFL,g|O_NONBLOCK)&&!fcntl(status_pipe[i],F_SETFL,s|O_NONBLOCK));
 }
 struct te_request request={{files[0],files[1],files[2],gate[0],status_pipe[1]}};
 struct te_prepared prepared;
 struct te_error te;
 assert(!te_prepare_owned_sources(&request,te_native_operations(),&prepared,&te));
 struct td_record scratch[TD_MAX_CAPACITY];
 struct td_plan plan={{0,1,2,prepared.copies[3],prepared.copies[4]},scratch,TD_MAX_CAPACITY};
 struct tfo_plan observed={{0,1,2,prepared.copies[3],prepared.copies[4]}};
 struct stat cwd;
 assert(!stat(".",&cwd));
 struct bio_time deadline=native_deadline();
 pid_t owner=getpid();
 sigset_t all,old_mask;
 assert(!sigfillset(&all)&&!sigprocmask(SIG_SETMASK,&all,&old_mask));
 pid_t child=fork();
 assert(child>=0);
 if(!child){
  if(te_map_in_owned_child(&prepared,(uint64_t)owner,te_native_operations(),&te))_exit(10);
  const struct td_operations *td=td_native_operations();
#if defined(__linux__)
  assert(!td->supported);
  const struct tfo_operations*o=tfo_native_operations();
  struct td_operations linux_ops={1,NULL,o->getpid_fn,o->getppid_fn,o->signals_blocked_fn,linux_inventory,real_close};
  td=&linux_ops;
#endif
  struct td_error de;
  if(td_close_in_owned_child(&plan,(uint64_t)owner,td,&de))_exit(11);
  struct tfo_snapshot snapshot;
  struct tfo_error oe;
  if(tfo_snapshot_in_owned_child(&observed,(uint64_t)owner,tfo_native_operations(),&snapshot,&oe))_exit(12);
  struct bw_status ready={0};
  ready.binding=(struct bw_binding){(uint32_t)owner,(uint32_t)getpid(),{0}};
  ready.kind=BW_READY;
  ready.detail=-1;
  ready.mutation_flags=3;
  ready.real_uid=ready.effective_uid=(uint32_t)getuid();
  ready.real_gid=ready.effective_gid=(uint32_t)getgid();
  ready.group_count=(uint32_t)count;
  for(int i=0;i<count;i++)ready.groups[i]=(uint32_t)groups[i];
  ready.cwd_device=(uint64_t)(uint32_t)cwd.st_dev;
  ready.cwd_inode=(uint64_t)cwd.st_ino;
  for(unsigned i=0;i<5;i++)ready.kept_fds[i]=(uint32_t)plan.keep[i];
  unsigned char bytes[512];
  if(bow_status_encode(&ready,&snapshot,bytes)!=BW_OK)_exit(13);
  struct bio_object_result out;
  struct bio_error e;
  if(!strcmp(name,"legacy-status")){unsigned char legacy[256];
  if(bw_status_encode(&ready,legacy)!=BW_OK||write(plan.keep[4],legacy,256)!=256)_exit(14);
  _exit(0);
  }
  if(!strcmp(name,"truncated-status")){if(write(plan.keep[4],bytes,511)!=511)_exit(15);
  _exit(0);
  }
  if(bio_write_object_status(plan.keep[4],bytes,deadline,bio_native_operations(),&out,&e))_exit(16);
  struct bio_result go;
  if(bio_read_record(plan.keep[3],64,deadline,bio_native_operations(),&go,&e))_exit(17);
  struct bw_binding b;
  if(bow_go_decode(go.prefix,go.bytes_moved,&ready.binding,&b)!=BW_OK)_exit(40);
  if(bio_require_eof(plan.keep[3],deadline,bio_native_operations(),&go,&e))_exit(18);
  if(write(1,"object-ready-out\n",17)!=17||write(2,"object-ready-err\n",17)!=17)_exit(19);
  _exit(0);
 }
 int owned=1,reaped=0,wait_status=0,failed=0,cleanup_failed=0,pipe_set=0,go_attempted=0;
 struct sigaction saved_pipe,ignored;
 memset(&ignored,0,sizeof(ignored));
 ignored.sa_handler=SIG_IGN;
#define NREQUIRE(x) do{if(!(x)){fprintf(stderr,"native object line %d failed\n",__LINE__);failed=1;goto cleanup;}}while(0)
#define NCLOSE(fd) do{int close_fd=(fd);(fd)=-1;NREQUIRE(!close(close_fd));}while(0)
 NREQUIRE(!sigemptyset(&ignored.sa_mask)&&!sigaction(SIGPIPE,&ignored,&saved_pipe));
 pipe_set=1;
 NREQUIRE(!sigprocmask(SIG_SETMASK,&old_mask,NULL));
 NCLOSE(gate[0]);
 NCLOSE(status_pipe[1]);
 for(unsigned i=0;i<5;i++)NCLOSE(prepared.copies[i]);
 struct bw_binding binding={(uint32_t)owner,(uint32_t)child,{0}};
 struct nr_status_stream stream;
 NREQUIRE(!nr_status_init(&stream,&binding));
 int rc=nr_status_next(&stream,status_pipe[0],deadline,bio_native_operations());
 if(!strcmp(name,"legacy-status")||!strcmp(name,"truncated-status")){
  NREQUIRE(rc==-1&&stream.failed&&!stream.ready_objects.ready&&stream.wire.accepted_records==0&&stream.used==(!strcmp(name,"legacy-status")?256u:511u));
  NREQUIRE(!wait_owned(child,&wait_status,0,&owned,&reaped)&&WIFEXITED(wait_status)&&WEXITSTATUS(wait_status)==0);
  goto cleanup;
 }
 NREQUIRE(!rc&&stream.ready_objects.ready&&stream.used==512&&stream.wire.accepted_records==1);
 int held[2]={files[1],files[2]};
 if(!strcmp(name,"wrong-reference"))held[0]=files[3];
 struct tfo_matches matched;
 struct tfo_error match_error;
 int match=tfo_match_regular_outputs(&stream.ready_objects,held,tfo_native_operations(),&matched,&match_error);
 if(!strcmp(name,"wrong-reference")){NREQUIRE(match==-1&&!matched.ready);
 NREQUIRE(!wait_owned(child,&wait_status,1,&owned,&reaped));
 goto cleanup;
 }
 NREQUIRE(!match&&matched.ready);
 unsigned char go[64];
 NREQUIRE((!strcmp(name,"legacy-go")?bw_go_encode(&binding,go):bow_go_encode(&binding,go))==BW_OK);
 struct bio_result written;
 struct bio_error io_error;
 go_attempted=1;
 NREQUIRE(!bio_write_record(gate[1],go,sizeof(go),deadline,bio_native_operations(),&written,&io_error));
 NCLOSE(gate[1]);
 NREQUIRE(!wait_owned(child,&wait_status,0,&owned,&reaped)&&WIFEXITED(wait_status)&&WEXITSTATUS(wait_status)==(!strcmp(name,"legacy-go")?40:0));
 for(unsigned i=1;i<3;i++){int reader=open(paths[i],O_RDONLY|O_CLOEXEC);
 NREQUIRE(reader>=3);
 char data[32]={0};
 ssize_t n=read(reader,data,sizeof(data));
 int close_result=close(reader);
 NREQUIRE(!close_result);
 if(!strcmp(name,"legacy-go"))NREQUIRE(n==0);
 else NREQUIRE(n==17&&!memcmp(data,i==1?"object-ready-out\n":"object-ready-err\n",17));
 }
 cleanup:
 if(owned&&wait_owned(child,&wait_status,1,&owned,&reaped))cleanup_failed=1;
 for(unsigned i=0;i<5;i++)if(prepared.copies[i]>=0&&close(prepared.copies[i]))cleanup_failed=1;
 for(unsigned i=0;i<4;i++){if(files[i]>=0&&close(files[i]))cleanup_failed=1;
 if(unlink(paths[i]))cleanup_failed=1;
 }
 for(unsigned i=0;i<2;i++){if(gate[i]>=0&&close(gate[i]))cleanup_failed=1;
 if(status_pipe[i]>=0&&close(status_pipe[i]))cleanup_failed=1;
 }
 if(rmdir(directory))cleanup_failed=1;
 if(pipe_set&&sigaction(SIGPIPE,&saved_pipe,NULL))cleanup_failed=1;
#undef NREQUIRE
#undef NCLOSE
 printf("native-object-exchange %s actual_child_reap=%d cleanup_failure=%d GO_attempted=%d full_acceptance=0\n",name,reaped,cleanup_failed,go_attempted);
 return failed||cleanup_failed||owned||!reaped?1:0;
}
int main(int argc,char**argv){if(argc!=2)return 2;
return native_exchange(argv[1]);
}
