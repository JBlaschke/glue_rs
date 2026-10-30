/* Reuse source-isolated libdtrace stubs and model setup without cloning cases.
 * No provider, signal, target launch or privileged operation is performed. */
static void after_real_close(int);
static unsigned status_clock_calls;
#define GLUE_STOPPED_STATUS_CLOCK_CALL() (status_clock_calls++)
#define GLUE_STOPPED_STATUS_AFTER_CLOSE(fd) after_real_close(fd)
#define main reused_stopped_producer_driver_main
#include "test_runtime_stopped_backend.c"
#undef main
#undef GLUE_STOPPED_STATUS_CLOCK_CALL
#undef GLUE_STOPPED_STATUS_AFTER_CLOSE
#include "runtime_stopped_status.h"
static int late_clock_fd=-1;
static int closed_fds[4];static unsigned real_close_count;
static void after_real_close(int fd){assert(real_close_count<4);closed_fds[real_close_count++]=fd;if(fd==late_clock_fd)clock_bad=1;}
static struct rt_stopped_status checked(struct fixture *f,const char *label){
 struct rt_snapshot expected=f->b->view;struct rt_stopped_identity identity_expected;assert(!rt_stopped_identity(f->b,&identity_expected));
 unsigned char *backend_before=malloc(sizeof(*f->b));assert(backend_before);memcpy(backend_before,f->b,sizeof(*f->b));unsigned clocks=status_clock_calls,options_before=options,closes=real_close_count;uint64_t time_before=now;
 struct rt_stopped_status out,again;memset(&out,0xa5,sizeof(out));assert(!rt_stopped_status(f->b,&out));assert(!rt_stopped_status(f->b,&again));assert(!memcmp(&out,&again,sizeof(out)));assert(!memcmp(&out.lifecycle,&expected,sizeof(expected)));assert(!memcmp(&out.identity,&identity_expected,sizeof(identity_expected)));assert(!memcmp(backend_before,f->b,sizeof(*f->b)));free(backend_before);
 struct rt_snapshot legacy;memset(&legacy,0xa5,sizeof(legacy));assert(rt_snapshot(f->b,&legacy)==-1);for(size_t i=0;i<sizeof(legacy);i++)assert(!((unsigned char *)&legacy)[i]);
 assert(status_clock_calls==clocks&&options==(int)options_before&&real_close_count==closes&&now==time_before);
 assert(out.version==1&&out.profile_version==1&&out.layout_version==1);assert(!out.native_admission&&!out.quiescence_proved&&!out.state_admission&&!out.exemption_admission&&!out.full_flags_authority);
 assert(out.lifecycle.events==out.identity.total_events&&!memcmp(&out.lifecycle.binding,&out.identity.binding,sizeof(out.identity.binding)));
 uint64_t counted=0;for(unsigned i=0;i<19;i++)counted+=out.identity.common_counts[i];for(unsigned i=0;i<5;i++)counted+=out.identity.extra_counts[i];assert(counted==out.lifecycle.events);
 if(retained){char path[1024];int n=snprintf(path,sizeof(path),"%s/status-%s.json",retained,label);assert(n>0&&(size_t)n<sizeof(path));FILE *p=fopen(path,"wx");assert(p);const struct rt_snapshot *v=&out.lifecycle;fprintf(p,"{\"version\":%u,\"profile\":%u,\"layout\":%u,\"identity_state\":%d,\"events\":%"PRIu64",\"start_attempted\":%d,\"started\":%d,\"stop_attempted\":%d,\"stopped\":%d,\"drain_attempted\":%d,\"drained\":%d,\"close_attempted\":%d,\"resources_closed\":%d,\"first_error\":%d,\"first_errno\":%d,\"close_error\":%d,\"close_errno\":%d,\"writer_error\":%d,\"writer_mask\":%u,\"writer_failed\":%u,\"writer_errno\":[%d,%d,%d,%d],\"actual_model_closes\":%u,\"getter_clock_calls\":0,\"full_flags_authority\":false,\"native_admission\":false}\n",out.version,out.profile_version,out.layout_version,out.identity.state,v->events,v->start_attempted,v->started,v->stop_attempted,v->stopped,v->drain_attempted,v->drained,v->close_attempted,v->resources_closed,v->first_error.reason,v->first_error.system_errno,v->close_error.reason,v->close_error.system_errno,v->writer_close_error.reason,v->writer_close_attempted_mask,v->writer_close_failed_mask,v->writer_close_errno[0],v->writer_close_errno[1],v->writer_close_errno[2],v->writer_close_errno[3],real_close_count);assert(!fclose(p));}
 return out;
}
static void closed_outcomes(struct fixture *f,unsigned failed){struct rt_stopped_status s=checked(f,"after-close");assert(s.lifecycle.close_attempted&&s.lifecycle.writer_close_attempted_mask==15&&s.lifecycle.writer_close_failed_mask==failed);assert(s.lifecycle.resources_closed==!failed&&real_close_count==4);for(unsigned i=0;i<4;i++){assert(s.lifecycle.writer_close_errno[i]==((failed&(1u<<i))?EINTR:0));assert(fcntl(closed_fds[i],F_GETFD)==-1&&errno==EBADF);}}
static void complete(struct fixture *f,int end){ok(f,(struct event){.kind=18,.pid=f->binding.owner_pid});int e=0;assert(!f->ops.stop_fn(f->b,f->deadline,&e));if(end){f->b->draining=1;ok(f,(struct event){.kind=17});f->b->draining=0;}int rc=f->ops.drain_fn(f->b,f->deadline,consumer,f,&e);assert(end?!rc:rc);}
static void close_now(struct fixture *f,int want){int e=0;int rc=f->ops.close_fn(f->b,f->deadline,&e);assert(want?rc:!rc);assert(want?e>0:e==0);}
static void unresolved_teardown(struct fixture *f){
 assert(rt_destroy(&f->b)==-1&&f->b);retain(f);/* Only discard fixture memory: recorded production ownership remains unresolved. */free(f->b);f->b=NULL;assert(!close(f->dir));for(unsigned i=0;i<4;i++){char path[256];snprintf(path,sizeof(path),"%s/%s",f->path,file_names[i]);assert(!unlink(path));}assert(!rmdir(f->path));
}
int main(int argc,char **argv){
 assert(argc==2||argc==3);retained=argc==3?argv[2]:NULL;setup();real_close_count=0;status_clock_calls=0;late_clock_fd=-1;struct fixture f;init(&f);const char *mode=argv[1];
 if(!strcmp(mode,"null-before-destroy")){
  struct rt_stopped_status s;memset(&s,0xa5,sizeof(s));assert(rt_stopped_status(NULL,&s)==-1);for(size_t i=0;i<sizeof(s);i++)assert(!((unsigned char *)&s)[i]);assert(rt_stopped_status(f.b,NULL)==-1);s=checked(&f,"before-start");assert(s.identity.state==RT_STOPPED_PENDING&&!s.lifecycle.start_attempted&&!s.lifecycle.close_attempted);assert(!rt_destroy(&f.b)&&!f.b);memset(&s,0xa5,sizeof(s));assert(rt_stopped_status(f.b,&s)==-1);for(size_t i=0;i<sizeof(s);i++)assert(!((unsigned char *)&s)[i]);assert(!close(f.dir)&&!rmdir(f.path));puts("PASS null-before-destroy");return 0;
 }
 if(!strcmp(mode,"foreign-default")){
  assert(!rt_destroy(&f.b));expect_old=1;struct rt_error e;assert(!rt_recipe_images_create(&f.b,f.dir,&f.binding,f.deadline,1,&f.ops,&e));assert(!start_fixture(&f));assert(options==6&&!destructive);struct rt_snapshot old;assert(!rt_snapshot(f.b,&old));struct rt_stopped_status s;memset(&s,0xa5,sizeof(s));assert(rt_stopped_status(f.b,&s)==-1);for(size_t i=0;i<sizeof(s);i++)assert(!((unsigned char *)&s)[i]);close_now(&f,0);const char *saved=retained;retained=NULL;finish(&f);retained=saved;puts("PASS foreign-default");return 0;
 }
 assert(!start_fixture(&f));prefix(&f,0);struct rt_stopped_status before=checked(&f,"before-finish");assert(before.identity.state==RT_STOPPED_PREFIX_RECORDED&&!before.lifecycle.close_attempted);
 if(!strcmp(mode,"clean-final")){complete(&f,1);close_now(&f,0);closed_outcomes(&f,0);struct rt_stopped_status s=checked(&f,"clean");assert(s.lifecycle.drained&&s.lifecycle.end_count==1&&s.lifecycle.first_error.reason==RT_OK&&s.identity.state==RT_STOPPED_PREFIX_RECORDED);
 }else if(!strcmp(mode,"earlier-fault-cleanup")){dtrace_errdata_t err={0};err.dteda_fault=3;err.dteda_msg="injected";assert(error_cb(&err,cb_arg)==DTRACE_HANDLE_ABORT);struct rt_error first=f.b->view.first_error;int e=0;assert(!f.ops.stop_fn(f.b,f.deadline,&e));assert(f.ops.drain_fn(f.b,f.deadline,consumer,&f,&e));close_now(&f,0);closed_outcomes(&f,0);struct rt_stopped_status s=checked(&f,"fault");assert(s.identity.state==RT_STOPPED_UNUSABLE&&s.lifecycle.resources_closed&&!memcmp(&first,&s.lifecycle.first_error,sizeof(first))&&s.lifecycle.close_error.reason==RT_OK);
 }else if(!strcmp(mode,"late-clock")){complete(&f,1);late_clock_fd=f.b->files[ERROR_FILE];close_now(&f,1);closed_outcomes(&f,0);struct rt_stopped_status s=checked(&f,"late-clock");assert(s.lifecycle.resources_closed&&s.lifecycle.first_error.reason==RT_CLOCK&&s.lifecycle.first_error.stage==RT_CLOSE&&s.lifecycle.close_error.reason==RT_CLOCK&&s.lifecycle.close_error.system_errno==EIO&&s.identity.state==RT_STOPPED_UNUSABLE);
 }else if(!strcmp(mode,"writer-close")){complete(&f,1);close_bad=f.b->files[INVENTORY_FILE];close_now(&f,1);closed_outcomes(&f,2);struct rt_stopped_status s=checked(&f,"writer-close");assert(!s.lifecycle.resources_closed&&s.lifecycle.first_error.reason==RT_POSIX&&s.lifecycle.writer_close_error.system_errno==EINTR&&s.identity.state==RT_STOPPED_UNUSABLE);unresolved_teardown(&f);puts("PASS writer-close");return 0;
 }else if(!strcmp(mode,"missing-drain")){ok(&f,(struct event){.kind=18,.pid=f.binding.owner_pid});int e=0;assert(!f.ops.stop_fn(f.b,f.deadline,&e));close_now(&f,0);closed_outcomes(&f,0);struct rt_stopped_status s=checked(&f,"missing-drain");assert(!s.lifecycle.drain_attempted&&!s.lifecycle.drained&&!s.lifecycle.end_count&&s.lifecycle.resources_closed);
 }else if(!strcmp(mode,"missing-end")){complete(&f,0);close_now(&f,0);closed_outcomes(&f,0);struct rt_stopped_status s=checked(&f,"missing-end");assert(s.lifecycle.drain_attempted&&!s.lifecycle.drained&&!s.lifecycle.end_count&&s.lifecycle.first_error.reason==RT_INCOMPLETE&&s.lifecycle.resources_closed);
 }else if(!strcmp(mode,"malformed-name")){uint64_t bytes=f.b->view.raw_bytes;assert(send_event(&f,(struct event){.kind=20,.fn="proc_info",.pid=f.binding.owner_pid,.tid=40,.detail=1,.args={176,176},.bad=7})==DTRACE_CONSUME_ABORT);struct rt_stopped_status s=checked(&f,"malformed-name");assert(s.identity.state==RT_STOPPED_UNUSABLE&&s.identity.marker_seen&&s.lifecycle.first_error.reason==RT_LAYOUT&&s.lifecycle.events==before.lifecycle.events&&s.lifecycle.raw_bytes==bytes);close_now(&f,0);closed_outcomes(&f,0);
 }else{fprintf(stderr,"Unknown mode %s\n",mode);assert(0);}
 finish(&f);puts("PASS status actual lifecycle copy");return 0;
}
