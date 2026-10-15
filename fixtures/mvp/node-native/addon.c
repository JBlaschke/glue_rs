#include <node_api.h>
#include <stdlib.h>
extern int probe_answer(void);
extern int probe_constructors(void);
static napi_value answer(napi_env env,napi_callback_info info){napi_value value;(void)info;if(napi_create_int32(env,probe_answer(),&value)!=napi_ok)return NULL;return value;}
static napi_value constructors(napi_env env,napi_callback_info info){napi_value value;(void)info;if(napi_create_int32(env,probe_constructors(),&value)!=napi_ok)return NULL;return value;}
static napi_value callback(napi_env env,napi_callback_info info){size_t argc=1;napi_value argv[1],self,value,out;if(napi_get_cb_info(env,info,&argc,argv,&self,NULL)!=napi_ok||argc!=1)return NULL;if(napi_create_int32(env,probe_answer(),&value)!=napi_ok||napi_call_function(env,self,argv[0],1,&value,&out)!=napi_ok)return NULL;return out;}
static napi_value fail(napi_env env,napi_callback_info info){(void)info;napi_throw_error(env,"ERR_PROBE","prepared addon error");return NULL;}
typedef struct {napi_async_work work;napi_deferred deferred;int answer;} task;
static void execute(napi_env env,void*data){(void)env;((task*)data)->answer=probe_answer();}
static void complete(napi_env env,napi_status status,void*data){task*t=data;napi_value value;if(status==napi_ok&&napi_create_int32(env,t->answer,&value)==napi_ok)napi_resolve_deferred(env,t->deferred,value);napi_delete_async_work(env,t->work);free(t);}
static napi_value thread(napi_env env,napi_callback_info info){(void)info;task*t=calloc(1,sizeof(task));napi_value promise,name;if(!t)return NULL;if(napi_create_promise(env,&t->deferred,&promise)!=napi_ok||napi_create_string_utf8(env,"prepared-thread",NAPI_AUTO_LENGTH,&name)!=napi_ok||napi_create_async_work(env,NULL,name,execute,complete,t,&t->work)!=napi_ok){free(t);return NULL;}if(napi_queue_async_work(env,t->work)!=napi_ok){napi_delete_async_work(env,t->work);free(t);return NULL;}return promise;}
static napi_value init(napi_env env,napi_value exports){napi_property_descriptor methods[]={{"answer",NULL,answer,NULL,NULL,NULL,napi_default,NULL},{"constructors",NULL,constructors,NULL,NULL,NULL,napi_default,NULL},{"callback",NULL,callback,NULL,NULL,NULL,napi_default,NULL},{"fail",NULL,fail,NULL,NULL,NULL,napi_default,NULL},{"thread",NULL,thread,NULL,NULL,NULL,napi_default,NULL}};if(napi_define_properties(env,exports,5,methods)!=napi_ok)return NULL;return exports;}
NAPI_MODULE(NODE_GYP_MODULE_NAME,init)
