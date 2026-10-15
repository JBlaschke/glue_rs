#include <node_api.h>
extern int probe_answer(void);
static napi_value answer(napi_env env, napi_callback_info info) {
  napi_value value; (void)info;
  if (napi_create_int32(env, probe_answer(), &value) != napi_ok) return NULL;
  return value;
}
static napi_value init(napi_env env, napi_value exports) {
  napi_value fn;
  if (napi_create_function(env,"answer",NAPI_AUTO_LENGTH,answer,NULL,&fn) != napi_ok) return NULL;
  if (napi_set_named_property(env,exports,"answer",fn) != napi_ok) return NULL;
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
