#ifndef GLUE_LUA_BRIDGE_H
#define GLUE_LUA_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

/* Private ABI. No lua_State or Lua API crosses this boundary. */
typedef struct glue_lua_reply {
    const unsigned char *data;
    size_t len;
    void *cookie;
    int status; /* 0: TLV values, 1: error bytes, 2: sticky Rust panic. */
} glue_lua_reply;

typedef glue_lua_reply (*glue_lua_request)(void *, uint32_t,
                                         const unsigned char *, size_t);
typedef void (*glue_lua_release)(void *, void *);

typedef struct glue_lua_options {
    /* SIZE_MAX disables each fault. Only growing allocations can fail. */
    size_t fail_after_allocations;
    size_t fail_after_reply_allocations;
    int collect_on_first_reply; /* Test-only deterministic nested GC request. */
} glue_lua_options;

typedef struct glue_lua_result {
    int status;
    size_t error_len;
    unsigned char error[4096];
    size_t allocation_attempts;
    size_t callbacks;
    size_t releases;
    size_t outstanding_replies;
    size_t peak_outstanding_replies;
    size_t shutdown_callbacks;
} glue_lua_result;

/* Synchronous: ctx, all input bytes, and callback code outlive state close. */
void glue_lua_run(void *ctx, glue_lua_request request,
                  glue_lua_release release,
                  const unsigned char *bootstrap, size_t bootstrap_len,
                  const unsigned char *package_path, size_t package_path_len,
                  const unsigned char *entry, size_t entry_len,
                  const char *origin,
                  const glue_lua_options *options,
                  glue_lua_result *result);

#endif
