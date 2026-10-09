/* All Lua calls and all Lua non-local error/yield transfers stay in C. */
#include "bridge.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#ifdef __cplusplus
#error "The Lua error boundary must be compiled as C"
#endif
#if LUA_VERSION_RELEASE_NUM != 50409 && LUA_VERSION_RELEASE_NUM != 50501
#error "Unsupported linked Lua source release"
#endif
_Static_assert(sizeof(lua_Integer) == 8, "Lua integer ABI must be int64");
_Static_assert(sizeof(lua_Number) == 8, "Lua number ABI must be float64");
_Static_assert((lua_Integer)-1 < 0, "Lua integer ABI must be signed");
_Static_assert(LUA_INT_TYPE == LUA_INT_LONGLONG, "Lua integer type must be long long");
_Static_assert(LUA_FLOAT_TYPE == LUA_FLOAT_DOUBLE, "Lua number type must be double");
#ifdef GLUE_LUA_NATIVE
_Static_assert(sizeof(uintptr_t) == sizeof(uint64_t), "Native profile requires 64-bit pointers");
_Static_assert(sizeof(lua_CFunction) == sizeof(uintptr_t), "Native function pointer representation");
#endif

#define GLUE_MAX_KEY 4096u
#define GLUE_MAX_RESULTS 16u
#define GLUE_MAX_DEPTH 32u
#define GLUE_MAX_REPLY ((size_t)128 * 1024 * 1024)

typedef struct run_context {
    void *rust;
    glue_lua_request request;
    glue_lua_release release;
    const unsigned char *bootstrap;
    size_t bootstrap_len;
    const unsigned char *package_path;
    size_t package_path_len;
    const unsigned char *entry;
    size_t entry_len;
    const char *origin;
    size_t remaining_allocations;
    size_t reply_fault;
    int reply_fault_started;
    int collect_on_first_reply;
    int panicked;
    int closing;
    glue_lua_result *result;
} run_context;

/* Local to each C request frame, so GC requests can nest during decoding. */
typedef struct reply_context {
    run_context *run;
    const glue_lua_reply *reply;
    size_t position;
} reply_context;

static void *system_allocator(void *ud, void *ptr, size_t old_size,
                              size_t new_size) {
    run_context *run = (run_context *)ud;
    void *replacement;
    if (new_size == 0) {
        free(ptr);
        return NULL;
    }
    /* Lua's old_size for NULL is an object type, not an allocation size. */
    if (ptr == NULL || new_size > old_size) {
        run->result->allocation_attempts++;
        if (run->remaining_allocations != SIZE_MAX) {
            if (run->remaining_allocations == 0)
                return NULL;
            run->remaining_allocations--;
        }
    }
    replacement = realloc(ptr, new_size);
    /* Lua requires shrinking allocations never to fail. The larger original
       allocation remains valid if the system cannot satisfy a shrink. */
    if (replacement == NULL && ptr != NULL && new_size <= old_size)
        return ptr;
    return replacement;
}

static int traceback(lua_State *L) {
    const char *message = lua_type(L, 1) == LUA_TSTRING
        ? lua_tostring(L, 1) : "non-string Lua error";
    /* This C message handler is protected by lua_pcall, including OOM. */
    luaL_traceback(L, L, message, 1);
    return 1;
}

static _Noreturn void invalid_reply(lua_State *L) {
    luaL_error(L, "invalid archive callback reply");
    abort(); /* luaL_error cannot return; never continue parsing after failure. */
}

static void read_bytes(lua_State *L, reply_context *reply, size_t len,
                      const unsigned char **data) {
    if (len > reply->reply->len - reply->position)
        invalid_reply(L);
    *data = reply->reply->data + reply->position;
    reply->position += len;
}

static uint32_t read_u32(lua_State *L, reply_context *reply) {
    const unsigned char *data;
    read_bytes(L, reply, 4, &data);
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
        | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint64_t read_u64(lua_State *L, reply_context *reply) {
    const unsigned char *data;
    uint64_t bits = 0;
    unsigned i;
    read_bytes(L, reply, 8, &data);
    for (i = 0; i < 8; i++)
        bits |= (uint64_t)data[i] << (8 * i);
    return bits;
}

static int push_value(lua_State *L, reply_context *reply, unsigned depth,
                       int is_key) {
    const unsigned char *data;
    unsigned tag;
    if (depth > GLUE_MAX_DEPTH)
        invalid_reply(L);
    luaL_checkstack(L, 4, "archive reply nesting");
    read_bytes(L, reply, 1, &data);
    tag = data[0];
    if (is_key && tag != 2 && tag != 3)
        invalid_reply(L);
    switch (tag) {
    case 0:
        lua_pushnil(L);
        break;
    case 1:
        read_bytes(L, reply, 1, &data);
        if (data[0] > 1)
            invalid_reply(L);
        lua_pushboolean(L, data[0]);
        break;
    case 2: {
        uint64_t bits = read_u64(L, reply);
        int64_t integer;
        /* Bit copy avoids implementation-defined unsigned-to-signed casts. */
        memcpy(&integer, &bits, sizeof(integer));
        lua_pushinteger(L, (lua_Integer)integer);
        break;
    }
#ifdef GLUE_LUA_NATIVE
    case 5: {
        uint64_t bits = read_u64(L, reply);
        uintptr_t address;
        lua_CFunction initializer;
        if (bits == 0)
            invalid_reply(L);
        /* This private reply comes only from the preloaded manager's validated
           initializer lease. Bits alone cannot establish an arbitrary address
           is callable. The native profile pins all image handles past close. */
        address = (uintptr_t)bits;
        memcpy(&initializer, &address, sizeof(initializer));
        lua_pushcfunction(L, initializer);
        break;
    }
#endif
    case 3: {
        size_t len = read_u32(L, reply);
        read_bytes(L, reply, len, &data);
        lua_pushlstring(L, (const char *)data, len);
        break;
    }
    case 4: {
        uint32_t count = read_u32(L, reply);
        uint32_t i;
        /* Smallest legal key/value pair is empty string + nil (6 bytes). */
        if ((size_t)count > (reply->reply->len - reply->position) / 6)
            invalid_reply(L);
        lua_newtable(L);
        for (i = 0; i < count; i++) {
            push_value(L, reply, depth + 1, 1);
            push_value(L, reply, depth + 1, 0);
            lua_rawset(L, -3);
        }
        break;
    }
    default:
        invalid_reply(L);
    }
    return 0;
}

static int push_reply(lua_State *L) {
    reply_context *reply = (reply_context *)lua_touserdata(L, 1);
    uint32_t count;
    uint32_t i;
    if (reply->run->collect_on_first_reply) {
        reply->run->collect_on_first_reply = 0;
        /* Private fault-test hook: force finalizers while the outer reply is
           owned, beneath this C-only protection frame. Production disables it. */
        lua_gc(L, LUA_GCCOLLECT);
    }
    if (reply->reply->len > GLUE_MAX_REPLY
        || (reply->reply->len != 0 && reply->reply->data == NULL))
        invalid_reply(L);
    if (reply->reply->status == 1 || reply->reply->status == 2) {
        const char *message = reply->reply->len == 0
            ? "archive callback failed" : (const char *)reply->reply->data;
        size_t len = reply->reply->len == 0
            ? strlen(message) : reply->reply->len;
        lua_pushlstring(L, message, len);
        return 1; /* The request frame releases the reply before raising it. */
    }
    if (reply->reply->status != 0 || reply->reply->len < 4)
        invalid_reply(L);
    count = read_u32(L, reply);
    if (count > GLUE_MAX_RESULTS)
        invalid_reply(L);
    luaL_checkstack(L, (int)count + 4, "archive reply results");
    for (i = 0; i < count; i++)
        push_value(L, reply, 1, 0);
    if (reply->position != reply->reply->len)
        invalid_reply(L);
    return (int)count;
}

static int archive_request(lua_State *L) {
    run_context *run = (run_context *)lua_touserdata(L, lua_upvalueindex(1));
    lua_Integer operation = luaL_checkinteger(L, 1);
    size_t key_len;
    const char *key = luaL_checklstring(L, 2, &key_len);
    glue_lua_reply reply;
    reply_context decoding;
    int status;
    int results;
    int base;
    if (operation < 0 || (uint64_t)operation > UINT32_MAX)
        return luaL_error(L, "invalid archive operation");
    if (key_len > GLUE_MAX_KEY)
        return luaL_error(L, "archive key exceeds 4096 bytes");
    if (run->panicked)
        return luaL_error(L, "archive callback panicked");
    /* Reserve the nonallocating pcall setup BEFORE borrowing Rust context. */
    luaL_checkstack(L, 4, "archive callback protection");
    base = lua_gettop(L);
    run->result->callbacks++;
    if (run->closing)
        run->result->shutdown_callbacks++;
    reply = run->request(run->rust, (uint32_t)operation,
                         (const unsigned char *)key, key_len);
    /* The Rust callback frame and its FnMut borrow have ended at this point. */
    if (reply.status == 2)
        run->panicked = 1;
    run->result->outstanding_replies++;
    if (run->result->outstanding_replies > run->result->peak_outstanding_replies)
        run->result->peak_outstanding_replies = run->result->outstanding_replies;
    if (!run->reply_fault_started && run->reply_fault != SIZE_MAX) {
        run->remaining_allocations = run->reply_fault;
        run->reply_fault_started = 1;
    }
    decoding.run = run;
    decoding.reply = &reply;
    decoding.position = 0;
    lua_pushcfunction(L, push_reply); /* Zero-upvalue C function: no allocation. */
    lua_pushlightuserdata(L, &decoding);
    status = lua_pcall(L, 1, LUA_MULTRET, 0);
    /* Both successful copies and allocation/error failures release exactly once. */
    run->release(run->rust, reply.cookie);
    run->result->releases++;
    run->result->outstanding_replies--;
    if (status != LUA_OK || reply.status == 1 || reply.status == 2)
        return lua_error(L);
    /* All original arguments remain below the protected call's results. */
    results = lua_gettop(L) - base;
    return results;
}

static int initialize_and_run(lua_State *L) {
    run_context *run = (run_context *)lua_touserdata(L, 1);
    static const luaL_Reg libraries[] = {
        {LUA_GNAME, luaopen_base},
        {LUA_COLIBNAME, luaopen_coroutine},
        {LUA_TABLIBNAME, luaopen_table},
        {LUA_STRLIBNAME, luaopen_string},
        {LUA_MATHLIBNAME, luaopen_math},
        {LUA_UTF8LIBNAME, luaopen_utf8},
        {LUA_LOADLIBNAME, luaopen_package},
        {NULL, NULL}
    };
    const luaL_Reg *library;
    int status;
    for (library = libraries; library->name != NULL; library++) {
        luaL_requiref(L, library->name, library->func, 1);
        lua_pop(L, 1);
    }
    status = luaL_loadbufferx(L, (const char *)run->bootstrap,
                              run->bootstrap_len, "@glue-bootstrap", "t");
    if (status != LUA_OK)
        return lua_error(L);
    lua_pushlightuserdata(L, run);
    lua_pushcclosure(L, archive_request, 1);
    lua_pushlstring(L, (const char *)run->package_path, run->package_path_len);
#ifdef GLUE_LUA_NATIVE
    lua_pushboolean(L, 1);
#else
    lua_pushboolean(L, 0);
#endif
    lua_call(L, 3, 0);
    status = luaL_loadbufferx(L, (const char *)run->entry, run->entry_len,
                              run->origin, "t");
    if (status != LUA_OK)
        return lua_error(L);
    lua_call(L, 0, 0);
    return 0;
}

static void copy_message(glue_lua_result *result, const char *message,
                         size_t len) {
    if (len > sizeof(result->error))
        len = sizeof(result->error);
    memcpy(result->error, message, len);
    result->error_len = len;
}

void glue_lua_run(void *ctx, glue_lua_request request,
                  glue_lua_release release,
                  const unsigned char *bootstrap, size_t bootstrap_len,
                  const unsigned char *package_path, size_t package_path_len,
                  const unsigned char *entry, size_t entry_len,
                  const char *origin,
                  const glue_lua_options *options,
                  glue_lua_result *result) {
    run_context run;
    lua_State *L;
    int status;
    memset(result, 0, sizeof(*result));
    memset(&run, 0, sizeof(run));
    run.rust = ctx;
    run.request = request;
    run.release = release;
    run.bootstrap = bootstrap;
    run.bootstrap_len = bootstrap_len;
    run.package_path = package_path;
    run.package_path_len = package_path_len;
    run.entry = entry;
    run.entry_len = entry_len;
    run.origin = origin;
    run.remaining_allocations = options->fail_after_allocations;
    run.reply_fault = options->fail_after_reply_allocations;
    run.collect_on_first_reply = options->collect_on_first_reply;
    run.result = result;
#if LUA_VERSION_NUM == 505
    L = lua_newstate(system_allocator, &run, luaL_makeseed(NULL));
#else
    L = lua_newstate(system_allocator, &run);
#endif
    if (L == NULL) {
        result->status = LUA_ERRMEM;
        copy_message(result, "cannot allocate Lua state", 25);
        return;
    }
    /* Initial stack is LUA_MINSTACK. These zero-upvalue/pointer pushes do not
       allocate; every subsequent throwing call lies beneath this C pcall. */
    lua_pushcfunction(L, traceback);
    lua_pushcfunction(L, initialize_and_run);
    lua_pushlightuserdata(L, &run);
    status = lua_pcall(L, 1, 0, 1);
    result->status = status;
    if (status != LUA_OK) {
        if (lua_type(L, -1) == LUA_TSTRING) {
            size_t len;
            const char *message = lua_tolstring(L, -1, &len);
            copy_message(result, message, len);
        } else {
            copy_message(result, "non-string Lua error", 20);
        }
    }
    /* lua_close protects finalizers internally. Context and callbacks remain
       alive; finalizer requests get the same protected marshalling/release. */
    run.closing = 1;
    lua_close(L);
    if (run.panicked) {
        result->status = -1;
        copy_message(result, "archive callback panicked", 25);
    }
}

#ifdef GLUE_LUA_NATIVE
/* Static C fixtures exercise the same Lua ABI as a loaded initializer. They
   are reachable only by this private test getter, never by archive lookup. */
static int fixture_answer(lua_State *L) {
    lua_pushinteger(L, 42);
    return 1;
}

static int fixture_function_error(lua_State *L) {
    return luaL_error(L, "native fixture function error");
}

static int fixture_read(lua_State *L) {
    int base = lua_gettop(L);
    lua_getglobal(L, "request");
    lua_pushinteger(L, 2);
    lua_pushliteral(L, "asset");
    lua_call(L, 2, LUA_MULTRET);
    return lua_gettop(L) - base;
}

static int fixture_initializer(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *origin = luaL_checkstring(L, 2);
    if (strcmp(name, "bridge.fixture") != 0
        || strcmp(origin, "glue://test/native/module.so") != 0)
        return luaL_error(L, "native fixture loader arguments differ");
    lua_newtable(L);
    lua_pushinteger(L, 42);
    lua_setfield(L, -2, "value");
    lua_pushcfunction(L, fixture_answer);
    lua_setfield(L, -2, "answer");
    lua_pushcfunction(L, fixture_function_error);
    lua_setfield(L, -2, "fail");
    lua_pushcfunction(L, fixture_read);
    lua_setfield(L, -2, "read");
    return 1;
}

static int fixture_initializer_error(lua_State *L) {
    return luaL_error(L, "native fixture initializer error");
}

uint64_t glue_lua_test_initializer(unsigned variant) {
    lua_CFunction initializer = variant == 0
        ? fixture_initializer : fixture_initializer_error;
    uintptr_t address;
    memcpy(&address, &initializer, sizeof(address));
    return (uint64_t)address;
}
#endif
