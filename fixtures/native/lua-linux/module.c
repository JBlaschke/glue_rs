/* Compile against the selected pinned headers, without -llua. The launcher
 * supplies the Lua API to this exact C ABI fixture. It is not a generic addon. */
#include <lua.h>
#include <lauxlib.h>
#include <unistd.h>

extern int glue_lua_dep(void);
int glue_native_data = 7;
static int constructors;
static int initializers;

__attribute__((constructor))
static void initialize_library(void) {
    ++constructors;
}

static int answer(lua_State *state) {
    if (getpid() <= 0) {
        return luaL_error(state, "native OS call failed");
    }
    lua_pushinteger(state, glue_lua_dep() + glue_native_data);
    return 1;
}

static int fail(lua_State *state) {
    return luaL_error(state, "native function failure");
}

static lua_Integer integer_global(lua_State *state, const char *name) {
    lua_getglobal(state, name);
    int valid = 0;
    lua_Integer value = lua_tointegerx(state, -1, &valid);
    lua_settop(state, -2);
    return valid ? value : 0;
}

int luaopen_native_probe(lua_State *state) {
    luaL_checkversion(state);
    ++initializers;
    if (integer_global(state, "fixture_init_error") != 0) {
        return luaL_error(state, "native initializer failure");
    }
    lua_Integer seed = integer_global(state, "fixture_seed");
    if (seed != 123) {
        return luaL_error(state, "native initializer did not share the selected Lua state");
    }
    lua_pushinteger(state, seed + 1);
    lua_setglobal(state, "native_observed_seed");

    lua_createtable(state, 0, 7);
    lua_pushcclosure(state, answer, 0);
    lua_setfield(state, -2, "answer");
    lua_pushcclosure(state, fail, 0);
    lua_setfield(state, -2, "fail");
    lua_pushinteger(state, constructors);
    lua_setfield(state, -2, "constructors");
    lua_pushinteger(state, initializers);
    lua_setfield(state, -2, "initializers");
    lua_pushinteger(state, glue_native_data);
    lua_setfield(state, -2, "data");
    lua_pushinteger(state, getpid());
    lua_setfield(state, -2, "pid");
    lua_pushinteger(state, LUA_VERSION_NUM);
    lua_setfield(state, -2, "version_num");
    return 1;
}
