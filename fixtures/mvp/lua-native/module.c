#include "lua.h"
#include "lauxlib.h"
extern int secondary_answer(void);
extern int secondary_threads(void);
static int constructors;
__attribute__((constructor)) static void initialize(void) { constructors++; }
static int answer(lua_State *L) { lua_pushinteger(L, secondary_answer()); return 1; }
static int threads(lua_State *L) { lua_pushboolean(L, secondary_threads()); return 1; }
static int fail(lua_State *L) { return luaL_error(L, "native protected function error"); }
static int callback(lua_State *L) { lua_pushvalue(L, 1); lua_call(L, 0, 1); return 1; }
int luaopen_module(lua_State *L) {
    static const luaL_Reg methods[] = {
        {"answer", answer}, {"threads", threads}, {"fail", fail}, {"callback", callback}, {0, 0}
    };
    luaL_checkversion(L);
    luaL_newlib(L, methods);
    lua_pushinteger(L, constructors);
    lua_setfield(L, -2, "constructors");
    return 1;
}
int luaopen_failed(lua_State *L) { return luaL_error(L, "native protected initializer error"); }
int luaopen_mismatched(lua_State *L) {
    luaL_checkversion_(L, LUA_VERSION_NUM == 504 ? 505 : 504, LUAL_NUMSIZES);
    return 0;
}
