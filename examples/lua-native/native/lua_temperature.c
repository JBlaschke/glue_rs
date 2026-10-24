#include <lua.h>
#include <lauxlib.h>
#include "temperature.h"

#if LUA_VERSION_NUM != 504
#error "This example requires Lua 5.4 headers; its manifest selects Lua 5.4."
#endif
_Static_assert(sizeof(lua_Integer) == 8, "glue requires 64-bit Lua integers");
_Static_assert(sizeof(lua_Number) == 8, "glue requires 64-bit Lua numbers");

static int fahrenheit(lua_State *state) {
    lua_Number celsius = luaL_checknumber(state, 1);
    lua_pushnumber(state, temperature_fahrenheit(celsius));
    return 1;
}

int luaopen_temperature(lua_State *state) {
    const luaL_Reg functions[] = {{"fahrenheit", fahrenheit}, {NULL, NULL}};
    luaL_checkversion(state);
    luaL_newlib(state, functions);
    return 1;
}
