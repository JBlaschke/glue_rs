/* Independent stock Lua reference driver. No glue archive/bootstrap code. */
#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
int main(int argc, char **argv) {
    int i, status;
    lua_State *L;
    if (argc < 2) { fputs("usage: lua-reference SCRIPT ARGUMENTS...\n", stderr); return 2; }
    L = luaL_newstate();
    if (L == NULL) return 1;
    luaL_openlibs(L);
    lua_createtable(L, argc - 2, 1);
    for (i = 1; i < argc; i++) {
        lua_pushstring(L, argv[i]);
        lua_rawseti(L, -2, i - 1);
    }
    lua_setglobal(L, "arg");
    status = luaL_loadfile(L, argv[1]);
    if (status == LUA_OK) status = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (status != LUA_OK) fprintf(stderr, "%s\n", lua_tostring(L, -1));
    lua_close(L);
    return status == LUA_OK ? 0 : 1;
}
