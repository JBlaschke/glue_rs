/* Ordinary disk-loader comparison, linked to the exact selected Cargo-built
 * Lua core. This fixture-only program is not a product host-file loader. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

static const char *input_root;
static lua_CFunction initializer;

static void *load_image(const char *root, const char *name) {
    char path[4096];
    int size = snprintf(path, sizeof(path), "%s/native/%s", root, name);
    if (size < 0 || (size_t)size >= sizeof(path)) {
        fputs("baseline image path exceeds fixture limit\n", stderr);
        exit(EXIT_FAILURE);
    }
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "baseline dlopen: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return handle;
}

static size_t read_input(const char *key, char *buffer, size_t capacity) {
    char path[4096];
    int size = snprintf(path, sizeof(path), "%s/%s", input_root, key);
    if (size < 0 || (size_t)size >= sizeof(path)) {
        fputs("baseline input path exceeds fixture limit\n", stderr);
        exit(EXIT_FAILURE);
    }
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror("baseline fopen");
        exit(EXIT_FAILURE);
    }
    size_t length = fread(buffer, 1, capacity, file);
    int excess = fgetc(file);
    if (ferror(file) || excess != EOF || fclose(file) != 0) {
        fputs("baseline input exceeds fixture limit or could not be read\n", stderr);
        exit(EXIT_FAILURE);
    }
    return length;
}

static int read_asset(lua_State *state) {
    size_t length;
    const char *key = luaL_checklstring(state, 1, &length);
    static const char expected[] = "assets/message.txt";
    if (length != sizeof(expected) - 1 || memcmp(key, expected, length) != 0) {
        return luaL_error(state, "baseline only reads the exact fixture asset");
    }
    char buffer[128];
    length = read_input(expected, buffer, sizeof(buffer));
    lua_pushlstring(state, buffer, length);
    return 1;
}

static int setup(lua_State *state) {
    const struct { const char *name; lua_CFunction open; } libraries[] = {
        {LUA_GNAME, luaopen_base}, {LUA_COLIBNAME, luaopen_coroutine},
        {LUA_TABLIBNAME, luaopen_table}, {LUA_STRLIBNAME, luaopen_string},
        {LUA_MATHLIBNAME, luaopen_math}, {LUA_UTF8LIBNAME, luaopen_utf8},
        {LUA_LOADLIBNAME, luaopen_package},
    };
    for (size_t index = 0; index < sizeof(libraries) / sizeof(libraries[0]); ++index) {
        luaL_requiref(state, libraries[index].name, libraries[index].open, 1);
        lua_settop(state, -2);
    }
    lua_getglobal(state, "package");
    lua_getfield(state, -1, "preload");
    lua_pushcclosure(state, initializer, 0);
    lua_setfield(state, -2, "native_probe");
    lua_settop(state, 0);
    lua_pushboolean(state, 1);
    lua_setglobal(state, "fixture_baseline");
    lua_createtable(state, 0, 1);
    lua_pushcclosure(state, read_asset, 0);
    lua_setfield(state, -2, "read");
    lua_setglobal(state, "glue");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("usage: baseline INPUT_ROOT\n", stderr);
        return EXIT_FAILURE;
    }
    input_root = argv[1];
    void *dependency = load_image(input_root, "libglue_lua_dep.so");
    void *module = load_image(input_root, "libglue_lua_native.so");
    void *symbol = dlsym(module, "luaopen_native_probe");
    const char *error = dlerror();
    if (symbol == NULL || error != NULL || sizeof(initializer) != sizeof(symbol)) {
        fprintf(stderr, "baseline dlsym: %s\n", error != NULL ? error : "missing initializer");
        return EXIT_FAILURE;
    }
    memcpy(&initializer, &symbol, sizeof(initializer));
    char source[65536];
    size_t length = read_input("app/main.lua", source, sizeof(source));
    lua_State *state = luaL_newstate();
    if (state == NULL) {
        fputs("baseline could not create Lua state\n", stderr);
        return EXIT_FAILURE;
    }
    lua_pushcclosure(state, setup, 0);
    int status = lua_pcall(state, 0, 0, 0);
    if (status == LUA_OK) {
        status = luaL_loadbufferx(state, source, length, "@glue://native-lua-demo/app/main.lua", "t");
    }
    if (status == LUA_OK) {
        status = lua_pcall(state, 0, 0, 0);
    }
    if (status != LUA_OK) {
        const char *message = lua_tostring(state, -1);
        fprintf(stderr, "baseline Lua error: %s\n", message != NULL ? message : "non-string error");
    }
    lua_close(state);
    if (dlclose(module) != 0 || dlclose(dependency) != 0) {
        fputs("baseline dlclose failed\n", stderr);
        return EXIT_FAILURE;
    }
    return status == LUA_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
