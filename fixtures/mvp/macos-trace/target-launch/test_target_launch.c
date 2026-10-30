#include "target_launch.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct tl_span span(const char *value) {
    return (struct tl_span){(const uint8_t *)value, strlen(value)};
}
static struct tl_recipe recipe(const struct tl_span *args, size_t count) {
    return (struct tl_recipe){TL_AARCH64_DARWIN, args, count, 0};
}
static void zero(const void *value, size_t length) {
    const unsigned char *bytes = value;
    for (size_t i = 0; i < length; i++) assert(!bytes[i]);
}
static void refused(struct tl_recipe *r, struct tl_span executable,
                    enum tl_reason reason, size_t argument) {
    struct tl_plan p;
    struct tl_error e;
    memset(&p, 0xa5, sizeof(p));
    assert(tl_prepare(r, executable, &p, &e) == -1);
    zero(&p, sizeof(p));
    assert(e.reason == reason && e.argument == argument);
}
static void compact(void) {
    char executable[] = "/Library/Glue MVP/glue";
    char archive[] = "/Library/Glue MVP/app.glue";
    struct tl_span args[] = {span("run"), span(archive), span("--"), span("argument caf\xc3\xa9")};
    struct tl_recipe r = recipe(args, 4);
    struct tl_plan p;
    struct tl_error e;
    assert(!tl_prepare(&r, span(executable), &p, &e));
    assert(e.reason == TL_REASON_NONE && e.argument == SIZE_MAX);
    assert(p.ready == 1 && p.target == TL_AARCH64_DARWIN && p.argument_count == 5);
    assert(!p.environment_count && !p.environment[0] && !p.argv[5]);
    assert(!strcmp(p.argv[0], executable) && !strcmp(p.argv[1], "run"));
    assert(!strcmp(p.argv[2], archive) && !strcmp(p.argv[3], "--"));
    assert(!strcmp(p.argv[4], "argument caf\xc3\xa9"));
    uint8_t before[TL_CANONICAL_CAPACITY], after[TL_CANONICAL_CAPACITY];
    size_t bn, an;
    assert(!tl_canonical(&p, before, sizeof(before), &bn));
    executable[1] = 'X'; archive[1] = 'X'; args[0] = span("changed"); r.target = 99;
    assert(!strcmp(p.argv[0], "/Library/Glue MVP/glue"));
    assert(!strcmp(p.argv[2], "/Library/Glue MVP/app.glue"));
    assert(!tl_canonical(&p, after, sizeof(after), &an));
    assert(an == bn && !memcmp(before, after, an));
    args[0] = span("argument with spaces"); r = recipe(args, 1);
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(!strcmp(p.argv[1], "argument with spaces"));
}
static void empty_and_binary(void) {
    struct tl_recipe r = recipe(NULL, 0);
    struct tl_plan p;
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(p.argument_count == 1 && p.used == 3 && !p.argv[1]);
    const uint8_t binary[] = {'x', 0xff, 'y'};
    struct tl_span args[] = {{NULL, 0}, {binary, sizeof(binary)}, span("${HOME}; /a/../b")};
    r = recipe(args, 3);
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(p.argument_count == 4 && !p.argv[1][0]);
    assert(!memcmp(p.argv[2], binary, sizeof(binary)) && !p.argv[2][sizeof(binary)]);
    assert(!strcmp(p.argv[3], "${HOME}; /a/../b"));
}
static void profile(void) {
    struct tl_recipe r = recipe(NULL, 0);
    for (uint64_t target = 0; target < 4; target++) {
        if (target == TL_AARCH64_DARWIN) continue;
        r.target = target;
        refused(&r, span("/g"), TL_REASON_TARGET, SIZE_MAX);
    }
    r.target = UINT64_MAX;
    refused(&r, span("/g"), TL_REASON_TARGET, SIZE_MAX);
    r.target = TL_AARCH64_DARWIN; r.environment_count = 1;
    refused(&r, span("/g"), TL_REASON_ENVIRONMENT, SIZE_MAX);
    r.environment_count = SIZE_MAX;
    refused(&r, span("/g"), TL_REASON_ENVIRONMENT, SIZE_MAX);
}
static void counts(void) {
    struct tl_span args[TL_MAX_ARGS];
    for (size_t i = 0; i < TL_MAX_ARGS; i++) args[i] = (struct tl_span){NULL, 0};
    struct tl_recipe r = recipe(args, TL_MAX_ARGS - 1);
    struct tl_plan p;
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(p.argument_count == TL_MAX_ARGS && p.used == 3 + TL_MAX_ARGS - 1);
    for (size_t i = 1; i < TL_MAX_ARGS; i++) assert(!p.argv[i][0]);
    assert(!p.argv[TL_MAX_ARGS]);
    r.argument_count = TL_MAX_ARGS;
    refused(&r, span("/g"), TL_REASON_COUNT, SIZE_MAX);
    r.arguments = NULL; r.argument_count = SIZE_MAX;
    refused(&r, span("/g"), TL_REASON_COUNT, SIZE_MAX);
    r.argument_count = 1;
    refused(&r, span("/g"), TL_REASON_ARGUMENT, SIZE_MAX);
}
static void bytes(void) {
    uint8_t data[TL_MAX_BYTES]; memset(data, 'a', sizeof(data));
    struct tl_span arg = {data, TL_MAX_BYTES - 4};
    struct tl_recipe r = recipe(&arg, 1);
    struct tl_plan p;
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(p.used == TL_MAX_BYTES && p.argv[1][TL_MAX_BYTES - 4] == 0);
    uint8_t canonical[TL_CANONICAL_CAPACITY]; size_t n;
    assert(!tl_canonical(&p, canonical, sizeof(canonical), &n));
    assert(n == 24 + 8 + TL_MAX_BYTES - 2);
    arg.length++;
    refused(&r, span("/g"), TL_REASON_CAPACITY, 1);
    arg.length = SIZE_MAX;
    refused(&r, span("/g"), TL_REASON_SPAN, 1);
    arg.length = TL_MAX_BYTES;
    refused(&r, span("/g"), TL_REASON_SPAN, 1);
}
static void paths(void) {
    const char *bad[] = {"", "/", "g", "//g", "/g/", "/a//b", "/a/./b", "/a/../b"};
    struct tl_recipe r = recipe(NULL, 0);
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        refused(&r, span(bad[i]), TL_REASON_PATH, 0);
    char path[TL_MAX_EXECUTABLE_BYTES + 2];
    memset(path, 'a', sizeof(path)); path[0] = '/';
    struct tl_plan p;
    assert(!tl_prepare(&r, (struct tl_span){(const uint8_t *)path, TL_MAX_EXECUTABLE_BYTES}, &p, NULL));
    assert(strlen(p.argv[0]) == TL_MAX_EXECUTABLE_BYTES);
    refused(&r, (struct tl_span){(const uint8_t *)path, TL_MAX_EXECUTABLE_BYTES + 1}, TL_REASON_PATH, 0);
    assert(!tl_prepare(&r, span("/path with spaces/\xc3\xbc/glue"), &p, NULL));
}
static void spans(void) {
    const uint8_t nul[] = {'a', 0, 'b'};
    const uint8_t path[] = {'/', 'g', 0, 'x'};
    struct tl_span arg = {nul, sizeof(nul)};
    struct tl_recipe r = recipe(&arg, 1);
    refused(&r, span("/g"), TL_REASON_SPAN, 1);
    arg = (struct tl_span){NULL, 1};
    refused(&r, span("/g"), TL_REASON_SPAN, 1);
    r = recipe(NULL, 0);
    refused(&r, (struct tl_span){path, sizeof(path)}, TL_REASON_SPAN, 0);
    refused(&r, (struct tl_span){NULL, 1}, TL_REASON_SPAN, 0);
    refused(&r, (struct tl_span){path, SIZE_MAX}, TL_REASON_SPAN, 0);
}
static void reset(void) {
    struct { uint8_t first[16]; struct tl_plan plan; uint8_t last[16]; } guarded;
    memset(&guarded, 0xa5, sizeof(guarded));
    struct tl_recipe r = recipe(NULL, 0); struct tl_error e;
    assert(!tl_prepare(&r, span("/g"), &guarded.plan, &e));
    assert(tl_prepare(NULL, span("/g"), &guarded.plan, &e) == -1);
    zero(&guarded.plan, sizeof(guarded.plan));
    assert(e.reason == TL_REASON_ARGUMENT);
    for (size_t i = 0; i < 16; i++) assert(guarded.first[i] == 0xa5 && guarded.last[i] == 0xa5);
    assert(tl_prepare(&r, span("/g"), NULL, &e) == -1);
    assert(e.reason == TL_REASON_ARGUMENT && e.argument == SIZE_MAX);
    assert(tl_prepare(NULL, (struct tl_span){NULL, 0}, NULL, NULL) == -1);
}
static void canonical_vector(void) {
    const uint8_t binary[] = {0xff};
    struct tl_span args[] = {span("run"), {NULL, 0}, {binary, 1}};
    struct tl_recipe r = recipe(args, 3); struct tl_plan p;
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    static const uint8_t expected[] = {
        'G','L','U','E','T','L',0,1,
        0,0,0,0,0,0,0,1, 0,0,0,4, 0,0,0,0,
        0,0,0,2,'/','g', 0,0,0,3,'r','u','n', 0,0,0,0, 0,0,0,1,0xff
    };
    uint8_t out[sizeof(expected) + 2]; size_t n = 99;
    memset(out, 0xa5, sizeof(out));
    assert(!tl_canonical(&p, out + 1, sizeof(expected), &n));
    assert(n == sizeof(expected) && !memcmp(out + 1, expected, n));
    assert(out[0] == 0xa5 && out[sizeof(out) - 1] == 0xa5);
    assert(tl_canonical(&p, out + 1, sizeof(expected) - 1, &n) == -1 && !n);
    zero(out + 1, sizeof(expected) - 1);
    assert(out[0] == 0xa5 && out[sizeof(out) - 1] == 0xa5);
}
static void identity(void) {
    struct tl_span a[] = {span("ab"), span("c")}, b[] = {span("a"), span("bc")};
    struct tl_recipe r = recipe(a, 2); struct tl_plan p;
    uint8_t left[TL_CANONICAL_CAPACITY], right[TL_CANONICAL_CAPACITY]; size_t ln, rn;
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(!tl_canonical(&p, left, sizeof(left), &ln));
    r.arguments = b;
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(!tl_canonical(&p, right, sizeof(right), &rn));
    assert(ln == rn && memcmp(left, right, ln));
    r = recipe(NULL, 0);
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(!tl_canonical(&p, left, sizeof(left), &ln));
    struct tl_span empty = {NULL, 0}; r = recipe(&empty, 1);
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(!tl_canonical(&p, right, sizeof(right), &rn));
    assert(rn == ln + 4 && memcmp(left, right, ln));
    r = recipe(a, 2);
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(!tl_canonical(&p, left, sizeof(left), &ln));
    struct tl_span swap = a[0]; a[0] = a[1]; a[1] = swap;
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    assert(!tl_canonical(&p, right, sizeof(right), &rn));
    assert(ln == rn && memcmp(left, right, ln));
    memcpy(left, right, rn); ln = rn;
    assert(!tl_prepare(&r, span("/h"), &p, NULL));
    assert(!tl_canonical(&p, right, sizeof(right), &rn));
    assert(ln == rn && memcmp(left, right, ln));
}
static void bad_canonical(const struct tl_plan *p) {
    uint8_t out[TL_CANONICAL_CAPACITY]; size_t used = 99;
    memset(out, 0xa5, sizeof(out));
    assert(tl_canonical(p, out, sizeof(out), &used) == -1 && !used);
    zero(out, sizeof(out));
}
static void layout(void) {
    struct tl_span args[] = {span("run"), span("archive")};
    struct tl_recipe r = recipe(args, 2); struct tl_plan p;
    for (unsigned fault = 0; fault < 15; fault++) {
        assert(!tl_prepare(&r, span("/g"), &p, NULL));
        switch (fault) {
        case 0: p.ready = 0; break;
        case 1: p.target = 2; break;
        case 2: p.argument_count = 0; break;
        case 3: p.argument_count = TL_MAX_ARGS + 1; break;
        case 4: p.environment_count = 1; break;
        case 5: p.environment[0] = p.storage; break;
        case 6: p.used = TL_MAX_BYTES + 1; break;
        case 7: p.argv[1] = (char *)(uintptr_t)1; break;
        case 8: p.argv[p.argument_count] = p.storage; break;
        case 9: p.used--; break;
        case 10: p.used++; break;
        case 11: memset(p.storage, 'x', p.used); break;
        case 12: p.storage[0] = 'x'; break;
        case 13: p.storage[4] = 0; break;
        case 14: p.argv[0]++; break;
        }
        bad_canonical(&p);
    }
    assert(!tl_prepare(&r, span("/g"), &p, NULL));
    struct tl_plan moved = p;
    bad_canonical(&moved);
    bad_canonical(NULL);
    uint8_t out[8]; size_t used = 99; memset(out, 0xa5, sizeof(out));
    assert(tl_canonical(&p, NULL, 0, &used) == -1 && !used);
    assert(tl_canonical(&p, out, sizeof(out), NULL) == -1); zero(out, sizeof(out));
    out[0] = 0xa5;
    assert(tl_canonical(&p, out, 0, &used) == -1 && !used && out[0] == 0xa5);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "compact")) compact();
    else if (!strcmp(argv[1], "empty-binary")) empty_and_binary();
    else if (!strcmp(argv[1], "profile")) profile();
    else if (!strcmp(argv[1], "counts")) counts();
    else if (!strcmp(argv[1], "bytes")) bytes();
    else if (!strcmp(argv[1], "paths")) paths();
    else if (!strcmp(argv[1], "spans")) spans();
    else if (!strcmp(argv[1], "reset")) reset();
    else if (!strcmp(argv[1], "canonical-vector")) canonical_vector();
    else if (!strcmp(argv[1], "identity")) identity();
    else if (!strcmp(argv[1], "layout")) layout();
    else return 2;
    printf("pure target-launch control %s passed\n", argv[1]);
    return 0;
}
