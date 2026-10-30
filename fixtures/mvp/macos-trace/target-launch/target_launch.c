#include "target_launch.h"
#include <string.h>

static int fail(struct tl_error *error, enum tl_reason reason, size_t argument) {
    if (error) *error = (struct tl_error){reason, argument};
    return -1;
}
static int valid_span(struct tl_span span) {
    return span.length < TL_MAX_BYTES && (!span.length || span.bytes) &&
           (!span.length || !memchr(span.bytes, 0, span.length));
}
static int valid_path(struct tl_span span) {
    if (span.length < 2 || span.length > TL_MAX_EXECUTABLE_BYTES ||
        !span.bytes || span.bytes[0] != '/') return 0;
    size_t start = 1;
    for (size_t i = 1; i <= span.length; i++) {
        if (i != span.length && span.bytes[i] != '/') continue;
        size_t length = i - start;
        if (!length || (length == 1 && span.bytes[start] == '.') ||
            (length == 2 && span.bytes[start] == '.' && span.bytes[start + 1] == '.'))
            return 0;
        start = i + 1;
    }
    return 1;
}
int tl_prepare(const struct tl_recipe *recipe, struct tl_span executable,
               struct tl_plan *plan, struct tl_error *error) {
    if (plan) memset(plan, 0, sizeof(*plan));
    if (error) *error = (struct tl_error){TL_REASON_NONE, SIZE_MAX};
    if (!recipe || !plan) return fail(error, TL_REASON_ARGUMENT, SIZE_MAX);
    if (recipe->target != TL_AARCH64_DARWIN)
        return fail(error, TL_REASON_TARGET, SIZE_MAX);
    if (recipe->environment_count)
        return fail(error, TL_REASON_ENVIRONMENT, SIZE_MAX);
    if (recipe->argument_count >= TL_MAX_ARGS)
        return fail(error, TL_REASON_COUNT, SIZE_MAX);
    if (recipe->argument_count && !recipe->arguments)
        return fail(error, TL_REASON_ARGUMENT, SIZE_MAX);
    if (!valid_span(executable)) return fail(error, TL_REASON_SPAN, 0);
    if (!valid_path(executable)) return fail(error, TL_REASON_PATH, 0);
    size_t total = executable.length + 1;
    for (size_t i = 0; i < recipe->argument_count; i++) {
        struct tl_span span = recipe->arguments[i];
        if (!valid_span(span)) return fail(error, TL_REASON_SPAN, i + 1);
        if (span.length >= TL_MAX_BYTES - total)
            return fail(error, TL_REASON_CAPACITY, i + 1);
        total += span.length + 1;
    }
    plan->target = recipe->target;
    plan->argument_count = recipe->argument_count + 1;
    plan->used = total;
    size_t offset = 0;
    for (size_t i = 0; i < plan->argument_count; i++) {
        struct tl_span span = i ? recipe->arguments[i - 1] : executable;
        plan->argv[i] = plan->storage + offset;
        if (span.length) memcpy(plan->argv[i], span.bytes, span.length);
        offset += span.length + 1;
    }
    plan->ready = 1;
    return 0;
}
static int layout(const struct tl_plan *plan, size_t lengths[TL_MAX_ARGS]) {
    if (!plan || plan->ready != 1 || plan->target != TL_AARCH64_DARWIN ||
        plan->environment_count || plan->environment[0] ||
        !plan->argument_count || plan->argument_count > TL_MAX_ARGS ||
        !plan->used || plan->used > TL_MAX_BYTES) return -1;
    size_t offset = 0;
    for (size_t i = 0; i < plan->argument_count; i++) {
        if (offset >= plan->used || plan->argv[i] != plan->storage + offset) return -1;
        const char *end = memchr(plan->storage + offset, 0, plan->used - offset);
        if (!end) return -1;
        lengths[i] = (size_t)(end - (plan->storage + offset));
        if (!i && !valid_path((struct tl_span){(const uint8_t *)plan->storage, lengths[i]}))
            return -1;
        offset += lengths[i] + 1;
    }
    if (offset != plan->used) return -1;
    for (size_t i = plan->argument_count; i <= TL_MAX_ARGS; i++)
        if (plan->argv[i]) return -1;
    return 0;
}
static void be32(uint8_t *out, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) out[i] = (uint8_t)(value >> (24 - 8 * i));
}
static void be64(uint8_t *out, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (56 - 8 * i));
}
int tl_canonical(const struct tl_plan *plan, uint8_t *out, size_t capacity,
                 size_t *used) {
    if (out && capacity) memset(out, 0, capacity);
    if (used) *used = 0;
    if (!out || !used) return -1;
    size_t lengths[TL_MAX_ARGS];
    if (layout(plan, lengths)) return -1;
    size_t needed = 24 + 4 * plan->argument_count + plan->used - plan->argument_count;
    if (needed > capacity) return -1;
    static const uint8_t domain[8] = {'G', 'L', 'U', 'E', 'T', 'L', 0, 1};
    memcpy(out, domain, sizeof(domain));
    be64(out + 8, plan->target);
    be32(out + 16, (uint32_t)plan->argument_count);
    be32(out + 20, (uint32_t)plan->environment_count);
    size_t offset = 24;
    for (size_t i = 0; i < plan->argument_count; i++) {
        be32(out + offset, (uint32_t)lengths[i]);
        offset += 4;
        memcpy(out + offset, plan->argv[i], lengths[i]);
        offset += lengths[i];
    }
    *used = offset;
    return 0;
}
