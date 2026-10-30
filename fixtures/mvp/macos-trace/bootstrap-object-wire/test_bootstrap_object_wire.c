#include "bootstrap_object_wire.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static int all_zero(const void *value, size_t size) {
    const uint8_t *p = value;
    for (size_t i = 0; i < size; ++i) if (p[i]) return 0;
    return 1;
}
static struct bw_binding binding(void) {
    struct bw_binding b = {0};
    b.controller_pid = UINT32_C(0x01020304); b.child_pid = UINT32_C(0x11223344);
    for (unsigned i = 0; i < 32; ++i) b.request_sha256[i] = (uint8_t)i;
    return b;
}
static struct bw_status status(unsigned kind) {
    struct bw_status s = {0};
    s.binding = binding(); s.kind = kind; s.detail = -1;
    if (kind == BW_READY) {
        s.mutation_flags = BW_CREDENTIAL_ATTEMPT | BW_DESCRIPTOR_ATTEMPT;
        s.real_uid = s.effective_uid = 1001; s.real_gid = s.effective_gid = 1002;
        s.group_count = 2; s.groups[0] = 1002; s.groups[1] = 7;
        s.cwd_device = UINT64_C(0x0123456789abcdef);
        s.cwd_inode = UINT64_C(0xfedcba9876543210);
        s.kept_fds[0] = 0; s.kept_fds[1] = 1; s.kept_fds[2] = 2;
        s.kept_fds[3] = 17; s.kept_fds[4] = 23;
        for (unsigned i = 0; i < 32; ++i) s.signal_policy_sha256[i] = (uint8_t)(255 - i);
    } else if (kind == BW_EXEC_ATTEMPT) {
        s.sequence = 1; s.stage = BW_EXEC;
        s.mutation_flags = BW_CREDENTIAL_ATTEMPT | BW_DESCRIPTOR_ATTEMPT;
    } else {
        s.stage = BW_REQUEST; s.reason = BW_ARGUMENT;
    }
    return s;
}
static struct tfo_snapshot snapshot(const struct bw_status *s) {
    struct tfo_snapshot result = {0};
    result.ready = 1; result.controller_pid = s->binding.controller_pid;
    result.child_pid = s->binding.child_pid;
    for (unsigned i = 0; i < TFO_KEEP_COUNT; ++i) {
        struct tfo_entry *r = &result.entries[i];
        r->fd = (int)s->kept_fds[i];
        r->descriptor_flags = (int)(UINT32_C(0x10203040) + i);
        r->status_flags = (int)(UINT32_C(0x21314151) + i);
        r->backing.mode = UINT32_C(0x89abcdef) - i;
        r->backing.device = UINT64_C(0x0102030405060708) + i;
        r->backing.inode = UINT64_C(0xf1e2d3c4b5a69788) + i;
        r->backing.links = UINT64_C(0xfedcba9876543210) - i;
    }
    return result;
}
static int same_snapshot(const struct tfo_snapshot *a, const struct tfo_snapshot *b) {
    if (a->ready != b->ready || a->controller_pid != b->controller_pid ||
        a->child_pid != b->child_pid) return 0;
    for (unsigned i = 0; i < TFO_KEEP_COUNT; ++i) {
        const struct tfo_entry *x = &a->entries[i], *y = &b->entries[i];
        if (x->fd != y->fd || x->descriptor_flags != y->descriptor_flags ||
            x->status_flags != y->status_flags || x->backing.mode != y->backing.mode ||
            x->backing.device != y->backing.device || x->backing.inode != y->backing.inode ||
            x->backing.links != y->backing.links) return 0;
    }
    return 1;
}
static int rejected(const uint8_t *data, size_t length, const struct bw_binding *b) {
    struct bw_status s; struct tfo_snapshot t;
    memset(&s, 0xa5, sizeof(s)); memset(&t, 0xa5, sizeof(t));
    CHECK(bow_status_decode(data, length, b, &s, &t) != BW_OK);
    CHECK(all_zero(&s, sizeof(s)) && all_zero(&t, sizeof(t)));
    return 0;
}
static int encode_rejected(const struct bw_status *s, const struct tfo_snapshot *t) {
    uint8_t out[BOW_STATUS_SIZE]; memset(out, 0xa5, sizeof(out));
    CHECK(bow_status_encode(s, t, out) != BW_OK);
    CHECK(all_zero(out, sizeof(out))); return 0;
}
static int go_rejected(const uint8_t *data, size_t length, const struct bw_binding *b) {
    struct bw_binding out; memset(&out, 0xa5, sizeof(out));
    CHECK(bow_go_decode(data, length, b, &out) != BW_OK);
    CHECK(all_zero(&out, sizeof(out))); return 0;
}
static int roundtrip(void) {
    for (unsigned kind = BW_READY; kind <= BW_ERROR; ++kind) {
        struct bw_status s = status(kind), decoded;
        struct tfo_snapshot t = snapshot(&s), decoded_t;
        uint8_t encoded[BOW_STATUS_SIZE], again[BOW_STATUS_SIZE], legacy[BW_STATUS_SIZE];
        CHECK(bow_status_encode(&s, kind == BW_READY ? &t : NULL, encoded) == BW_OK);
        CHECK(bw_status_encode(&s, legacy) == BW_OK);
        CHECK(memcmp(legacy, encoded + BOW_PAYLOAD_OFFSET, sizeof(legacy)) == 0);
        CHECK(bow_status_decode(encoded, sizeof(encoded), &s.binding, &decoded, &decoded_t) == BW_OK);
        CHECK(bow_status_encode(&decoded, kind == BW_READY ? &decoded_t : NULL, again) == BW_OK);
        CHECK(memcmp(encoded, again, sizeof(encoded)) == 0);
        if (kind == BW_READY) CHECK(same_snapshot(&t, &decoded_t));
        else CHECK(all_zero(&decoded_t, sizeof(decoded_t)));
    }
    return 0;
}
static int lengths(void) {
    struct bw_status s = status(BW_READY); struct tfo_snapshot t = snapshot(&s);
    uint8_t out[BOW_STATUS_SIZE]; CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    for (size_t n = 0; n < BOW_STATUS_SIZE; ++n) CHECK(rejected(out, n, &s.binding) == 0);
    const size_t too_long[] = {513, 1024, SIZE_MAX};
    for (unsigned i = 0; i < sizeof(too_long) / sizeof(too_long[0]); ++i)
        CHECK(rejected(out, too_long[i], &s.binding) == 0);
    CHECK(rejected(NULL, BOW_STATUS_SIZE, &s.binding) == 0);
    CHECK(rejected(out, BOW_STATUS_SIZE, NULL) == 0);
    CHECK(encode_rejected(NULL, &t) == 0);
    CHECK(bow_status_encode(&s, &t, NULL) == BW_FAULT_ARGUMENT);
    struct bw_status decoded; struct tfo_snapshot observed;
    memset(&decoded, 0xa5, sizeof(decoded)); memset(&observed, 0xa5, sizeof(observed));
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, &decoded, NULL) == BW_FAULT_ARGUMENT);
    CHECK(all_zero(&decoded, sizeof(decoded)));
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, NULL, &observed) == BW_FAULT_ARGUMENT);
    CHECK(all_zero(&observed, sizeof(observed)));
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, NULL, NULL) == BW_FAULT_ARGUMENT);
    return 0;
}
static int headers(void) {
    struct bw_status s = status(BW_READY); struct tfo_snapshot t = snapshot(&s);
    uint8_t out[BOW_STATUS_SIZE], changed[BOW_STATUS_SIZE];
    CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    for (unsigned i = 0; i < BOW_PAYLOAD_OFFSET; ++i) {
        memcpy(changed, out, sizeof(out)); changed[i] ^= 0x80;
        CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    }
    for (unsigned i = 488; i < BOW_STATUS_SIZE; ++i) {
        memcpy(changed, out, sizeof(out)); changed[i] = 1;
        CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    }
    for (unsigned i = 232; i < BW_STATUS_SIZE; ++i) {
        memcpy(changed, out, sizeof(out)); changed[BOW_PAYLOAD_OFFSET + i] = 1;
        CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    }
    memcpy(changed, out, sizeof(out)); changed[BOW_PAYLOAD_OFFSET + 10] = 0;
    changed[BOW_PAYLOAD_OFFSET + 11] = BW_ERROR;
    CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    /* A canonical inner ATTEMPT still cannot masquerade as an outer READY. */
    s = status(BW_EXEC_ATTEMPT);
    CHECK(bw_status_encode(&s, changed + BOW_PAYLOAD_OFFSET) == BW_OK);
    CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    return 0;
}
static int rows(void) {
    struct bw_status s = status(BW_READY); struct tfo_snapshot t = snapshot(&s), bad;
    uint8_t out[BOW_STATUS_SIZE], changed[BOW_STATUS_SIZE];
    CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    CHECK(encode_rejected(&s, NULL) == 0);
    const int invalid_ready[] = {-1, 0, 2, INT_MAX};
    for (unsigned i = 0; i < sizeof(invalid_ready) / sizeof(invalid_ready[0]); ++i) {
        bad = t; bad.ready = invalid_ready[i]; CHECK(encode_rejected(&s, &bad) == 0);
    }
    bad = t; bad.controller_pid++; CHECK(encode_rejected(&s, &bad) == 0);
    bad = t; bad.child_pid += UINT64_C(1) << 32; CHECK(encode_rejected(&s, &bad) == 0);
    for (unsigned i = 0; i < TFO_KEEP_COUNT; ++i) {
        bad = t; bad.entries[i].fd = -1; CHECK(encode_rejected(&s, &bad) == 0);
        bad = t; bad.entries[i].fd++; CHECK(encode_rejected(&s, &bad) == 0);
        bad = t; bad.entries[i].descriptor_flags = -1; CHECK(encode_rejected(&s, &bad) == 0);
        bad = t; bad.entries[i].status_flags = INT_MIN; CHECK(encode_rejected(&s, &bad) == 0);
        for (unsigned field = 0; field < 3; ++field) {
            memcpy(changed, out, sizeof(out));
            changed[BOW_ROW_OFFSET + BOW_ROW_SIZE * i + 4 * field] = 0x80;
            CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
        }
        memcpy(changed, out, sizeof(out)); changed[BOW_ROW_OFFSET + BOW_ROW_SIZE * i + 3] ^= 1;
        CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    }
    /* Preserve every nonnegative native flag bit, and opaque unsigned extrema. */
    for (unsigned i = 0; i < TFO_KEEP_COUNT; ++i) {
        t.entries[i].descriptor_flags = INT_MAX; t.entries[i].status_flags = INT_MAX;
        t.entries[i].backing.mode = UINT32_MAX; t.entries[i].backing.device = UINT64_MAX;
        t.entries[i].backing.inode = 0; t.entries[i].backing.links = UINT64_MAX;
    }
    CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    struct bw_status decoded; struct tfo_snapshot observed;
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, &decoded, &observed) == BW_OK);
    CHECK(same_snapshot(&t, &observed));
    for (unsigned kind = BW_EXEC_ATTEMPT; kind <= BW_ERROR; ++kind) {
        s = status(kind); CHECK(encode_rejected(&s, &t) == 0);
        CHECK(bow_status_encode(&s, NULL, out) == BW_OK);
        for (unsigned i = BOW_ROW_OFFSET; i < 488; ++i) {
            memcpy(changed, out, sizeof(out)); changed[i] = 1;
            CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
        }
        memcpy(changed, out, sizeof(out)); changed[19] = TFO_KEEP_COUNT;
        CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    }
    return 0;
}
static int canonical(void) {
    struct bw_status s = status(BW_READY), bad; struct tfo_snapshot t = snapshot(&s);
    uint8_t out[BOW_STATUS_SIZE], changed[BOW_STATUS_SIZE];
    CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    struct bw_binding b = s.binding;
    b.controller_pid++; CHECK(rejected(out, sizeof(out), &b) == 0);
    b = s.binding; b.child_pid++; CHECK(rejected(out, sizeof(out), &b) == 0);
    b = s.binding; b.request_sha256[31]++; CHECK(rejected(out, sizeof(out), &b) == 0);
    b = s.binding; b.controller_pid = b.child_pid; CHECK(rejected(out, sizeof(out), &b) == 0);
    bad = s; bad.real_uid = 0; CHECK(encode_rejected(&bad, &t) == 0);
    bad = s; bad.groups[1] = bad.groups[0]; CHECK(encode_rejected(&bad, &t) == 0);
    bad = s; bad.kept_fds[4] = bad.kept_fds[3]; CHECK(encode_rejected(&bad, &t) == 0);
    bad = s; bad.detail = INT64_MAX; CHECK(encode_rejected(&bad, &t) == 0);
    bad = s; bad.mutation_flags = 4; CHECK(encode_rejected(&bad, &t) == 0);
    const unsigned offsets[] = {68, 75, 91, 103, 175, 231};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
        memcpy(changed, out, sizeof(out)); changed[BOW_PAYLOAD_OFFSET + offsets[i]] ^= 0x80;
        CHECK(rejected(changed, sizeof(changed), &s.binding) == 0);
    }
    return 0;
}
static int profiles(void) {
    struct bw_status s = status(BW_READY), decoded;
    struct tfo_snapshot t = snapshot(&s);
    uint8_t out[BOW_STATUS_SIZE], old[BW_STATUS_SIZE], padded[BOW_STATUS_SIZE] = {0};
    CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    CHECK(bw_status_encode(&s, old) == BW_OK);
    for (size_t n = 0; n <= BOW_STATUS_SIZE; ++n) {
        memset(&decoded, 0xa5, sizeof(decoded));
        CHECK(bw_status_decode(out, n, &s.binding, &decoded) != BW_OK);
        CHECK(all_zero(&decoded, sizeof(decoded)));
    }
    CHECK(rejected(old, sizeof(old), &s.binding) == 0);
    memcpy(padded, old, sizeof(old)); CHECK(rejected(padded, sizeof(padded), &s.binding) == 0);
    memcpy(padded, out, sizeof(out)); padded[9] = 1;
    CHECK(rejected(padded, sizeof(padded), &s.binding) == 0);
    memcpy(padded, out, sizeof(out)); memcpy(padded, "GLUEBS01", 8);
    CHECK(rejected(padded, sizeof(padded), &s.binding) == 0);
    return 0;
}
static int go(void) {
    struct bw_binding b = binding(), decoded, invalid;
    uint8_t out[BOW_GO_SIZE], old[BW_GO_SIZE], changed[BOW_GO_SIZE];
    CHECK(bow_go_encode(&b, out) == BW_OK);
    CHECK(bow_go_decode(out, sizeof(out), &b, &decoded) == BW_OK);
    CHECK(memcmp(&b, &decoded, sizeof(b)) == 0);
    memcpy(changed, out, sizeof(out)); changed[63] = 1;
    CHECK(bow_go_decode(changed, sizeof(changed), &b, &decoded) != BW_OK);
    CHECK(all_zero(&decoded, sizeof(decoded)));
    CHECK(bw_go_encode(&b, old) == BW_OK);
    CHECK(go_rejected(old, sizeof(old), &b) == 0);
    memset(&decoded, 0xa5, sizeof(decoded));
    CHECK(bw_go_decode(out, sizeof(out), &b, &decoded) != BW_OK);
    CHECK(all_zero(&decoded, sizeof(decoded)));
    for (size_t n = 0; n < BOW_GO_SIZE; ++n) CHECK(go_rejected(out, n, &b) == 0);
    CHECK(go_rejected(out, BOW_GO_SIZE + 1, &b) == 0);
    CHECK(go_rejected(out, SIZE_MAX, &b) == 0);
    CHECK(go_rejected(NULL, sizeof(out), &b) == 0);
    CHECK(go_rejected(out, sizeof(out), NULL) == 0);
    for (unsigned i = 0; i < BOW_GO_SIZE; ++i) {
        memcpy(changed, out, sizeof(out)); changed[i] ^= 0x80;
        CHECK(go_rejected(changed, sizeof(changed), &b) == 0);
    }
    invalid = b; invalid.child_pid = invalid.controller_pid;
    CHECK(go_rejected(out, sizeof(out), &invalid) == 0);
    memset(changed, 0xa5, sizeof(changed));
    CHECK(bow_go_encode(&invalid, changed) != BW_OK); CHECK(all_zero(changed, sizeof(changed)));
    memset(changed, 0xa5, sizeof(changed));
    CHECK(bow_go_encode(NULL, changed) != BW_OK); CHECK(all_zero(changed, sizeof(changed)));
    CHECK(bow_go_encode(&b, NULL) == BW_FAULT_ARGUMENT);
    CHECK(bow_go_decode(out, sizeof(out), &b, NULL) == BW_FAULT_ARGUMENT);
    /* Both mixed-version shapes are refused, not detected or downgraded. */
    memcpy(changed, out, sizeof(out)); changed[9] = 1;
    CHECK(go_rejected(changed, sizeof(changed), &b) == 0);
    memcpy(changed, old, sizeof(old)); changed[9] = 2;
    CHECK(go_rejected(changed, sizeof(changed), &b) == 0);
    return 0;
}
static int no_stale(void) {
    struct bw_status s = status(BW_READY), decoded; struct tfo_snapshot t = snapshot(&s), observed;
    uint8_t out[BOW_STATUS_SIZE]; CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, &decoded, &observed) == BW_OK);
    out[BOW_ROW_OFFSET + 4 * BOW_ROW_SIZE + 8] = 0xff;
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, &decoded, &observed) != BW_OK);
    CHECK(all_zero(&decoded, sizeof(decoded)) && all_zero(&observed, sizeof(observed)));
    CHECK(bow_status_encode(&s, &t, out) == BW_OK);
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, &decoded, &observed) == BW_OK);
    s = status(BW_EXEC_ATTEMPT); CHECK(bow_status_encode(&s, NULL, out) == BW_OK);
    CHECK(bow_status_decode(out, sizeof(out), &s.binding, &decoded, &observed) == BW_OK);
    CHECK(all_zero(&observed, sizeof(observed)));
    CHECK(bow_status_encode(&s, &t, out) != BW_OK);
    CHECK(all_zero(out, sizeof(out)));
    return 0;
}
static void print_hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    putchar('\n');
}
static int vectors(void) {
    const char *names[] = {"ready", "attempt", "error0", "error1", "error2"};
    for (unsigned i = 0; i < 5; ++i) {
        struct bw_status s = status(i == 0 ? BW_READY : i == 1 ? BW_EXEC_ATTEMPT : BW_ERROR);
        if (i == 3) { s.sequence = 1; s.stage = BW_GO_IO; s.reason = BW_MISMATCH; s.mutation_flags = 3; s.detail = 17; }
        if (i == 4) { s.sequence = 2; s.stage = BW_EXEC; s.reason = BW_SYSCALL; s.system_errno = 2; s.mutation_flags = 3; }
        struct tfo_snapshot t = snapshot(&s); uint8_t out[BOW_STATUS_SIZE];
        CHECK(bow_status_encode(&s, i == 0 ? &t : NULL, out) == BW_OK);
        printf("%s:", names[i]); print_hex(out, sizeof(out));
    }
    struct bw_binding b = binding(); uint8_t out[BOW_GO_SIZE];
    CHECK(bow_go_encode(&b, out) == BW_OK); printf("go:"); print_hex(out, sizeof(out)); return 0;
}
static int from_hex(const char *text, uint8_t *out, size_t n) {
    if (strlen(text) != n * 2) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned value;
        if (sscanf(text + 2 * i, "%2x", &value) != 1) return 0;
        out[i] = (uint8_t)value;
    }
    return 1;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "vectors")) return vectors();
    if (!strcmp(argv[1], "decode-status") && argc == 3) {
        uint8_t in[BOW_STATUS_SIZE]; struct bw_binding b = binding();
        struct bw_status s; struct tfo_snapshot t;
        CHECK(from_hex(argv[2], in, sizeof(in)));
        CHECK(bow_status_decode(in, sizeof(in), &b, &s, &t) == BW_OK);
        puts("decoded"); return 0;
    }
    if (!strcmp(argv[1], "decode-go") && argc == 3) {
        uint8_t in[BOW_GO_SIZE]; struct bw_binding b = binding(), out;
        CHECK(from_hex(argv[2], in, sizeof(in)));
        CHECK(bow_go_decode(in, sizeof(in), &b, &out) == BW_OK);
        puts("decoded"); return 0;
    }
    if (!strcmp(argv[1], "roundtrip")) return roundtrip();
    if (!strcmp(argv[1], "lengths")) return lengths();
    if (!strcmp(argv[1], "headers")) return headers();
    if (!strcmp(argv[1], "rows")) return rows();
    if (!strcmp(argv[1], "canonical")) return canonical();
    if (!strcmp(argv[1], "profiles")) return profiles();
    if (!strcmp(argv[1], "go")) return go();
    if (!strcmp(argv[1], "no-stale")) return no_stale();
    return 2;
}
