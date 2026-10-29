#include "bootstrap_object_wire.h"
#include <limits.h>
#include <string.h>

_Static_assert(CHAR_BIT == 8, "wire octets");
_Static_assert(sizeof(uint32_t) == 4 && sizeof(uint64_t) == 8, "wire widths");
_Static_assert(TFO_KEEP_COUNT == 5, "fixed descriptor rows");
_Static_assert(BOW_PAYLOAD_OFFSET + BW_STATUS_SIZE == BOW_ROW_OFFSET, "payload extent");
_Static_assert(BOW_ROW_OFFSET + TFO_KEEP_COUNT * BOW_ROW_SIZE == 488, "row extent");
_Static_assert(BOW_GO_SIZE == BW_GO_SIZE, "GO extent");

static const uint8_t status_magic[8] = {'G','L','U','E','F','S','0','2'};
static const uint8_t go_magic[8] = {'G','L','U','E','F','G','0','2'};
static void put16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static void put32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (24 - 8 * i));
}
static void put64(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint32_t get16(const uint8_t *p) {
    return ((uint32_t)p[0] << 8) | p[1];
}
static uint32_t get32(const uint8_t *p) {
    uint32_t v = 0;
    for (unsigned i = 0; i < 4; ++i) v = (v << 8) | p[i];
    return v;
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
static int zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i]) return 0;
    return 1;
}
static enum bw_fault snapshot_valid(const struct bw_status *s,
    const struct tfo_snapshot *snapshot) {
    if (!snapshot) return BW_FAULT_ARGUMENT;
    if (snapshot->ready != 1) return BW_FAULT_CANONICAL;
    if (snapshot->controller_pid != s->binding.controller_pid ||
        snapshot->child_pid != s->binding.child_pid) return BW_FAULT_BINDING;
    for (unsigned i = 0; i < TFO_KEEP_COUNT; ++i) {
        const struct tfo_entry *row = &snapshot->entries[i];
        if (row->fd < 0 || row->descriptor_flags < 0 || row->status_flags < 0)
            return BW_FAULT_CANONICAL;
        if ((uint64_t)row->descriptor_flags > UINT32_MAX ||
            (uint64_t)row->status_flags > UINT32_MAX) return BW_FAULT_CANONICAL;
        if ((uint64_t)row->fd != s->kept_fds[i]) return BW_FAULT_CANONICAL;
    }
    return BW_OK;
}

enum bw_fault bow_status_encode(const struct bw_status *s,
    const struct tfo_snapshot *snapshot, uint8_t out[BOW_STATUS_SIZE]) {
    if (!out) return BW_FAULT_ARGUMENT;
    memset(out, 0, BOW_STATUS_SIZE);
    if (!s) return BW_FAULT_ARGUMENT;
    uint8_t payload[BW_STATUS_SIZE];
    enum bw_fault f = bw_status_encode(s, payload);
    if (f != BW_OK) return f;
    if (s->kind == BW_READY) {
        f = snapshot_valid(s, snapshot);
        if (f != BW_OK) return f;
    } else if (snapshot) return BW_FAULT_CANONICAL;

    memcpy(out, status_magic, sizeof(status_magic));
    put16(out + 8, 2); put16(out + 10, s->kind);
    put32(out + 12, BOW_STATUS_SIZE);
    put32(out + 16, s->kind == BW_READY ? TFO_KEEP_COUNT : 0);
    put32(out + 20, BW_STATUS_SIZE);
    memcpy(out + BOW_PAYLOAD_OFFSET, payload, sizeof(payload));
    if (s->kind == BW_READY) {
        for (unsigned i = 0; i < TFO_KEEP_COUNT; ++i) {
            const struct tfo_entry *row = &snapshot->entries[i];
            uint8_t *p = out + BOW_ROW_OFFSET + i * BOW_ROW_SIZE;
            put32(p, (uint32_t)row->fd);
            put32(p + 4, (uint32_t)row->descriptor_flags);
            put32(p + 8, (uint32_t)row->status_flags);
            put32(p + 12, row->backing.mode);
            put64(p + 16, row->backing.device);
            put64(p + 24, row->backing.inode);
            put64(p + 32, row->backing.links);
        }
    }
    return BW_OK;
}

enum bw_fault bow_status_decode(const uint8_t *in, size_t length,
    const struct bw_binding *expected, struct bw_status *status,
    struct tfo_snapshot *snapshot) {
    if (status) memset(status, 0, sizeof(*status));
    if (snapshot) memset(snapshot, 0, sizeof(*snapshot));
    if (!status || !snapshot) return BW_FAULT_ARGUMENT;
    if (length != BOW_STATUS_SIZE) return BW_FAULT_LENGTH;
    if (!in || !expected) return BW_FAULT_ARGUMENT;
    if (memcmp(in, status_magic, sizeof(status_magic))) return BW_FAULT_MAGIC;
    if (get16(in + 8) != 2) return BW_FAULT_VERSION;
    if (get32(in + 12) != BOW_STATUS_SIZE || get32(in + 20) != BW_STATUS_SIZE)
        return BW_FAULT_LENGTH;
    if (!zero(in + 24, 8) || !zero(in + 488, 24)) return BW_FAULT_RESERVED;
    uint32_t kind = get16(in + 10);
    if (kind < BW_READY || kind > BW_ERROR) return BW_FAULT_KIND;
    if (get32(in + 16) != (kind == BW_READY ? TFO_KEEP_COUNT : 0))
        return BW_FAULT_CANONICAL;

    struct bw_status s;
    enum bw_fault f = bw_status_decode(in + BOW_PAYLOAD_OFFSET, BW_STATUS_SIZE,
        expected, &s);
    if (f != BW_OK) return f;
    if (s.kind != kind) return BW_FAULT_CANONICAL;
    struct tfo_snapshot observations = {0};
    if (kind == BW_READY) {
        observations.ready = 1;
        observations.controller_pid = s.binding.controller_pid;
        observations.child_pid = s.binding.child_pid;
        for (unsigned i = 0; i < TFO_KEEP_COUNT; ++i) {
            const uint8_t *p = in + BOW_ROW_OFFSET + i * BOW_ROW_SIZE;
            uint32_t fd = get32(p), descriptor_flags = get32(p + 4);
            uint32_t status_flags = get32(p + 8);
            if ((uint64_t)fd > INT_MAX || (uint64_t)descriptor_flags > INT_MAX ||
                (uint64_t)status_flags > INT_MAX) return BW_FAULT_CANONICAL;
            struct tfo_entry *row = &observations.entries[i];
            row->fd = (int)fd;
            row->descriptor_flags = (int)descriptor_flags;
            row->status_flags = (int)status_flags;
            row->backing.mode = get32(p + 12);
            row->backing.device = get64(p + 16);
            row->backing.inode = get64(p + 24);
            row->backing.links = get64(p + 32);
        }
        f = snapshot_valid(&s, &observations);
        if (f != BW_OK) return f;
    } else if (!zero(in + BOW_ROW_OFFSET, TFO_KEEP_COUNT * BOW_ROW_SIZE)) {
        return BW_FAULT_CANONICAL;
    }
    *status = s;
    *snapshot = observations;
    return BW_OK;
}

enum bw_fault bow_go_encode(const struct bw_binding *binding,
    uint8_t out[BOW_GO_SIZE]) {
    if (!out) return BW_FAULT_ARGUMENT;
    memset(out, 0, BOW_GO_SIZE);
    uint8_t payload[BW_GO_SIZE];
    enum bw_fault f = bw_go_encode(binding, payload);
    if (f != BW_OK) return f;
    memcpy(payload, go_magic, sizeof(go_magic));
    put16(payload + 8, 2);
    memcpy(out, payload, sizeof(payload));
    return BW_OK;
}

enum bw_fault bow_go_decode(const uint8_t *in, size_t length,
    const struct bw_binding *expected, struct bw_binding *out) {
    if (!out) return BW_FAULT_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (length != BOW_GO_SIZE) return BW_FAULT_LENGTH;
    if (!in || !expected) return BW_FAULT_ARGUMENT;
    if (memcmp(in, go_magic, sizeof(go_magic))) return BW_FAULT_MAGIC;
    if (get16(in + 8) != 2) return BW_FAULT_VERSION;
    /* Rebase only the explicitly admitted new magic/version into the existing
     * strict GO validator. No legacy input can reach this conversion. */
    uint8_t canonical[BW_GO_SIZE], payload[BW_GO_SIZE];
    enum bw_fault f = bw_go_encode(expected, canonical);
    if (f != BW_OK) return f;
    memcpy(payload, in, sizeof(payload));
    memcpy(payload, canonical, 10);
    return bw_go_decode(payload, sizeof(payload), expected, out);
}
