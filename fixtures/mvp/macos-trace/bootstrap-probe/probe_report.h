#ifndef GLUE_BOOTSTRAP_PROBE_REPORT_H
#define GLUE_BOOTSTRAP_PROBE_REPORT_H
#include <stddef.h>
#include <stdint.h>
#define NP_REPORT_SIZE 256u
#define NP_MAX_GROUPS 16u
#define NP_ID_MAX UINT64_C(2147483647)
/* This wire profile describes Darwin values, independent of the codec host. */
#define NP_DARWIN_ACCMODE 3u
#define NP_DARWIN_NONBLOCK 4u
#define NP_DARWIN_ASYNC 64u
#define NP_DARWIN_EVTONLY 32768u
#define NP_DARWIN_CLOEXEC 1u
#define NP_DARWIN_EPERM 1u
struct np_report {
    uint8_t request_sha256[32];
    uint64_t pids[3], ids[4], group_count, groups[NP_MAX_GROUPS];
    uint64_t cwd_device, cwd_inode, fd_count, fds[3];
    uint64_t status_flags[3], descriptor_flags[3];
    int64_t root_regain_result;
    uint64_t root_regain_errno, post_ids[4], signal_policy, environment_count;
};
enum np_fault { NP_OK, NP_ARGUMENT, NP_LENGTH, NP_HEADER, NP_RESERVED, NP_BINDING, NP_CANONICAL };
/* Pure, no allocation/syscalls. C models are not wire layouts. All spans/objects
 * must be valid, stable and nonoverlapping. Encode/decode/hex outputs clear on
 * failure. Binding is supplied bytes, not proof of consumed request or exec. */
enum np_fault np_parse_sha256(const char *, size_t, uint8_t out[32]);
enum np_fault np_report_validate(const struct np_report *);
enum np_fault np_report_encode(const struct np_report *, uint8_t out[NP_REPORT_SIZE]);
enum np_fault np_report_decode(const uint8_t *, size_t, const uint8_t expected[32], struct np_report *);
#endif
