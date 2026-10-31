/* Differential control only: existing production C wire/request decoders read
 * the independently constructed Python launch vectors. No launch/provider IO. */
#include "../bootstrap-request/bootstrap_request.h"
#include "../bootstrap-object-wire/bootstrap_object_wire.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t length[4], request[BR_MAX_WIRE], ready[BOW_STATUS_SIZE];
    uint8_t go[BOW_GO_SIZE], attempt[BOW_STATUS_SIZE];
    if (fread(length, 1, 4, stdin) != 4) return 1;
    size_t n = ((size_t)length[0] << 24) | ((size_t)length[1] << 16) |
               ((size_t)length[2] << 8) | length[3];
    if (n > sizeof(request) || fread(request, 1, n, stdin) != n ||
        fread(ready, 1, sizeof(ready), stdin) != sizeof(ready) ||
        fread(go, 1, sizeof(go), stdin) != sizeof(go) ||
        fread(attempt, 1, sizeof(attempt), stdin) != sizeof(attempt) ||
        fgetc(stdin) != EOF) return 2;
    struct br_request r;
    struct br_error error;
    if (br_request_decode(request, n, &r, &error) != BR_OK) return 3;
    struct bw_binding binding = {3131, 4242, {0}};
    memcpy(binding.request_sha256, ready + 32 + 24, 32);
    struct bw_status status, exec;
    struct tfo_snapshot snapshot, no_snapshot;
    if (bow_status_decode(ready, sizeof(ready), &binding, &status, &snapshot) != BW_OK ||
        status.kind != BW_READY || snapshot.ready != 1) return 4;
    struct br_ready_context context = {0};
    context.binding = binding;
    for (unsigned i = 0; i < 5; ++i) context.kept_fds[i] = status.kept_fds[i];
    memcpy(context.signal_policy_sha256, status.signal_policy_sha256, 32);
    if (br_ready_compare(&r, &context, &status, &error) != BR_OK) return 5;
    struct bw_binding decoded;
    if (bow_go_decode(go, sizeof(go), &binding, &decoded) != BW_OK) return 6;
    if (bow_status_decode(attempt, sizeof(attempt), &binding, &exec, &no_snapshot) != BW_OK ||
        exec.kind != BW_EXEC_ATTEMPT || no_snapshot.ready) return 7;
    return 0;
}
