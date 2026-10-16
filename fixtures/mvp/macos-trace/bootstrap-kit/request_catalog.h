#ifndef GLUE_BOOTSTRAP_KIT_REQUEST_CATALOG_H
#define GLUE_BOOTSTRAP_KIT_REQUEST_CATALOG_H
#include "../bootstrap-admission/bootstrap_admission.h"
#include "../bootstrap-request/bootstrap_request.h"
#define BK_CATALOG_CAPACITY 320u
#define BK_CATALOG_LENGTH 269u
/* Compiled constant only, supplied by the generated catalog translation unit.
 * There is no native argument/environment selector for this object. */
struct bk_request_catalog { uint8_t bytes[BK_CATALOG_CAPACITY]; size_t length; };
struct bk_catalog_context {
    struct ba_deployment deployment;
    char executable[BA_PATH_MAX], cwd[BA_PATH_MAX];
};
const struct bk_request_catalog *bk_compiled_request_catalog(void);
/* Pure helpers. Valid, stable, nonalias input/output storage; outputs clear on
 * failure. Decode is deliberately narrower than generic NR: fixed lowercase
 * 64-hex build ID and context-probe leaf. It is not catalog authentication. */
int bk_catalog_decode(const struct bk_request_catalog *, struct bk_catalog_context *);
/* Complete directory policy for physical component indexes 0..6. Raw FD flags
 * use the build platform's ABI; only the Darwin native utility calls this in use. */
int bk_directory_metadata_valid(const struct ba_metadata *, const struct ba_deployment *, size_t);
/* Observations are caller-supplied unit data here. The native CLI obtains real
 * kernel observations and compiled data internally; this API grants no launch. */
int bk_request_prepare(const struct bk_catalog_context *, const uint64_t ids[4],
                       const uint64_t groups[TC_MAX_GROUPS], size_t group_count,
                       const struct ba_metadata *cwd, uint64_t release,
                       const uint8_t catalog_sha256[32], struct br_request *);
#endif
