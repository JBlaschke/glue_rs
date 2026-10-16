#ifndef GLUE_BOOTSTRAP_RUNNER_CATALOG_H
#define GLUE_BOOTSTRAP_RUNNER_CATALOG_H
#include <stddef.h>
#include <stdint.h>
#include "../bootstrap-admission/bootstrap_admission.h"
#define NR_CATALOG_HEADER_BYTES 192u
#define NR_CATALOG_CAPACITY 320u
#define NR_MAX_PROBE_BYTES UINT64_C(4194304)
#define NR_OUTPUT_PREFIX "/System/Volumes/Data/private/tmp/"
/* Build-time constant only. No native runtime argument can replace this object.
 * Source/recipe digests exclude generated catalog and resulting binary bytes. */
struct nr_catalog {
    uint64_t probe_bytes;
    struct ba_deployment deployment;
    uint8_t probe_sha256[32], probe_sources_sha256[32];
    uint8_t runner_static_sources_sha256[32], build_recipe_sha256[32];
    char build_id[65], leaf[65];
};
/* Supplied by exactly one build-time translation unit; default returns NULL. */
const struct nr_catalog *nr_compiled_catalog(void);
/* Pure canonical encoding only, not provisioning/admission or hashing.
 * All objects/spans valid, stable, nonalias. Whole320-byte output clears on failure. */
int nr_catalog_bytes(const struct nr_catalog *, uint8_t [NR_CATALOG_CAPACITY], size_t *);
int nr_catalog_paths(const struct nr_catalog *, char executable[BA_PATH_MAX], char cwd[BA_PATH_MAX]);
#endif
