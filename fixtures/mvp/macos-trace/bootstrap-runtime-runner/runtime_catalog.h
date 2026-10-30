#ifndef GLUE_RUNTIME_BOOTSTRAP_CATALOG_H
#define GLUE_RUNTIME_BOOTSTRAP_CATALOG_H
#include "../bootstrap-admission/bootstrap_admission.h"
#include "../target-launch/target_launch.h"
#define NRR_CATALOG_CAPACITY 8192u
#define NRR_MAX_LAUNCHER_BYTES UINT64_C(16777216)
#define NRR_OUTPUT_BYTES 65536u
struct nrr_catalog {
 uint64_t launcher_bytes;
 struct ba_deployment deployment;
 uint8_t launcher_sha256[32], sources_sha256[32], recipe_sha256[32], r01_lock_sha256[32];
 char build_id[65], leaf[65], cwd_name[65];
 struct tl_recipe launch;
};
/* Compiled source only; NULL is the default and refuses before native effects.
 * Recipe/lock identities are provenance bindings, not proof of a native closure. */
const struct nrr_catalog *nrr_compiled_catalog(void);
/* Pure helpers require valid stable nonoverlapping objects/spans, including
 * readable complete recipe tables. Fixed outputs have their advertised size;
 * output bytes and written count clear on refusal. No path/native admission. */
int nrr_catalog_paths(const struct nrr_catalog *,char executable[BA_PATH_MAX],char cwd[BA_PATH_MAX]);
int nrr_catalog_bytes(const struct nrr_catalog *,uint8_t out[NRR_CATALOG_CAPACITY],size_t *used);
struct nr_attempt;
int nrr_prepare(struct nr_attempt *);
int nrr_admit(struct nr_attempt *);
#endif
