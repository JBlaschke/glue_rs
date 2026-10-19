#ifndef GLUE_NATIVE_BOOTSTRAP_RUNNER_H
#define GLUE_NATIVE_BOOTSTRAP_RUNNER_H
/* Exactly one native attempt; no elevation, alternate operations, runtime catalog
 * or arbitrary executable argument. Inputs/outputs follow the frozen closed
 * request/catalog/path profiles. Return0 means consistent diagnostic self-report,
 * never exec/trace/kernel identity/full acceptance. No root execution authorized
 * merely by this declaration. Platform/nonroot/unconfigured builds refuse.
 * Caller must terminate immediately with the returned status (the closed CLI
 * uses _exit); never reuse a controller after failure/uncertain cleanup or add
 * fallible finalization after a promoted result. Valid immutable C-string inputs. */
int nr_native_run_once(const char *request_path, const char *new_output_path);
#endif
