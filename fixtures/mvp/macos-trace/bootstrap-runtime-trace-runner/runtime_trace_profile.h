#ifndef GLUE_FIXED_RUNTIME_TRACE_PROFILE_H
#define GLUE_FIXED_RUNTIME_TRACE_PROFILE_H
/* Source-selected wrapper only. Include the unchanged untraced profile before
 * adding tracing, so ordinary runtime wrappers still reject traced builds. */
#if defined(GLUE_RUNTIME_TRACING) || defined(GLUE_OWNED_TRACING)
#error runtime tracing is selected only by the fixed source wrapper
#endif
#include "../bootstrap-runtime-runner/runtime_profile.h"
#define GLUE_RUNTIME_TRACING 1
#define GLUE_OWNED_TRACING 1
#endif
