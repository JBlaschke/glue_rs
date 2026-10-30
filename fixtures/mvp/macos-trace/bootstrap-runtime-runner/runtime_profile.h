#ifndef GLUE_RUNTIME_BOOTSTRAP_PROFILE_H
#define GLUE_RUNTIME_BOOTSTRAP_PROFILE_H
#include "../bootstrap-object-runner/objects_profile.h"
#if defined(GLUE_RUNTIME_PROFILE) && GLUE_RUNTIME_PROFILE != 1
#error runtime profile is fixed by reviewed source
#endif
#ifdef GLUE_OWNED_TRACING
#error later runtime exec epochs require separate tracing adoption
#endif
#define GLUE_RUNTIME_PROFILE 1
#endif
