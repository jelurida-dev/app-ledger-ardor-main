#pragma once

#ifdef HAVE_NBGL

#include "nbgl_use_case.h"

// Runs continue_callback if the blind signing setting is enabled. Otherwise asks
// the user to enable it: on acceptance the setting is stored in NVM and
// continue_callback runs, on refusal reject_callback runs.
void blindSigningEnsureEnabled(nbgl_callback_t continue_callback, nbgl_callback_t reject_callback);

#endif
