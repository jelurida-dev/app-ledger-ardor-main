#ifdef HAVE_NBGL

#include "ardor.h"
#include "settings.h"

#include "nbgl_use_case.h"
#include "glyphs.h"
#include "blind_sign_nbgl.h"

static nbgl_callback_t continue_cb;
static nbgl_callback_t reject_cb;

static void blind_sign_choice(bool enable) {
    if (enable) {
        settings_set_allow_blind_signing(true);
        continue_cb();
    } else {
        reject_cb();
    }
}

void blindSigningEnsureEnabled(nbgl_callback_t continue_callback, nbgl_callback_t reject_callback) {
    if (N_storage.settings.allowBlindSigning) {
        continue_callback();
        return;
    }
    continue_cb = continue_callback;
    reject_cb = reject_callback;
    nbgl_useCaseChoice(&C_Warning_64px,
                       "Enable blind signing to\nauthorize this\noperation",
                       NULL,
                       "Enable blind signing",
                       "Reject",
                       blind_sign_choice);
}

#endif
