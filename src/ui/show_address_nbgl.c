#ifdef HAVE_NBGL

#include <string.h>  // memset

#include "menu.h"
#include "display.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "reedSolomon.h"

static char rsAddress[27];

static void reviewChoice(bool confirm) {
    if (confirm) {
        showAddressConfirm();
    } else {
        showAddressCancel();
    }
}

static void continueReview(void) {
    nbgl_useCaseAddressConfirmation(rsAddress, reviewChoice);
}

void showAddressScreen(const uint64_t accountId) {
    memset(rsAddress, 0, sizeof(rsAddress));
    snprintf(rsAddress, sizeof(rsAddress), APP_PREFIX);
    reedSolomonEncode(accountId, rsAddress + strlen(rsAddress));

    nbgl_useCaseReviewStart(&C_ArdorIcon64px,
                            "Verify Ardor address",
                            NULL,
                            "Cancel",
                            continueReview,
                            showAddressCancel);
}

#endif