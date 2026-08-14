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
        // showAddressConfirm sends the APDU response and returns to the main menu
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, showAddressConfirm);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, showAddressCancel);
    }
}

void showAddressScreen(const uint64_t accountId) {
    explicit_bzero(rsAddress, sizeof(rsAddress));
    snprintf(rsAddress, sizeof(rsAddress), APP_PREFIX);
    reedSolomonEncode(accountId, rsAddress + strlen(rsAddress));

    nbgl_useCaseAddressReview(rsAddress,
                              NULL,
                              &C_ArdorIcon64px,
                              "Verify Ardor address",
                              NULL,
                              reviewChoice);
}

#endif
