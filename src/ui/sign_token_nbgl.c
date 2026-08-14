#ifdef HAVE_NBGL

#include "display.h"
#include "nbgl_use_case.h"
#include "ardor.h"
#include "glyphs.h"
#include "menu.h"
#include "blind_sign_nbgl.h"

// The token content itself cannot be decoded, so the review shows the only
// meaningful field, the token timestamp (also, a review needs at least one
// tag-value pair to be navigable)
static char timestampText[11];
static nbgl_contentTagValue_t pair;
static nbgl_contentTagValueList_t pairList;

static void reviewChoice(bool confirm) {
    if (confirm) {
        signTokenConfirm();
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_SIGNED, ui_menu_main);
    } else {
        signTokenCancel();
        nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
    }
}

static void startBlindReview(void) {
    snprintf(timestampText, sizeof(timestampText), "%u", state.tokenSign.timestamp);
    pair.item = "Timestamp";
    pair.value = timestampText;
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = &pair;
    nbgl_useCaseReviewBlindSigning(TYPE_OPERATION,
                                   &pairList,
                                   &C_ArdorIcon64px,
                                   "Token signature",
                                   NULL,
                                   "Sign token?",
                                   NULL,
                                   reviewChoice);
}

static void rejectBeforeReview(void) {
    signTokenCancel();
    nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
}

void signTokenScreen(void) {
    blindSigningEnsureEnabled(startBlindReview, rejectBeforeReview);
}

#endif
