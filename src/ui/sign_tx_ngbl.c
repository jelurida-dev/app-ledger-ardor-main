#ifdef HAVE_NBGL

#include "display.h"
#include "nbgl_use_case.h"
#include "ardor.h"
#include "glyphs.h"
#include "menu.h"
#include "blind_sign_nbgl.h"

static nbgl_contentTagValue_t pairs[6];
static nbgl_contentTagValueList_t pairList;

static void reviewChoice(bool confirm) {
    if (confirm) {
        signTransactionConfirm();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        signTransactionCancel();
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

static void preparePairList(void) {
    int i = 0;
    pairs[i].item = "Chain&TxnType";
    pairs[i++].value = state.txnAuth.chainAndTxnTypeText;
    for (int j = 0; j < MAX_WINDOWS; j++) {
        if (*state.txnAuth.windowTitles[j] != 0) {
            pairs[i].item = state.txnAuth.windowTitles[j];
            pairs[i++].value = state.txnAuth.windowTexts[j];
        }
    }
    if (*state.txnAuth.appendagesText != 0) {
        pairs[i].item = "Appendages";
        pairs[i++].value = state.txnAuth.appendagesText;
    }
    pairs[i].item = "Fees";
    pairs[i++].value = state.txnAuth.feeText;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = i;
    pairList.pairs = pairs;
}

static void startBlindReview(void) {
    preparePairList();
    nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                   &pairList,
                                   &C_ArdorIcon64px,
                                   "Review transaction",
                                   NULL,
                                   "Sign transaction?",
                                   NULL,
                                   reviewChoice);
}

static void rejectBeforeReview(void) {
    signTransactionCancel();
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
}

void signTransactionScreen(void) {
    if (state.txnAuth.requiresBlindSigning) {
        blindSigningEnsureEnabled(startBlindReview, rejectBeforeReview);
    } else {
        preparePairList();
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &pairList,
                           &C_ArdorIcon64px,
                           "Review transaction",
                           NULL,
                           "Sign transaction?",
                           reviewChoice);
    }
}

#endif
