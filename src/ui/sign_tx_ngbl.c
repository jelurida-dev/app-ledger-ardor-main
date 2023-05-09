#ifdef HAVE_NBGL

#include "display.h"
#include "nbgl_use_case.h"
#include "ardor.h"
#include "glyphs.h"
#include "menu.h"

static void signTxConfirmation() {
    signTransactionConfirm();
    nbgl_useCaseStatus("SIGNATURE\nSUCCESSFUL", true, ui_menu_main);
}

static void signTxCancellation() {
    signTransactionCancel();
    nbgl_useCaseStatus("Signature\ncancelled", false, ui_menu_main);
}

static void askTransactionRejectionConfirmation(void) {
    // display a choice to confirm/cancel rejection
    nbgl_useCaseConfirm("Reject transaction?",
                        NULL,
                        "Yes, Reject",
                        "Go back to transaction",
                        signTxCancellation);
}

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void reviewChoice(bool confirm) {
    if (confirm) {
        signTxConfirmation();
    } else {
        askTransactionRejectionConfirmation();
    }
}

static nbgl_layoutTagValue_t pairs[6];
static nbgl_layoutTagValueList_t pairList;

static void reviewContinue() {
    int i = 0;
    pairs[i].item = "Chain&TxnType";
    pairs[i++].value = state.txnAuth.chainAndTxnTypeText;
    if (state.txnAuth.uiFlowBitfeild > 1) {
        // optionals 1 and 2
        pairs[i].item = state.txnAuth.optionalWindow1Title;
        pairs[i++].value = state.txnAuth.optionalWindow1Text;
        pairs[i].item = state.txnAuth.optionalWindow2Title;
        pairs[i++].value = state.txnAuth.optionalWindow2Text;
    }
    if (state.txnAuth.uiFlowBitfeild > 5) {
        pairs[i].item = state.txnAuth.optionalWindow3Title;
        pairs[i++].value = state.txnAuth.optionalWindow3Text;
    }
    if (state.txnAuth.uiFlowBitfeild == 1 || state.txnAuth.uiFlowBitfeild == 7) {
        pairs[i].item = "Appendages";
        pairs[i++].value = state.txnAuth.appendagesText;
    }
    pairs[i].item = "Fees";
    pairs[i++].value = state.txnAuth.feeText;
    
    PRINTF("uiFlowBitfeild: %d i: %d\n", state.txnAuth.uiFlowBitfeild, i);

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = i;
    pairList.pairs = pairs;

    nbgl_pageInfoLongPress_t infoLongPress = {
        .icon = &C_ArdorIcon64px,
        .text = "Confirm\nSign transaction",
        .longPressText = "Hold to sign"
    };
    PRINTF("nbgl_useCaseStaticReview\n");
    nbgl_useCaseStaticReview(&pairList, &infoLongPress, "Reject transaction", reviewChoice);
}

void signTransactionScreen() {
    nbgl_useCaseReviewStart(&C_ArdorIcon64px,
                        "Review transaction",
                        NULL,
                        "Reject transaction",
                        reviewContinue,
                        askTransactionRejectionConfirmation);
}

#endif