#ifdef HAVE_BAGL

#include "ux.h"
#include "display.h"
#include "menu.h"
#include "ardor.h"
#include "blind_sign_bagl.h"

static void signTxConfirmation() {
    signTransactionConfirm();
    ui_menu_main();
}

static void signTxCancellation() {
    signTransactionCancel();
    ui_menu_main();
}

#define MAX_NUM_STEPS 10

const ux_flow_step_t *ux_tx_flow[MAX_NUM_STEPS + 1];

UX_STEP_NOCB(ux_tx_initial,
             pnn,
             {
                 &C_icon_eye,
                 "Authorize",
                 "transaction",
             });
UX_STEP_NOCB(ux_tx_blind_signing_warning,
             pnn,
             {
                 &C_icon_warning,
                 "Blind",
                 "Signing",
             });
UX_STEP_NOCB(ux_tx_chain,
             bnnn_paging,
             {
                 .title = "Chain&TxnType",
                 .text = state.txnAuth.chainAndTxnTypeText,
             });
UX_STEP_NOCB(ux_tx_optional1,
             bnnn_paging,
             {
                 .title = state.txnAuth.optionalWindow1Title,
                 .text = state.txnAuth.optionalWindow1Text,
             });
UX_STEP_NOCB(ux_tx_optional2,
             bnnn_paging,
             {
                 .title = state.txnAuth.optionalWindow2Title,
                 .text = state.txnAuth.optionalWindow2Text,
             });
UX_STEP_NOCB(ux_tx_optional3,
             bnnn_paging,
             {
                 .title = state.txnAuth.optionalWindow3Title,
                 .text = state.txnAuth.optionalWindow3Text,
             });
UX_STEP_NOCB(ux_tx_appendages,
             bnnn_paging,
             {
                 .title = "Appendages",
                 .text = state.txnAuth.appendagesText,
             });
UX_STEP_NOCB(ux_tx_fee,
             bnnn_paging,
             {
                 .title = "Fees",
                 .text = state.txnAuth.feeText,
             });
UX_STEP_CB(ux_tx_accept,
           pbb,
           signTxConfirmation(),
           {
               &C_icon_validate_14,
               "Accept",
               "and send",
           });
UX_STEP_CB(ux_tx_reject,
           pb,
           signTxCancellation(),
           {
               &C_icon_crossmark,
               "Reject",
           });

void signTransactionScreen() {
    if (state.txnAuth.requiresBlindSigning && !N_storage.settings.allowBlindSigning) {
        blindSigningNotEnabledScreen(signTxCancellation);
        return;
    }

    uint8_t index = 0;

    ux_tx_flow[index++] = &ux_tx_initial;

    if (state.txnAuth.requiresBlindSigning) {
        ux_tx_flow[index++] = &ux_tx_blind_signing_warning;
    }

    ux_tx_flow[index++] = &ux_tx_chain;

    if (*state.txnAuth.optionalWindow1Title != 0) {
        ux_tx_flow[index++] = &ux_tx_optional1;
    }

    if (*state.txnAuth.optionalWindow2Title != 0) {
        ux_tx_flow[index++] = &ux_tx_optional2;
    }

    if (*state.txnAuth.optionalWindow3Title != 0) {
        ux_tx_flow[index++] = &ux_tx_optional3;
    }

    if (*state.txnAuth.appendagesText != 0) {
        ux_tx_flow[index++] = &ux_tx_appendages;
    }

    ux_tx_flow[index++] = &ux_tx_fee;
    ux_tx_flow[index++] = &ux_tx_accept;
    ux_tx_flow[index++] = &ux_tx_reject;

    ux_tx_flow[index++] = FLOW_END_STEP;
    ux_flow_init(0, ux_tx_flow, NULL);
}

#endif