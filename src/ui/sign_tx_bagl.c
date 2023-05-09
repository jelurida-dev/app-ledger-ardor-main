#ifdef HAVE_BAGL

#include "ux.h"
#include "display.h"
#include "menu.h"
#include "ardor.h"

static void signTxConfirmation() {
    signTransactionConfirm();
    ui_menu_main();
}

static void signTxCancellation() {
    signTransactionCancel();
    ui_menu_main();
}

UX_STEP_NOCB(aasFlowPage1, 
    pnn, 
    {
      &C_icon_eye,
      "Authorize",
      "transaction",
    });
UX_STEP_NOCB(aasFlowPage2, 
    bnnn_paging, 
    {
      .title = "Chain&TxnType",
      .text = state.txnAuth.chainAndTxnTypeText,
    });

UX_STEP_NOCB(aasFlowOptional1,
    bnnn_paging, 
    {
      .title = state.txnAuth.optionalWindow1Title,
      .text = state.txnAuth.optionalWindow1Text,
    });
UX_STEP_NOCB(aasFlowOptional2, 
    bnnn_paging, 
    {
      .title = state.txnAuth.optionalWindow2Title,
      .text = state.txnAuth.optionalWindow2Text,
    });
UX_STEP_NOCB(aasFlowOptional3, 
    bnnn_paging, 
    {
        .title = state.txnAuth.optionalWindow3Title,
        .text = state.txnAuth.optionalWindow3Text,
    });
UX_STEP_NOCB(aasFlowAppendages, 
    bnnn_paging, 
    {
      .title = "Appendages",
      .text = state.txnAuth.appendagesText,
    });
UX_STEP_NOCB(aasFlowPage3, 
    bnnn_paging, 
    {
      .title = "Fees",
      .text = state.txnAuth.feeText,
    });
UX_STEP_CB(aasFlowPage4, 
    pbb, 
    signTxConfirmation(),
    {
      &C_icon_validate_14,
      "Accept",
      "and send",
    });
UX_STEP_CB(aasFlowPage5, 
    pb, 
    signTxCancellation(),
    {
      &C_icon_crossmark,
      "Reject",
    });

UX_FLOW(ux_flow_000,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_001,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowAppendages,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_010,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowOptional1,
  &aasFlowOptional2,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_011,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowOptional1,
  &aasFlowOptional2,
  &aasFlowAppendages,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_110,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowOptional1,
  &aasFlowOptional2,
  &aasFlowOptional3,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

UX_FLOW(ux_flow_111,
  &aasFlowPage1,
  &aasFlowPage2,
  &aasFlowOptional1,
  &aasFlowOptional2,
  &aasFlowOptional3,
  &aasFlowAppendages,
  &aasFlowPage3,
  &aasFlowPage4,
  &aasFlowPage5
);

void signTransactionScreen() {
    if(0 == G_ux.stack_count)
        ux_stack_push();

    switch (state.txnAuth.uiFlowBitfeild) {

        case 0x00:
            ux_flow_init(0, ux_flow_000, NULL);
            break;
        case 0x01:
            ux_flow_init(0, ux_flow_001, NULL);
            break;
        case 0x02:
            ux_flow_init(0, ux_flow_010, NULL);
            break;
        case 0x03:
            ux_flow_init(0, ux_flow_011, NULL);
            break;
        case 0x06:
            ux_flow_init(0, ux_flow_110, NULL);
            break;
        case 0x07:
            ux_flow_init(0, ux_flow_111, NULL);
            break;
    }
}

#endif