#ifdef HAVE_BAGL

#include <stdio.h>

#include "ux.h"
#include "display.h"
#include "reedSolomon.h"

char screenContent[27];
ui_callback callback_function;

UX_STEP_CB(saFlowPage1, 
    bnnn_paging,
    callback_function(),
    {
      .title = "Your Address",
      .text = screenContent,
    });
UX_STEP_CB(saFlowPage2, 
    pb, 
    callback_function(),
    {
      &C_icon_validate_14,
      "Done"
    });
UX_FLOW(saFlow,
  &saFlowPage1,
  &saFlowPage2
);

void showAddressScreen(const uint64_t accountId, ui_callback callback) {
    memset(screenContent, 0, sizeof(screenContent));
    snprintf(screenContent, sizeof(screenContent), APP_PREFIX);
    reedSolomonEncode(accountId, screenContent + strlen(screenContent));
    callback_function = callback;

    if(0 == G_ux.stack_count)
        ux_stack_push();

    ux_flow_init(0, saFlow, NULL);
}

#endif