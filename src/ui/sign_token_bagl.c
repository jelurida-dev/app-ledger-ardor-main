#ifdef HAVE_BAGL

#include "ux.h"
#include "display.h"

ui_callback sign_tk_callback_accept, sign_tk_callback_reject;

UX_STEP_CB(stFlowPage1,
           pb,
           sign_tk_callback_accept(),
           {
               &C_icon_validate_14,
               "Sign token",
           });

UX_STEP_CB(stFlowPage2,
           pb,
           sign_tk_callback_reject(),
           {
               &C_icon_crossmark,
               "Reject",
           });
UX_FLOW(stFlow, &stFlowPage1, &stFlowPage2);

void showSignTokenScreen(ui_callback cb_accept, ui_callback cb_reject) {
    sign_tk_callback_accept = cb_accept;
    sign_tk_callback_reject = cb_reject;
    if(0 == G_ux.stack_count)
        ux_stack_push();

    ux_flow_init(0, stFlow, NULL);
}

#endif