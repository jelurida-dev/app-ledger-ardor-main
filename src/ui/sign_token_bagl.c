#ifdef HAVE_BAGL

#include "ux.h"
#include "display.h"

UX_STEP_CB(stFlowPage1,
           pb,
           signTokenConfirm(),
           {
               &C_icon_validate_14,
               "Sign token",
           });

UX_STEP_CB(stFlowPage2,
           pb,
           signTokenCancel(),
           {
               &C_icon_crossmark,
               "Reject",
           });
UX_FLOW(stFlow, &stFlowPage1, &stFlowPage2);

void signTokenScreen() {
    if(0 == G_ux.stack_count)
        ux_stack_push();

    ux_flow_init(0, stFlow, NULL);
}

#endif