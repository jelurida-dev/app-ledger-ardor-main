#ifdef HAVE_BAGL

#include "ux.h"
#include "display.h"
#include "menu.h"

static void signTokenConfirmation() {
    signTokenConfirm();
    ui_menu_main();
}

static void signTokenCancellation() {
    signTokenCancel();
    ui_menu_main();
}

UX_STEP_CB(stFlowPage1,
           pb,
           signTokenConfirmation(),
           {
               &C_icon_validate_14,
               "Sign token",
           });

UX_STEP_CB(stFlowPage2,
           pb,
           signTokenCancellation(),
           {
               &C_icon_crossmark,
               "Reject",
           });
UX_FLOW(stFlow, &stFlowPage1, &stFlowPage2);

void signTokenScreen() {
    if (0 == G_ux.stack_count) {
        ux_stack_push();
    }

    ux_flow_init(0, stFlow, NULL);
}

#endif