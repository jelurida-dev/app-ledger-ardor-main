#ifdef HAVE_BAGL

#include "ux.h"
#include "menu.h"
#include "glyphs.h"

UX_STEP_NOCB(ux_idle_flow_1_step,
             bn,
             {
                 "Application",
                 "is ready",
             });
UX_STEP_NOCB(ux_idle_flow_2_step,
             bn,
             {
                 "Version",
                 APPVERSION,
             });
UX_STEP_CB(ux_idle_flow_3_step,
           pb,
           os_sched_exit(-1),
           {
               &C_icon_dashboard,
               "Quit",
           });
UX_FLOW(ux_idle_flow, &ux_idle_flow_1_step, &ux_idle_flow_2_step, &ux_idle_flow_3_step);

void ui_menu_main() {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
}

#endif