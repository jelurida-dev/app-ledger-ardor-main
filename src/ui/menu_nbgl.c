#ifdef HAVE_NBGL

#include "menu.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "os.h"
#include "ardor.h"
#include "settings.h"

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

///////////////////////////////////////////////////////////////////////////
// Settings menu:

static const char *const INFO_TYPES[] = {"Version", "Developer"};
static const char *const INFO_CONTENTS[] = {APPVERSION, "Jelurida"};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = ARRAY_COUNT(INFO_TYPES),
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

enum {
    BLIND_SIGNING_IDX = 0,
    NB_SETTINGS,
};
static nbgl_contentSwitch_t G_switches[NB_SETTINGS];

enum {
    BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN,
};

static void settings_controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    if (token == BLIND_SIGNING_TOKEN) {
        // Write in NVM the opposite of what the current toggle is
        settings_set_allow_blind_signing(G_switches[BLIND_SIGNING_IDX].initState != ON_STATE);
        G_switches[BLIND_SIGNING_IDX].initState =
            N_storage.settings.allowBlindSigning ? ON_STATE : OFF_STATE;
    }
}

static const nbgl_content_t contentsList = {
    .type = SWITCHES_LIST,
    .content.switchesList.nbSwitches = NB_SETTINGS,
    .content.switchesList.switches = G_switches,
    .contentActionCallback = settings_controls_callback,
};

static const nbgl_genericContents_t settingContents = {
    .callbackCallNeeded = false,
    .contentsList = &contentsList,
    .nbContents = 1,
};

void ui_menu_main(void) {
    G_switches[BLIND_SIGNING_IDX].text = "Blind signing";
    G_switches[BLIND_SIGNING_IDX].subText = "Enable blind signing";
    G_switches[BLIND_SIGNING_IDX].token = BLIND_SIGNING_TOKEN;
    G_switches[BLIND_SIGNING_IDX].tuneId = TUNE_TAP_CASUAL;
    G_switches[BLIND_SIGNING_IDX].initState =
        N_storage.settings.allowBlindSigning ? ON_STATE : OFF_STATE;

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &C_ArdorIcon64px,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_quit);
}

#endif
