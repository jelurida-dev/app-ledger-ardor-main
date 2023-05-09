#ifdef HAVE_NBGL

#include "display.h"
#include "nbgl_use_case.h"
#include "glyphs.h"
#include "menu.h"

static void signTokenConfirmation() {
    signTokenConfirm();
    nbgl_useCaseStatus("TOKEN SIGNATURE\nSUCCESSFUL", true, ui_menu_main);
}

static void signTokenCancellation() {
    signTokenCancel();
    nbgl_useCaseStatus("Token signature\ncancelled", false, ui_menu_main);
}

static void reviewChoice(bool confirm) {
    if (confirm) {
        signTokenConfirmation();
    } else {
        signTokenCancellation();
    }
}

void signTokenScreen() {
    nbgl_layoutTagValueList_t pairList = {
        .nbMaxLinesForValue = 0,
        .nbPairs = 0,
        .pairs = NULL
    };

    nbgl_pageInfoLongPress_t infoLongPress = {
        .icon = &C_ArdorIcon64px,
        .text = "Confirm\nSign token",
        .longPressText = "Hold to sign"
    };
    
    nbgl_useCaseStaticReview(&pairList, &infoLongPress, "Cancel", reviewChoice);
}

#endif