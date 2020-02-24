/*******************************************************************************
*  (c) 2019 Haim Bender
*
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/


#include <stdint.h>
#include <stdbool.h>

#include <os.h>
#include <os_io_seproxyhal.h>
#include "ux.h"

#include "returnValues.h"
#include "config.h"
#include "ardor.h"

uint8_t screenContent[27];

static const bagl_element_t ui_screen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,117,11,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_CHECK},NULL,0,0,0,NULL,NULL,NULL},
        UI_TEXT(0x00, 0, 12, 128, "Your Address"),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)screenContent,0,0,0,NULL,NULL,NULL}
};

static unsigned int ui_screen_button(unsigned int button_mask, unsigned int button_mask_counter) {

    if (!(BUTTON_EVT_RELEASED & button_mask))
        return 0;

    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = 0x90;
    G_io_apdu_buffer[2] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 3);
    ui_idle();
    return 0;
}

void reedSolomonEncode(const uint64_t inp, uint8_t * const output);

void showAddressHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        unsigned int * const flags, unsigned int * const tx) {

    if ((MIN_DERIVATION_LENGTH * sizeof(uint32_t) > dataLength) || (MAX_DERIVATION_LENGTH * sizeof(uint32_t) < dataLength)) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return;
    }

    uint8_t derivationParamLengthInBytes = dataLength;

    if (0 != derivationParamLengthInBytes % sizeof(uint32_t)) {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
        return;
    }

    uint32_t derivationPathCpy[MAX_DERIVATION_LENGTH]; os_memset(derivationPathCpy, 0, sizeof(derivationPathCpy));  //for some reason you can't point to the derivation path on the buffer when deriving keys
    
    //datalength is checked in the main function so there should not be worry for some kind of overflow
    os_memmove(derivationPathCpy, dataBuffer, derivationParamLengthInBytes);
    
    G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

    uint16_t exception = 0;

    uint8_t publicKey[32]; os_memset(publicKey, 0, sizeof(publicKey));
    uint8_t ret = ardorKeys(derivationPathCpy, derivationParamLengthInBytes / 4, 0, publicKey, 0, 0, &exception); //derivationParamLengthInBytes should devied by 4, it's checked above

    if (R_SUCCESS == ret) {
        os_memset(screenContent, 0, sizeof(screenContent));
        snprintf(screenContent, sizeof(screenContent), APP_PREFIX);
        reedSolomonEncode(publicKeyToId(publicKey), screenContent + strlen(screenContent));
        UX_DISPLAY(ui_screen, (bagl_element_callback_t)makeTextGoAround_preprocessor);
        *flags |= IO_ASYNCH_REPLY;
    } else if (R_KEY_DERIVATION_EX == ret) {
        G_io_apdu_buffer[0] = ret;
        G_io_apdu_buffer[1] = exception >> 8;
        G_io_apdu_buffer[2] = exception & 0xFF;
        *tx = 3;
        return;
    } else {
        G_io_apdu_buffer[0] = ret;
        *tx = 1;
        return;
    }
}

void showAddressHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        unsigned int * const flags, unsigned int * const tx, const bool isLastCommandDifferent) {

    showAddressHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
