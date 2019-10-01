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

#include "ardor.h"
#include "returnValues.h"

uint8_t screenContent[27];

static const bagl_element_t ui_screen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,117,13,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_CHECK},NULL,0,0,0,NULL,NULL,NULL},
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

void reedSolomonEncode(uint64_t inp, uint8_t * output);
unsigned int makeTextGoAround_preprocessor(const bagl_element_t *element);


void showAddressHandlerHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {

    //should be at least the size of 2 uint32's for the key path
    //the +2 * sizeof(uint32_t) is done for saftey, it is second checked in deriveArdorKeypair
    if (dataLength <  2 * sizeof(uint32_t)) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return;
    }

    uint8_t derivationParamLengthInBytes = dataLength;

    //todo check if the 3 is actually the shortest param
    if (0 != derivationParamLengthInBytes % 4) {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
        return;
    }

    //55 is the biggest derivation path paramter that can be passed on
    uint32_t derivationPathCpy[55]; os_memset(derivationPathCpy, 0, sizeof(derivationPathCpy)); 
    
    //datalength is checked in the main function so there should not be worry for some kind of overflow
    os_memmove(derivationPathCpy, dataBuffer, derivationParamLengthInBytes);
    
    G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

    uint16_t exception = 0;

    uint8_t publicKey[32]; os_memset(publicKey, 0, sizeof(publicKey));
    uint8_t ret = ardorKeys(derivationPathCpy, derivationParamLengthInBytes / 4, 0, publicKey, 0, &exception); //derivationParamLengthInBytes should devied by 4, it's checked above

    if (R_SUCCESS == ret) {
        os_memset(screenContent, 0, sizeof(screenContent));
        snprintf(screenContent, sizeof(screenContent), "ARDOR-");
        reedSolomonEncode(publicKey, screenContent + strlen(screenContent));
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

void showAddressHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    showAddressHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
