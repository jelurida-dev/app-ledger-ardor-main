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


//done button callback
unsigned int doneButton(const bagl_element_t *e) {
    
    UNUSED(e);

    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = 0x90;
    G_io_apdu_buffer[2] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 3);
    
    ui_idle();  // redraw ui
    return 0; // DO NOT REDRAW THE BUTTON
}

//Defenition of the UI for this handler
char screenContent[27];
UX_STEP_VALID(saFlowPage1, 
    bnnn_paging,
    doneButton(NULL),
    {
      .title = "Your Address",
      .text = screenContent,
    });
UX_STEP_VALID(saFlowPage2, 
    pb, 
    doneButton(NULL),
    {
      &C_icon_validate_14,
      "Done"
    });
UX_FLOW(saFlow,
  &saFlowPage1,
  &saFlowPage2
);

void showScreen() {
    if(0 == G_ux.stack_count)
        ux_stack_push();

    ux_flow_init(0, saFlow, NULL);
}

//defined in reedSolomon.c
void reedSolomonEncode(const uint64_t inp, char * const output);

void showAddressHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx) {

    UNUSED(p1); UNUSED(p2); UNUSED(flags);

    if ((MIN_DERIVATION_LENGTH * sizeof(uint32_t) > dataLength) || (MAX_DERIVATION_LENGTH * sizeof(uint32_t) < dataLength)) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return;
    }

    uint8_t derivationParamLengthInBytes = dataLength;

    if (0 != derivationParamLengthInBytes % sizeof(uint32_t)) {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
        return;
    }
    
    G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

    uint16_t exception = 0;

    uint8_t publicKey[32]; os_memset(publicKey, 0, sizeof(publicKey));

    uint8_t ret = ardorKeys(dataBuffer, derivationParamLengthInBytes / sizeof(uint32_t), 0, publicKey, 0, 0, &exception); //derivationParamLengthInBytes should devied by 4, it's checked above

    if (R_SUCCESS == ret) {
        os_memset(screenContent, 0, sizeof(screenContent));
        snprintf(screenContent, sizeof(screenContent), APP_PREFIX);
        reedSolomonEncode(publicKeyToId(publicKey), screenContent + strlen(screenContent));
        showScreen();
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
       uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    UNUSED(isLastCommandDifferent);

    showAddressHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
