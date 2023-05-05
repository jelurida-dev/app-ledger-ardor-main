/*******************************************************************************
*  (c) 2019 Haim Bender
*  (c) 2021-2023 Jelurida IP B.V.
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
#include <string.h>

#include <os.h>
#include <os_io_seproxyhal.h>

#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "ui/menu.h"
#include "ui/display.h"

void doneButton(void) {
    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = 0x90;
    G_io_apdu_buffer[2] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 3);
    
    ui_menu_main();
}

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

    uint8_t publicKey[32]; memset(publicKey, 0, sizeof(publicKey));

    uint8_t ret = ardorKeys(dataBuffer, derivationParamLengthInBytes / sizeof(uint32_t), 0, publicKey, 0, 0, &exception); //derivationParamLengthInBytes should devied by 4, it's checked above

    if (R_SUCCESS == ret) {
        showAddressScreen(publicKeyToId(publicKey), &doneButton);
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
