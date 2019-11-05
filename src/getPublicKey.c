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

// This is the max amount of key that can be sent back to the client
#define MAX_KEYS 7

void getPublicKeyHandlerHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint8_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {

    //should be at least the size of 2 uint32's for the key path
    //the +2 * sizeof(uint32_t) is done for saftey, it is second checked in deriveArdorKeypair
    if (dataLength <  2 * sizeof(uint32_t)) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return; 
    }

    if (MAX_KEYS < p1) {
        G_io_apdu_buffer[(*tx)++] = R_BAD_NUM_KEYS;
        return;
    }

    uint8_t derivationParamLengthInBytes = dataLength;

    //todo check if the 3 is actually the shortest param
    if (0 != derivationParamLengthInBytes % 4) {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
        return;
    }

    //62 is the biggest derivation path paramter that can be passed on
    //this is a potentional vonrablitiy, make sure this is the same in all of the code
    uint32_t derivationPathCpy[62]; os_memset(derivationPathCpy, 0, sizeof(derivationPathCpy)); 
    
    //datalength is checked in the main function so there should not be worry for some kind of overflow
    os_memmove(derivationPathCpy, dataBuffer, derivationParamLengthInBytes);
    
    G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

    for (uint8_t i = 0; i < p1; i++) {
        uint16_t exception = 0;

        uint8_t publicKey[32]; os_memset(publicKey, 0, sizeof(publicKey));
        uint8_t ret = ardorKeys(derivationPathCpy, derivationParamLengthInBytes / 4, 0, publicKey, 0, &exception); //derivationParamLengthInBytes should devied by 4, it's checked above

        if (R_SUCCESS == ret) {
            os_memmove(G_io_apdu_buffer + *tx, publicKey, sizeof(publicKey));
            *tx += sizeof(publicKey);
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

        derivationPathCpy[(derivationParamLengthInBytes/4) - 1] += 1; //move the path index
    }
}

void getPublicKeyHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint8_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    getPublicKeyHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
