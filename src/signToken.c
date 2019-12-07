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

#include "aes/aes.h"

#include "ardor.h"
#include "returnValues.h"

#define P1_INIT         1
#define P1_MSG_BYTES    2
#define P1_SIGN         3

//todo, check out status mamangment on all commands

/*
    modes:
        P1_INIT: this commands just clears all bytes in the state
            dataBuffer: empty
            returns:    1 byte status

        P1_MSG_BYTES:
            dataBuffer: message bytes
            returns:    1 byte status

        P1_SIGN:
            dataBuffer: timestamp (4 bytes) | derivaiton path (uint32) * some length | 
            returns:    1 byte status | sharedkey 32 bytes
*/

void signTokenMessageHandlerHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint8_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {

    switch(p1) {

        case P1_INIT:
            state.tokenCreation.mode = P1_INIT;
            cx_sha256_init(&state.tokenCreation.hashstate);
            G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
            break;

        case P1_MSG_BYTES:
            if ((P1_INIT != state.tokenCreation.mode) && (P1_MSG_BYTES != state.tokenCreation.mode)) {
                G_io_apdu_buffer[(*tx)++] = R_WRONG_STATE;
                break;
            }

            cx_hash(&state.tokenCreation.hashstate.header, 0, dataBuffer, dataLength, 0, 0); //todo, calling this without a hash destination, lets see if it works

            G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
            break;

        case P1_SIGN:

            if (dataLength < 4) {
                G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
                break;
            }

            if (0 != dataLength - 4 % sizeof(uint32_t)) {
                G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
                break;
            }

            uint8_t derivationPathLengthInUints32 = (dataLength - 4) / sizeof(uint32_t);

            if (derivationPathLengthInUints32 < 2) {
                G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
                break;
            }

            if (derivationPathLengthInUints32 > 32) {
                G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
                break;
            }

            uint32_t derivationPath[32];
            os_memcpy(derivationPath, dataBuffer + 4, derivationPathLengthInUints32 * sizeof(uint32_t));

            uint16_t exception = 0;

            //gotta do some space reuse
            uint8_t publicKeyAndFinalHash[32]; os_memset(publicKeyAndFinalHash, 0, sizeof(publicKeyAndFinalHash));
            uint8_t ret = ardorKeys(derivationPath, derivationPathLengthInUints32, 0, publicKeyAndFinalHash, 0, 0, &exception); //derivationParamLengthInBytes should devied by 4, it's checked above

            if (R_SUCCESS != ret) {
                G_io_apdu_buffer[(*tx)++] = ret;

                if (R_KEY_DERIVATION_EX == ret) {
                    G_io_apdu_buffer[(*tx)++] = exception >> 8;
                    G_io_apdu_buffer[(*tx)++] = exception & 0xFF;
                }

                break;
            }

            cx_hash(&state.tokenCreation.hashstate.header, 0, publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash), 0, 0); //adding the public key to the hash
            cx_hash(&state.tokenCreation.hashstate.header, 0, dataBuffer, 4, 0, 0); //adding the timestamp to the hash
            cx_hash(&state.tokenCreation.hashstate.header, CX_LAST, 0, 0, publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash));

            uint8_t keySeed[64]; os_memset(keySeed, 0, sizeof(keySeed));

            if (R_SUCCESS != (ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, &exception))) {
                os_memset(keySeed, 0, sizeof(keySeed));
                G_io_apdu_buffer[(*tx)++] = ret;

                if (R_KEY_DERIVATION_EX == ret) {
                    G_io_apdu_buffer[(*tx)++] = exception >> 8;
                    G_io_apdu_buffer[(*tx)++] = exception & 0xFF;   
                }

                break;
            }

            G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

            //should only use the first 32 bytes of keyseed
            signMsg(keySeed, publicKeyAndFinalHash, G_io_apdu_buffer + 1); //is a void function, no ret value to check against
            os_memset(keySeed, 0, sizeof(keySeed));
            break;
       
       default:

            G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
            break;
    }
}


void signTokenMessageHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint8_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    signTokenMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
