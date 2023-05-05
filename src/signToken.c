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

#define P1_INIT         0
#define P1_MSG_BYTES    1
#define P1_SIGN         2

#define STATE_INVAILD           0
#define STATE_MODE_INITED       1
#define STATE_BYTES_RECIEVED    2

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
            returns:    1 byte status | token 100 bytes

    100-byte token consists of a 32-byte public key, a 4-byte timestamp, and a 64-byte signature
*/

//does what it says :)
void cleanTokenCreationState() {
    state.tokenCreation.mode = STATE_INVAILD;
}

// UI callbacks
void txn_authorized() {
    uint8_t *dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint8_t dataLength = G_io_apdu_buffer[OFFSET_LC];
    uint8_t derivationPathLengthInUints32 = (dataLength - 4) / sizeof(uint32_t);
    uint8_t tx = 0;
    uint16_t exception = 0;
    uint32_t timestamp = 0;
    uint8_t keySeed[32]; memset(keySeed, 0, sizeof(keySeed));

    //gotta do some space reuse
    uint8_t publicKeyAndFinalHash[32]; memset(publicKeyAndFinalHash, 0, sizeof(publicKeyAndFinalHash));
    uint8_t ret = ardorKeys(dataBuffer + sizeof(timestamp), derivationPathLengthInUints32, keySeed, publicKeyAndFinalHash, 0, 0, &exception);

    if (R_SUCCESS != ret) {
        cleanTokenCreationState();

        G_io_apdu_buffer[tx++] = ret;

        if (R_KEY_DERIVATION_EX == ret) {
            G_io_apdu_buffer[tx++] = exception >> 8;
            G_io_apdu_buffer[tx++] = exception & 0xFF;
        }
    } else {
        memcpy(&timestamp, dataBuffer, sizeof(timestamp));

        G_io_apdu_buffer[tx++] = R_SUCCESS;

        cx_hash(&state.tokenCreation.sha256.header, 0, publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash), 0, 0); //adding the public key to the hash
        
        //also make a copy to the output buffer, because of how a token is constructed
        memcpy(G_io_apdu_buffer + tx, publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash));
        tx += sizeof(publicKeyAndFinalHash);

        cx_hash(&state.tokenCreation.sha256.header, 0, (uint8_t*)&timestamp, sizeof(timestamp), 0, 0); //adding the timestamp to the hash

        memcpy(G_io_apdu_buffer + tx, &timestamp, sizeof(timestamp));
        tx += sizeof(timestamp);

        cx_hash(&state.tokenCreation.sha256.header, CX_LAST, 0, 0, publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash));

        signMsg(keySeed, publicKeyAndFinalHash, G_io_apdu_buffer + tx); //is a void function, no ret value to check against
        memset(keySeed, 0, sizeof(keySeed));

        tx += 64;

        G_io_apdu_buffer[tx++] = 0x90;
        G_io_apdu_buffer[tx++] = 0x00;
    }

    cleanTokenCreationState();

    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    
    ui_menu_main();
}

void txn_cancelled() {
    cleanTokenCreationState();

    G_io_apdu_buffer[0] = R_SUCCESS;
    G_io_apdu_buffer[1] = R_REJECT;
    G_io_apdu_buffer[2] = 0x90;
    G_io_apdu_buffer[3] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 4);
    
    ui_menu_main();
}

void p1TokenInitHandler(uint8_t * const tx) {
    cleanTokenCreationState();
    state.tokenCreation.mode = STATE_MODE_INITED;
    cx_sha256_init(&state.tokenCreation.sha256);
    G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
}

void p1TokenMsgBytesHandler(const uint8_t * const dataBuffer, const uint8_t dataLength, uint8_t * const tx, const bool isLastCommandDifferent) {
    if (isLastCommandDifferent || (STATE_INVAILD == state.tokenCreation.mode)) {
        cleanTokenCreationState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_STATE;
        return;
    }

    state.tokenCreation.mode = STATE_BYTES_RECIEVED;

    cx_hash(&state.tokenCreation.sha256.header, 0, dataBuffer, dataLength, 0, 0);

    G_io_apdu_buffer[(*tx)++] = R_SUCCESS;
}

void p1TokenSignHandler(const uint8_t dataLength, uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {
    if (isLastCommandDifferent || (STATE_BYTES_RECIEVED != state.tokenCreation.mode)) {
        cleanTokenCreationState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_STATE;
        return;
    }

    if (dataLength < 4) {
        cleanTokenCreationState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return;
    }

    if (0 != (dataLength - 4) % sizeof(uint32_t)) {
        cleanTokenCreationState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
        return;
    }

    //underflow was checked against above above
    uint8_t derivationPathLengthInUints32 = (dataLength - 4) / sizeof(uint32_t);

    if ((MIN_DERIVATION_LENGTH > derivationPathLengthInUints32) || (MAX_DERIVATION_LENGTH < derivationPathLengthInUints32)) {
        cleanTokenCreationState();
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return;
    }

    showSignTokenScreen(&txn_authorized, &txn_cancelled);
    *flags |= IO_ASYNCH_REPLY;
}

//Since this is a callback function, and this handler manages state, it's this function's reposibility to clear the state
//Every time we get some sort of an error
void signTokenMessageHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
        uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    UNUSED(p2);
    UNUSED(flags);

    if (isLastCommandDifferent)
        cleanTokenCreationState(); 

    if (P1_INIT == p1) {
        p1TokenInitHandler(tx);
    } else if (P1_MSG_BYTES == p1) {
        p1TokenMsgBytesHandler(dataBuffer, dataLength, tx, isLastCommandDifferent);
    } else if (P1_SIGN == p1) {
        p1TokenSignHandler(dataLength, flags, tx, isLastCommandDifferent);
    } else {
        cleanTokenCreationState();
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
    }
}


void signTokenMessageHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
               uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent) {

    signTokenMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx, isLastCommandDifferent);
    
    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
