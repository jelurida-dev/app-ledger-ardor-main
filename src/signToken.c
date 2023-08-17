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

#include "io.h"      // io_send*
#include "parser.h"  // command_t

#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "ui/menu.h"
#include "ui/display.h"
#include "io_helper.h"

#define P1_INIT 0
#define P1_MSG_BYTES 1
#define P1_SIGN 2

#define STATE_INVALID 0
#define STATE_MODE_INITED 1
#define STATE_BYTES_RECEIVED 2

/*
    modes:
        P1_INIT: this commands just clears all bytes in the state
            dataBuffer: empty
            returns:    1 byte status

        P1_MSG_BYTES:
            dataBuffer: message bytes
            returns:    1 byte status

        P1_SIGN:
            dataBuffer: timestamp (4 bytes) | derivation path (uint32) * some length |
            returns:    1 byte status | token 100 bytes

    100-byte token consists of a 32-byte public key, a 4-byte timestamp, and a 64-byte signature
*/

static void cleanTokenSignState() {
    memset(&state, 0, sizeof(state));
}

static int cleanAndReturn(uint8_t ret) {
    cleanTokenSignState();
    return io_send_return1(ret);
}

// UI callback defined in ui/display.h
void signTokenConfirm() {
    uint16_t exception = 0;
    uint8_t keySeed[32];
    memset(keySeed, 0, sizeof(keySeed));

    // gotta do some space reuse
    uint8_t publicKeyAndFinalHash[32];
    memset(publicKeyAndFinalHash, 0, sizeof(publicKeyAndFinalHash));
    uint8_t ret = ardorKeys(state.tokenSign.ptrDerivationPath,
                            state.tokenSign.derivationPathLengthInUints32,
                            keySeed,
                            publicKeyAndFinalHash,
                            0,
                            0,
                            &exception);

    if (R_SUCCESS != ret) {
        cleanTokenSignState();
        io_send_return3(ret, exception >> 8, exception & 0xFF);
        return;
    }

    state.tokenSign.token[0] = R_SUCCESS;
    size_t offset = 1;

    // adding the public key to the hash
    cx_hash_no_throw(&state.tokenSign.sha256.header,
                     0,
                     publicKeyAndFinalHash,
                     sizeof(publicKeyAndFinalHash),
                     0,
                     0);

    // also make a copy to the output buffer, because of how a token is constructed
    memcpy(state.tokenSign.token + offset, publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash));
    offset += sizeof(publicKeyAndFinalHash);

    // adding the timestamp to the hash
    cx_hash_no_throw(&state.tokenSign.sha256.header,
                     0,
                     (uint8_t*) &state.tokenSign.timestamp,
                     sizeof(state.tokenSign.timestamp),
                     0,
                     0);

    memcpy(state.tokenSign.token + offset,
           &state.tokenSign.timestamp,
           sizeof(state.tokenSign.timestamp));
    offset += sizeof(state.tokenSign.timestamp);

    cx_hash_no_throw(&state.tokenSign.sha256.header,
                     CX_LAST,
                     0,
                     0,
                     publicKeyAndFinalHash,
                     sizeof(publicKeyAndFinalHash));

    signMsg(keySeed, publicKeyAndFinalHash, state.tokenSign.token + offset);
    memset(keySeed, 0, sizeof(keySeed));

    io_send_response_pointer(state.tokenSign.token, sizeof(state.tokenSign.token), SW_OK);
    cleanTokenSignState();
}

// UI callback defined in ui/display.h
void signTokenCancel() {
    cleanTokenSignState();
    io_send_return2(R_SUCCESS, R_REJECT);
}

static int p1TokenInitHandler() {
    cleanTokenSignState();
    state.tokenSign.mode = STATE_MODE_INITED;
    cx_sha256_init(&state.tokenSign.sha256);
    return io_send_return1(R_SUCCESS);
}

static int p1TokenMsgBytesHandler(const command_t* const cmd, const bool isLastCommandDifferent) {
    if (isLastCommandDifferent || (STATE_INVALID == state.tokenSign.mode)) {
        return cleanAndReturn(R_WRONG_STATE);
    }

    state.tokenSign.mode = STATE_BYTES_RECEIVED;

    cx_hash_no_throw(&state.tokenSign.sha256.header, 0, cmd->data, cmd->lc, 0, 0);

    return io_send_return1(R_SUCCESS);
}

static int p1TokenSignHandler(const command_t* const cmd, const bool isLastCommandDifferent) {
    if (isLastCommandDifferent || (STATE_BYTES_RECEIVED != state.tokenSign.mode)) {
        return cleanAndReturn(R_WRONG_STATE);
    }

    if (cmd->lc < 4) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    }

    if (0 != (cmd->lc - 4) % sizeof(uint32_t)) {
        return cleanAndReturn(R_WRONG_SIZE_MODULO_ERR);
    }

    // underflow was checked against above above
    state.tokenSign.derivationPathLengthInUints32 = (cmd->lc - 4) / sizeof(uint32_t);

    if ((MIN_DERIVATION_LENGTH > state.tokenSign.derivationPathLengthInUints32) ||
        (MAX_DERIVATION_LENGTH < state.tokenSign.derivationPathLengthInUints32)) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    }

    memcpy(&state.tokenSign.timestamp, cmd->data, sizeof(state.tokenSign.timestamp));
    state.tokenSign.ptrDerivationPath = cmd->data + sizeof(state.tokenSign.timestamp);

    signTokenScreen();
    return 0;
}

// Since this is a callback function, and this handler manages state, it's this function's
// reposibility to clear the state Every time we get some sort of an error
int signTokenMessageHandler(const command_t* const cmd, const bool isLastCommandDifferent) {
    if (isLastCommandDifferent) cleanTokenSignState();

    if (P1_INIT == cmd->p1) {
        return p1TokenInitHandler();
    } else if (P1_MSG_BYTES == cmd->p1) {
        return p1TokenMsgBytesHandler(cmd, isLastCommandDifferent);
    } else if (P1_SIGN == cmd->p1) {
        return p1TokenSignHandler(cmd, isLastCommandDifferent);
    } else {
        return cleanAndReturn(R_UNKNOWN_CMD_PARAM_ERR);
    }
}
