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

#include "parser.h" // command_t
#include "io.h" // io_send*

#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "io_helper.h"

#define P1_GET_PUBLIC_KEY                                   1
#define P1_GET_PUBLIC_KEY_CHAIN_CODE_AND_ED_PUBLIC_KEY      2


/*
    This command allows the client to the EC-KCDSA public key, chain code and ED25519 public key for a requested derivation path

    API:

        P1: P1_GET_PUBLIC_KEY:
        dataBuffer: derivation path (uint32) * some length
        returns:    32 byte EC-KCDSA public key

        P1: P1_GET_PUBLIC_KEY_CHAIN_CODE_AND_ED_PUBLIC_KEY:
        dataBuffer: derivaiton path (uint32) * some length
        returns:    32 byte EC-KCDSA public key | 32 byte chain code | 32 byte ED25516 public key

*/



int getPublicKeyAndChainCodeHandler(const command_t * const cmd, const bool isLastCommandDifferent) {

    UNUSED(isLastCommandDifferent); //there is no state to manage, so there's nothing to do with this parameter

    if ((P1_GET_PUBLIC_KEY != cmd->p1) && (P1_GET_PUBLIC_KEY_CHAIN_CODE_AND_ED_PUBLIC_KEY != cmd->p1)) {
        return io_send_return1(R_UNKNOWN_CMD_PARAM_ERR);
    }

    if ((MIN_DERIVATION_LENGTH * sizeof(uint32_t) > cmd->lc) || (MAX_DERIVATION_LENGTH * sizeof(uint32_t) < cmd->lc)) {
        return io_send_return1(R_WRONG_SIZE_ERR);
    }

    uint8_t derivationParamLengthInBytes = cmd->lc;

    if (0 != derivationParamLengthInBytes % sizeof(uint32_t)) {
        return io_send_return1(R_UNKNOWN_CMD_PARAM_ERR);
    }
    
    // Instead of having 3 buffers for the public keys and chain code we use one buffer that
    // we will directly send as an APDU, instead of having to copy the data to the APDU buffer.
    // Buffer offsets:
    // 0: R_SUCCESS
    // 1: publicKeyCurve
    // 33: publicKeyEd25519YLE
    // 65: chainCode
    uint8_t buffer[97]; // 1 R_SUCCESS + 32 publicKeyCurve + 32 publicKeyEd25519YLE + 32 chainCode
    uint16_t exception = 0;

    uint8_t ret = ardorKeys(cmd->data, derivationParamLengthInBytes / sizeof(uint32_t), 0, 
                            buffer + 1, buffer + 33, buffer + 65, &exception);

    if (ret != R_SUCCESS) {
        return io_send_return3(ret, exception >> 8, exception & 0xFF);
    }
    buffer[0] = R_SUCCESS;
    size_t responseSize = P1_GET_PUBLIC_KEY_CHAIN_CODE_AND_ED_PUBLIC_KEY == cmd->p1 ? 97 : 33;
    return io_send_response_pointer(buffer, responseSize, SW_OK);
}
