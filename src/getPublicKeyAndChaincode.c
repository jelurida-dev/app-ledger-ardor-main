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

//todo add auth button for chaincode requests


void getPublicKeyAndChainCodeHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int * const flags, volatile unsigned int * const tx) {

    if ((P1_GET_PUBLIC_KEY != p1) && (P1_GET_PUBLIC_KEY_CHAIN_CODE_AND_ED_PUBLIC_KEY != p1)) {
        G_io_apdu_buffer[(*tx)++] = R_UNKNOWN_CMD_PARAM_ERR;
        return;
    }

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

    //62 is the biggest derivation path paramter that can be passed on
    //this is a potentional vonrablitiy, make sure this is the same in all of the code
    uint32_t derivationPathCpy[62]; os_memset(derivationPathCpy, 0, sizeof(derivationPathCpy)); 
    
    //datalength is checked in the main function so there should not be worry for some kind of overflow
    os_memmove(derivationPathCpy, dataBuffer, derivationParamLengthInBytes);
    
    
    uint8_t publicKeyEd25519[32];
    uint8_t publicKeyCurve[32];
    uint8_t chainCode[32];
    uint16_t exception = 0;

    uint8_t ret = ardorKeys(derivationPathCpy, derivationParamLengthInBytes / 4, 0, publicKeyCurve, publicKeyEd25519, chainCode, &exception); //derivationParamLengthInBytes should devied by 4, it's checked above

    G_io_apdu_buffer[(*tx)++] = ret;

    if (R_SUCCESS == ret) {
        
        os_memmove(G_io_apdu_buffer + *tx, publicKeyEd25519, sizeof(publicKeyEd25519));
        *tx += sizeof(publicKeyEd25519);

        if (P1_GET_PUBLIC_KEY_CHAIN_CODE_AND_ED_PUBLIC_KEY == p1) {
            os_memmove(G_io_apdu_buffer + *tx, chainCode, sizeof(chainCode));
            *tx += sizeof(chainCode);    

            os_memmove(G_io_apdu_buffer + *tx, publicKeyCurve, sizeof(publicKeyCurve));
            *tx += sizeof(publicKeyCurve);
        }

    } else if (R_KEY_DERIVATION_EX == ret) {  
        G_io_apdu_buffer[(*tx)++] = exception >> 8;
        G_io_apdu_buffer[(*tx)++] = exception & 0xFF;
    } else {
        G_io_apdu_buffer[(*tx)++] = ret;
    }
}

void getPublicKeyAndChainCodeHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int * const flags, volatile unsigned int * const tx, const bool isLastCommandDifferent) {

    getPublicKeyAndChainCodeHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
