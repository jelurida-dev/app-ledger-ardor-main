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

#define P1_INIT_ENCRYPT                     1
#define P1_INIT_DECRYPT_HIDE_SHARED_KEY     2
#define P1_INIT_DECRYPT_SHOW_SHARED_KEY     3
#define P1_AES_ENCRYPT_DECRYPT              4

/*

    This command allows the client to encrypt and decrypt messages that are assigned to some foreign public key and nonce
    First you need to call the right INIT function, you have 3 choices. After that you call P1_AES_ENCRYPT_DECRYPT as many times as you need

    API:

        P1: P1_INIT_ENCRYPT:
        dataBuffer: derivation path (uint32) * some length | second party public key
        returns:    1 byte status | nonce (on success) | IV

        P1: P1_INIT_DECRYPT_HIDE_SHARED_KEY:
        dataBuffer: derivaiton path (uint32) * some length | second party public key | nonce | IV
        returns:    1 byte status

        P1: P1_INIT_DECRYPT_SHOW_SHARED_KEY:
        dataBuffer: derivaiton path (uint32) * some length | second party public key | nonce | IV
        returns:    1 byte status | sharedkey 32 bytes

        P1_AES_ENCRYPT_DECRYPT:
        dataBuffer: buffer (224 max size) should be in modulu of 16 
        returns:    encrypted / decrypted buffer (same size as input)
*/

void cleanEncryptionState() {
    state.encryption.mode = 0;
}

void encryptDecryptMessageHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int * const flags, volatile unsigned int * const tx, const bool isLastCommandDifferent) {

    if (isLastCommandDifferent)
        cleanEncryptionState();

    if ((P1_INIT_ENCRYPT == p1) || (P1_INIT_DECRYPT_HIDE_SHARED_KEY == p1) || (P1_INIT_DECRYPT_SHOW_SHARED_KEY == p1)) {

        if (0 != dataLength % sizeof(uint32_t)) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
            return;
        }

        uint8_t derivationLength = 0;

        if (P1_INIT_ENCRYPT == p1)
            derivationLength = (dataLength - 32) / sizeof(uint32_t);
        else
            derivationLength = (dataLength - 32 * 2 - 16) / sizeof(uint32_t);

        if (2 > derivationLength) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
            return;
        }

        if (32 < derivationLength) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
            return;
        }

        uint32_t derivationPath[32]; //todo check if i can just point to the derivation path
        uint8_t nonce[32];
        os_memcpy(derivationPath, dataBuffer, derivationLength * sizeof(uint32_t));

        uint8_t * noncePtr = dataBuffer + derivationLength * sizeof(uint32_t) + 32;

        if (P1_INIT_ENCRYPT == p1) {
            cx_rng(nonce, sizeof(nonce));
            noncePtr = nonce; //if we are decrypting then we are using from the command
        }

        uint8_t exceptionOut = 0;
        uint8_t encryptionKey[32];

        uint8_t ret = getSharedEncryptionKey(derivationPath, derivationLength, dataBuffer + derivationLength * sizeof(uint32_t), noncePtr, &exceptionOut, encryptionKey);

        if (R_KEY_DERIVATION_EX == ret) {
            cleanEncryptionState();
            G_io_apdu_buffer[0] = ret;  
            G_io_apdu_buffer[1] = exceptionOut >> 8;
            G_io_apdu_buffer[2] = exceptionOut & 0xFF;
            *tx = 3;
            return;
        } else if (R_SUCCESS != ret) {
            cleanEncryptionState();
            G_io_apdu_buffer[0] = ret;
            *tx = 1;
            return;
        }

        if (P1_INIT_ENCRYPT == p1) {
            if (!aes_encrypt_init_fixed(encryptionKey, 32, state.encryption.ctx)) {
                cleanEncryptionState();
                G_io_apdu_buffer[0] = R_AES_ERROR;
                *tx = 1;
                return;
            }
        } else {
            if (!aes_decrypt_init_fixed(encryptionKey, 32, state.encryption.ctx)) {
                cleanEncryptionState();
                G_io_apdu_buffer[0] = R_AES_ERROR;
                *tx = 1;
                return;
            }

            os_memcpy(state.encryption.cbc, dataBuffer + dataLength - sizeof(state.encryption.cbc), sizeof(state.encryption.cbc)); //Copying the IV into the CBC
        }
        
        state.encryption.mode = p1;
        G_io_apdu_buffer[(*tx)++] = R_SUCCESS;

        if (P1_INIT_ENCRYPT == p1) {
            os_memcpy(G_io_apdu_buffer + *tx, nonce, sizeof(nonce));
            *tx+= 32;
            cx_rng(state.encryption.cbc, sizeof(state.encryption.cbc)); //The IV is stored in the CVC
            os_memcpy(G_io_apdu_buffer + *tx, state.encryption.cbc, sizeof(state.encryption.cbc));
            *tx+= sizeof(state.encryption.cbc);
        } else if (P1_INIT_DECRYPT_SHOW_SHARED_KEY == p1) {
            os_memcpy(G_io_apdu_buffer + *tx, encryptionKey, sizeof(encryptionKey));
            *tx+= 32;
        }

    } else if (P1_AES_ENCRYPT_DECRYPT == p1) {

        if (isLastCommandDifferent) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_NO_SETUP;
            return;
        }

        if ((P1_INIT_ENCRYPT != state.encryption.mode) && (P1_INIT_DECRYPT_HIDE_SHARED_KEY != state.encryption.mode) && 
            (P1_INIT_DECRYPT_SHOW_SHARED_KEY != state.encryption.mode))
        {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_NO_SETUP;
            return;
        }

        if (0 != dataLength % 16) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
            return;
        }

        uint8_t * pos = dataBuffer;
        uint8_t tmp[AES_BLOCK_SIZE];

        while (pos < dataBuffer + dataLength) {
            if (P1_INIT_ENCRYPT == state.encryption.mode) { //if we are doing encryption:

                for (uint8_t j = 0; j < AES_BLOCK_SIZE; j++)
                    state.encryption.cbc[j] ^= pos[j];

                aes_encrypt(state.encryption.ctx, state.encryption.cbc, state.encryption.cbc);
                os_memcpy(pos, state.encryption.cbc, AES_BLOCK_SIZE);
            } else {
                os_memcpy(tmp, pos, AES_BLOCK_SIZE);
                aes_decrypt(state.encryption.ctx, pos, pos);
                for (uint8_t j = 0; j < AES_BLOCK_SIZE; j++)
                    pos[j] ^= state.encryption.cbc[j];

                os_memcpy(state.encryption.cbc, tmp, AES_BLOCK_SIZE);
            }

            pos += AES_BLOCK_SIZE;
        }

        *tx = 1 + dataLength;

        for (uint8_t i = 0; i < dataLength; i++)
                G_io_apdu_buffer[i+1] = dataBuffer[i];

        G_io_apdu_buffer[0] = R_SUCCESS;

    } else {
        cleanEncryptionState();
        G_io_apdu_buffer[(*tx)++] = R_UNKOWN_CMD;
    }
}

void encryptDecryptMessageHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int * const flags, volatile unsigned int * const tx, const bool isLastCommandDifferent) {

    encryptDecryptMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx, isLastCommandDifferent);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
