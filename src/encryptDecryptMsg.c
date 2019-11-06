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

    modes:
        P1_INIT_ENCRYPT:
            dataBuffer: derivation path (uint32) * some length | second party public key
            returns:    1 byte status | nonce (on success) | IV

        P1_INIT_DECRYPT_HIDE_SHARED_KEY:
            dataBuffer: derivaiton path (uint32) * some length | second party public key | nonce | IV
            returns:    1 byte status

        P1_INIT_DECRYPT_SHOW_SHARED_KEY:
            dataBuffer: derivaiton path (uint32) * some length | second party public key | nonce | IV
            returns:    1 byte status | sharedkey 32 bytes

        P1_AES_ENCRYPT_DECRYPT:
            dataBuffer: IV (if we are in decryption mode and this is the first message) | buffer (224 max size) should be in modulu of 16 
            returns:    IV (16 bytes) iif this is the first message for encryption mode | encrypted / decrypted buffer (same size as input)
*/

void encryptDecryptMessageHandlerHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint8_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {


    PRINTF("\n e0 %d", sizeof(unsigned long));


    //todo: find a way to make sure that you can't encrypt if the state isn't set
    if ((P1_INIT_ENCRYPT == p1) || (P1_INIT_DECRYPT_HIDE_SHARED_KEY == p1) || (P1_INIT_DECRYPT_SHOW_SHARED_KEY == p1)) {

        state.encryption.mode = 0; //clean the state first

        if (0 != dataLength % sizeof(uint32_t)) {
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
            return;
        }

        PRINTF("\n e1 %d", check_canary());

        uint8_t derivationLength = 0;

        if (P1_INIT_ENCRYPT == p1)
            derivationLength = (dataLength - 32) / sizeof(uint32_t);
        else
            derivationLength = (dataLength - 32 * 2 - 16) / sizeof(uint32_t);

        PRINTF("\n e2 derivation length %d %d", derivationLength, dataLength);

        if (2 > derivationLength) {
            G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
            return;
        }

        if (32 < derivationLength) {
            G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
            return;
        }

        PRINTF("\n e3");

        uint32_t derivationPath[32]; //todo check if i can just point to the derivation path
        uint8_t nonce[32];
        os_memcpy(derivationPath, dataBuffer, derivationLength * sizeof(uint32_t));

        PRINTF("\n e4 %d", check_canary());

        uint8_t * noncePtr = dataBuffer + derivationLength * sizeof(uint32_t) + 32;

        if (P1_INIT_ENCRYPT == p1) {
            cx_rng(nonce, sizeof(nonce));
            noncePtr = nonce; //if we are decrypting then we are using from the command
        }

        uint8_t exceptionOut = 0;
        uint8_t encryptionKey[32];

        uint8_t ret = getSharedEncryptionKey(derivationPath, derivationLength, dataBuffer + derivationLength * sizeof(uint32_t), noncePtr, &exceptionOut, encryptionKey);

        PRINTF("\n e5 %d", check_canary());

        if (R_KEY_DERIVATION_EX == ret) {
            G_io_apdu_buffer[0] = ret;  
            G_io_apdu_buffer[1] = exceptionOut >> 8;
            G_io_apdu_buffer[2] = exceptionOut & 0xFF;
            *tx = 3;
            return;
        } else if (R_SUCCESS != ret) {
            G_io_apdu_buffer[0] = ret;
            *tx = 1;
            return;
        }

        if (P1_INIT_ENCRYPT == p1) {
            if (!aes_encrypt_init_fixed(encryptionKey, 32, state.encryption.ctx)) {
                G_io_apdu_buffer[0] = R_AES_ERROR;
                *tx = 1;
                return;
            }
        } else {
            if (!aes_decrypt_init_fixed(encryptionKey, 32, state.encryption.ctx)) {
                G_io_apdu_buffer[0] = R_AES_ERROR;
                *tx = 1;
                return;
            }

            os_memcpy(state.encryption.cbc, dataBuffer + dataLength - sizeof(state.encryption.cbc), sizeof(state.encryption.cbc)); //Copying the IV into the CBC
        }

        PRINTF("\n e6");
        
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

        PRINTF("\n e7");
    } else if (P1_AES_ENCRYPT_DECRYPT == p1) {

        if ((P1_INIT_ENCRYPT != state.encryption.mode) && (P1_INIT_DECRYPT_HIDE_SHARED_KEY != state.encryption.mode) && 
            (P1_INIT_DECRYPT_SHOW_SHARED_KEY != state.encryption.mode))
        {
            G_io_apdu_buffer[(*tx)++] = R_NO_SETUP;
            return;
        }

        if (0 != dataLength % 16) {
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
            return;
        }

        PRINTF("\n cbc %.*H", sizeof(state.encryption.cbc), state.encryption.cbc); 

        uint8_t * pos = dataBuffer;
        uint8_t tmp[AES_BLOCK_SIZE];

        while (pos < dataBuffer + dataLength) {
            if (P1_INIT_ENCRYPT == state.encryption.mode) {

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
        G_io_apdu_buffer[(*tx)++] = R_UNKOWN_CMD;
    }

    //temp: 17:26
	
    /*

    uint8_t nonce[32];
    cx_rng(nonce, sizeof(nonce));

    uint8_t IV[16];
    cx_rng(IV, sizeof(IV));

    uint8_t bufferToEncryptPos = p1 * sizeof(uint32_t) + 32; //derivation path and then public key
    uint8_t bufferToEncryptLength = dataLength - bufferToEncryptPos;    

    if (0 != bufferToEncryptLength % 16) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
        return;
    }

    if (255 < bufferToEncryptLength + 1 + sizeof(IV) + sizeof(nonce)) {
    	G_io_apdu_buffer[(*tx)++] = R_DATA_BUFFER_TOO_BIG;
        return;
    }

    PRINTF("\nd3");

    uint32_t derivationPath[54];
    os_memcpy(derivationPath, dataBuffer, p1 * sizeof(uint32_t));
   	
   	uint8_t exceptionOut = 0;
	uint8_t aesKey[32];

	uint8_t ret = getSharedEncryptionKey(derivationPath, p1, dataBuffer + p1 * sizeof(uint32_t), nonce, &exceptionOut, aesKey);

	

 	if (0 != aes_256_cbc_encrypt(aesKey, IV, dataBuffer + bufferToEncryptPos, bufferToEncryptLength)) {
		G_io_apdu_buffer[0] = R_AES_ERROR;
        *tx = 1;
		return;
	}

    G_io_apdu_buffer[0] = R_SUCCESS;

    os_memcpy(G_io_apdu_buffer + 1, nonce, sizeof(nonce));

    uint8_t i2 = 255 - bufferToEncryptLength; //moving the encypted buffer to the end of the stack to make room for the IV, then moving it back
    for (uint8_t i = 0; i <= bufferToEncryptLength; i++)
        dataBuffer[i2++] = dataBuffer[bufferToEncryptPos + i];

    os_memcpy(G_io_apdu_buffer + 1 + sizeof(nonce), IV, sizeof(IV));

    for (uint8_t i = 0; i < bufferToEncryptLength; i++)
        G_io_apdu_buffer[sizeof(IV) + sizeof(nonce) + 1 + i] = dataBuffer[255 - bufferToEncryptLength + i];

    *tx = 1 + sizeof(nonce) + sizeof(IV) + bufferToEncryptLength

    */

}

void encryptDecryptMessageHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint8_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {


	PRINTF("\n d0 %d", check_canary());

    encryptDecryptMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
