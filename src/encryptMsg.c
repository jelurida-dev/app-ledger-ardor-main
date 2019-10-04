#include <stdint.h>
#include <stdbool.h>

#include <os.h>
#include <os_io_seproxyhal.h>
#include "ux.h"

#include "ardor.h"
#include "returnValues.h"

void encryptMessageHandlerHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {

	if (p1 < 2) {
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
        return;
	}

    if (p1 > 50) { // (255 - 5 - 32 - 16) / 4
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
        return;
    }

    if (dataLength <  p1 * sizeof(uint32_t) + 1) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return; 
    }

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

    *tx = 1 + sizeof(nonce) + sizeof(IV) + bufferToEncryptLength;
}

void encryptMessageHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {


	PRINTF("\nd0");

    encryptMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
