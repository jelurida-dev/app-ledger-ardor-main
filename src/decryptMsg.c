#include <stdint.h>
#include <stdbool.h>

#include <os.h>
#include <os_io_seproxyhal.h>
#include "ux.h"

#include "ardor.h"
#include "returnValues.h"

void decryptMessageHelper(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
        volatile unsigned int *flags, volatile unsigned int *tx) {

	if (p1 < 2) {
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
        return;
	}

    if (p1 > 43) { //47 is the spacial limit
		G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
        return; 
    }

    if (dataLength <  p1 * sizeof(uint32_t) + 32 + 32 + 16 + 16) { //derivation path, src public key, nonce, iv, buffer
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
        return; 
    }

    uint8_t dataToDecryptPos = p1 * sizeof(uint32_t) + 32 + 32 + 16;
    uint8_t dataToDecryptLength = dataLength - dataToDecryptPos;

    PRINTF("\ntt %d %d", dataToDecryptPos, dataToDecryptLength);
    PRINTF("\nasuidasdhiuasdhs ballon");

    if (0 != dataToDecryptLength % 16) {
        G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
        return;
    }

    uint32_t derivationPath[43];

    os_memcpy(derivationPath, dataBuffer, p1 * sizeof(uint32_t));
   	
   	uint8_t exceptionOut = 0;
 	uint8_t numBytesWrittenOut = 0;
    uint8_t aesKey[32];

    uint8_t ret = getSharedEncryptionKey(derivationPath, p1, dataBuffer + p1 * sizeof(uint32_t), 
        dataBuffer + p1 * sizeof(uint32_t) + 32, &exceptionOut, aesKey);

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

    if (0 == aes_256_cbc_decrypt(aesKey, dataBuffer + dataToDecryptPos - IV_SIZE, dataBuffer + dataToDecryptPos, dataToDecryptLength)) {
        G_io_apdu_buffer[0] = R_SUCCESS;

        for (uint8_t i = 0; i < dataToDecryptLength; i++)
            G_io_apdu_buffer[1 + i] = dataBuffer[dataToDecryptPos + i];

        *tx = dataToDecryptLength + 1;
        
    } else {
        G_io_apdu_buffer[0] = R_AES_ERROR;
        *tx = 1;
    }
}

void decryptMessageHandler(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength,
                volatile unsigned int *flags, volatile unsigned int *tx) {

    decryptMessageHelper(p1, p2, dataBuffer, dataLength, flags, tx);
    
    G_io_apdu_buffer[(*tx)++] = 0x90;
    G_io_apdu_buffer[(*tx)++] = 0x00;
}
