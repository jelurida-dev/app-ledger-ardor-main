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
#include <cx.h>
#include <os_io_seproxyhal.h>

#include "ardor.h"
#include "curve25519_i64.h"
#include "returnValues.h"

unsigned int makeTextGoAround_preprocessor(const bagl_element_t *element)
{
    if (element->component.userid > 0)
        UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
    
    return 1;
}

void fillBufferWithAnswerAndEnding(uint8_t answer, uint8_t * tx) {
    if (0 == tx) {
        G_io_apdu_buffer[0] = answer;
        G_io_apdu_buffer[1] = 0x90;
        G_io_apdu_buffer[2] = 0x00;
    } else {
        G_io_apdu_buffer[(*tx)++] = answer;
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}

//note: add that output must be of size 32
void sha256TwoBuffers(uint8_t * bufferTohash1, uint16_t sizeOfBuffer1, uint8_t * bufferTohash2, uint16_t sizeOfBuffer2, uint8_t * output) {
    cx_sha256_t shaContext;

    os_memset(output, 0, 32);
    cx_sha256_init(&shaContext); //return value has no info

    cx_hash(&shaContext.header, 0, bufferTohash1, sizeOfBuffer1, output, 32);

    if (0 != bufferTohash2)
        cx_hash(&shaContext.header, 0, bufferTohash2, sizeOfBuffer2, output, 32);
    
    cx_hash(&shaContext.header, CX_LAST, 0, 0, output, 32);
}

void sha256Buffer(uint8_t * bufferTohash, uint16_t sizeOfBuffer, uint8_t * output) {
    sha256TwoBuffers(bufferTohash, sizeOfBuffer, 0, 0, output);
}

void signMsg(const uint8_t * keySeedBfr, const uint8_t msgSha256, const uint8_t * sig) {

    uint8_t publicKeyX[32], privateKey[32]; os_memset(publicKeyX, 0, sizeof(publicKeyX)); os_memset(privateKey, 0, sizeof(privateKey));

    keygen25519(publicKeyX, privateKey, keySeedBfr);

    uint8_t x[32]; os_memset(x, 0, sizeof(x));

    PRINTF("\n m %.*H", 32, msgSha256);
    PRINTF("\n privateKey %.*H", 32, privateKey);

    sha256TwoBuffers(msgSha256, 32, privateKey, sizeof(privateKey), x);

    PRINTF("\n x %.*H", 32, x);

    uint8_t Y[32]; os_memset(Y, 0, sizeof(Y));

    keygen25519(Y, 0, x);

    PRINTF("\n Y %.*H", 32, Y);

    uint8_t h[32]; os_memset(h, 0, sizeof(h));

    sha256TwoBuffers(msgSha256, 32, Y, sizeof(Y), h);

    PRINTF("\n h: %.*H", 32, h);

    os_memmove(sig + 32, h, 32);

    sign25519(sig, h, x, privateKey); //todo: i changed s to privateKey maybe this is a problem

    PRINTF("l2");
}

int ed25519_pk_to_curve25519(unsigned char *curve25519_pk, const unsigned char *ed25519_pk);

#define MIN_DERIVATION_PATH_LENGTH 3

//todo: make sure i clean everything out
uint8_t ardorKeys(const uint32_t * derivationPath, const uint8_t derivationPathLengthInUints32, 
                            uint8_t *keySeedBfrOut, uint8_t *publicKeyCurveOut, uint8_t * publicKeyEd25519Out, uint8_t * chainCodeOut, uint16_t * exceptionOut) {
    
    uint8_t publicKeyBE[32]; os_memset(publicKeyBE, 0, sizeof(publicKeyBE)); //declaring here although used later, so it can be acessable to the finally statement
    uint8_t keySeedBfr[64]; os_memset(keySeedBfr, 0, sizeof(keySeedBfr));
    struct cx_ecfp_256_private_key_s privateKey; //Don't need to init, since the ->d is copied into from some other palce

    //uint32_t bipPrefix[] = {44 | 0x80000000, 29 | 0x80000000};
    uint32_t bipPrefix[] = PATH_PREFIX; //defined in Makefile

    if ((derivationPathLengthInUints32 < sizeof(bipPrefix) / sizeof(bipPrefix[0])) || (derivationPathLengthInUints32 < MIN_DERIVATION_PATH_LENGTH))
        return R_DERIVATION_PATH_TOO_SHORT;

    PRINTF("\nw: %.*H", derivationPathLengthInUints32 * 4, derivationPath);

    for (uint8_t i = 0; i < sizeof(bipPrefix) / sizeof(bipPrefix[0]); i++) {
        PRINTF("\n a - %d %d", i, derivationPath[i]);
        if (derivationPath[i] != bipPrefix[i])
            return R_WRONG_DERIVATION_PATH_HEADER;
    }

    BEGIN_TRY {
            TRY {
                    PRINTF("\nZ1");

                    //todo: understand that in BLUE only has SLIP10, and document this 

                    os_perso_derive_node_bip32(CX_CURVE_Ed25519, derivationPath, derivationPathLengthInUints32, keySeedBfr, chainCodeOut);

                    PRINTF("\nZ2");

                    // weird custom initilization, code copied from Cardano's EdDSA implementaion
                    privateKey.curve = CX_CURVE_Ed25519;
                    privateKey.d_len = 64;
                    os_memmove(privateKey.d, keySeedBfr, 32);
                    

                    if (0 != keySeedBfrOut) {
                        PRINTF("\nZ3");
                        os_memmove(keySeedBfrOut, keySeedBfr, 64); //the first of 32 bytes are used //todo, put back 64
                    }

                    //uint8_t P[32], s[32]; os_memset(P, 0, 32); os_memset(s, 0, 32);

                    //keygen25519(P, s, keySeedBfr);

                    //PRINTF("\nCurvedPrivateKey = publicKey (Genereated to check against) = %.*H", 32, P);
                    
                    if ((0 != publicKeyCurveOut) || (0 != publicKeyEd25519Out)) { //todo check that the private keys still gets loaded if not generate_pair

                        cx_ecfp_public_key_t publicKey; 
                        cx_ecfp_init_public_key(CX_CURVE_Ed25519, 0, 0, &publicKey);

                        //cx_ecfp_generate_pair(CX_CURVE_Ed25519, &publicKey, &privateKey, 0);

                        cx_eddsa_get_public_key(
                                // cx_eddsa has a special case struct for Cardano's private keys
                                // but signature is standard
                                &privateKey,
                                CX_SHA512,
                                &publicKey,
                                NULL, 0, NULL, 0);

                        // copy public key from big endian to little endian
                        

                        for (uint8_t i = 0; i < sizeof(publicKeyBE); i++) {
                            publicKeyBE[i] = publicKey.W[64 - i];
                        }

                        //PRINTF("\nd4");

                        
                        /*
                        // set sign bit
                        if ((publicKey.W[32] & 1) != 0) {
                            publicKeyBE[31] |= 0x80;
                        }
                        */
                        

                        //todo figure out the bit signing thing?

                        if (0 != publicKeyEd25519Out)
                                os_memmove(publicKeyEd25519Out, publicKeyBE, 32);


                        if (0 != publicKeyCurveOut)
                            morph25519_e2m(publicKeyCurveOut, publicKeyBE);                      
                    }



                    PRINTF("\nd7");
            }
            CATCH_OTHER(exception) {
                PRINTF("\nd8");
                *exceptionOut = exception;
                return R_KEY_DERIVATION_EX;
            }
            FINALLY {

                os_memset(privateKey.d, 0, privateKey.d_len);
                os_memset(keySeedBfr, 0, sizeof(keySeedBfr));
                os_memset(publicKeyBE, 0, sizeof(publicKeyBE));
                PRINTF("\nd10");
            }
        }
        END_TRY;

        PRINTF("\nd9");
    
    return R_SUCCESS;
}

uint8_t getSharedEncryptionKey(const uint32_t * derivationPath, const uint8_t derivationPathLengthInUints32, uint8_t* targetPublicKey, 
                                uint8_t * nonce, uint16_t * exceptionOut, uint8_t * aesKeyOut) {
    
    uint8_t keySeed[64]; os_memset(keySeed, 0, sizeof(keySeed));

    uint8_t ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, exceptionOut);

    if (R_SUCCESS != ret)
        return ret;

    uint8_t sharedKey[32]; os_memset(sharedKey, 0, sizeof(sharedKey));


    curve25519(sharedKey, keySeed, targetPublicKey); //should use only the first 32 bytes of keyseed
    
    for (uint8_t i = 0; i < sizeof(sharedKey); i++)
        sharedKey[i] ^= nonce[i];

    sha256Buffer(sharedKey, sizeof(sharedKey), aesKeyOut);

    PRINTF("\n sharedkey: %.*H", 32, aesKeyOut);

    return R_SUCCESS;
}

uint64_t publicKeyToId(uint8_t * publicKey) {
        
    uint8_t tempSha[32];
    sha256Buffer(publicKey, 32, tempSha);

    return ((((uint64_t) tempSha[7]) << 56) |
            (((uint64_t) tempSha[6]) << 48) |
            (((uint64_t) tempSha[5]) << 40) |
            (((uint64_t) tempSha[4]) << 32) |
            (((uint64_t) tempSha[3]) << 24) |
            (((uint64_t) tempSha[2]) << 16) |
            (((uint64_t) tempSha[1]) << 8) |
            (((uint64_t) tempSha[0] )));
}
