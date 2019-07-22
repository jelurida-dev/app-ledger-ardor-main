#include <stdint.h>
#include <stdbool.h>

#include <os.h>
#include <cx.h>


#include "ardor.h"
#include "curve25519_i64.h"
#include "returnValues.h"


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

void createPrivateKey(uint8_t * publicKeyOut) {
    uint8_t s[32], k[32] = {0x95,0x28,0x7A,0x09,0x8A,0x21,0x87,0xF0,0x73,0x15,0xE6,0x0A,0x7C,0x68,0x24,0x95,0xBA,0xE5,0x8E,0x30,0x63,0x7E,0x75,0x1D,0x2A,0xF5,0x71,0x73,0xAA,0x18,0x94,0xE2};

    //os_memset(k, 10, sizeof(k));

    //keygen25519(publicKeyOut, s, k);



    uint8_t a[32] = {0xC9, 0xAD, 0x50, 0xA9, 0x77, 0x2F, 0xA8, 0x93, 0x86, 0xFF, 0x73, 0x78, 0x97, 0x1F, 0xB4, 0x56, 0x67, 0xFC, 0x98, 0xA7, 0xA2, 0x5A, 0xE8, 0x05, 0x89, 0xE8, 0x02, 0x84, 0x70, 0xD9, 0x15, 0xD5};
    uint8_t b[32] = {0xC0, 0x6F, 0x14, 0x8E, 0xAE, 0xF3, 0xFA, 0xCD, 0xED, 0x95, 0x41, 0x25, 0x93, 0xB7, 0xE5, 0x0F, 0x93, 0x18, 0xE1, 0x55, 0x3B, 0x15, 0xA4, 0x35, 0x2D, 0x81, 0xDF, 0x05, 0x50, 0x1F, 0x4B, 0x4C};
    uint8_t c[32] = {0x29, 0xEE, 0x15, 0xDF, 0x37, 0xF9, 0x15, 0x68, 0x20, 0xA3, 0xCE, 0x5D, 0x92, 0x8F, 0x75, 0x9C, 0x9E, 0x66, 0x51, 0x70, 0x5F, 0x14, 0xA3, 0x10, 0x8C, 0x86, 0xE4, 0x17, 0xB6, 0x32, 0x93, 0x08};


    sign25519(s, a, b, c);

    debugSend(0xab, 0, 0, 0, s, 32);



    //keygen(publicKeyOut, s, k);
}

int ed25519_pk_to_curve25519(unsigned char *curve25519_pk, const unsigned char *ed25519_pk);

#define MIN_DERIVATION_PATH_LENGTH 3

//todo: make sure i clean everything out
uint8_t ardorKeys(const uint32_t * derivationPath, const uint8_t derivationPathLengthInUints32, 
                            uint8_t *keySeedBfrOut, uint8_t *publicKeyOut, uint8_t * chainCodeOut, uint16_t * exceptionOut) {
    
    uint8_t keySeedBfr[64]; os_memset(keySeedBfr, 0, sizeof(keySeedBfr));
    uint8_t shaOut[64]; os_memset(shaOut, 0, sizeof(shaOut));
    uint8_t publicKeyBE[32]; os_memset(publicKeyBE, 0, sizeof(publicKeyBE));

    struct cx_ecfp_256_private_key_s privateKey; //Don't need to init, since the ->d is copied into from some other palce
    cx_ecfp_public_key_t publicKey; //cx_ecfp_init_public_key is called later, don't need to init this now, 

    uint32_t bipPrefix[] = {44 | 0x80000000, 29 | 0x80000000};

    if ((derivationPathLengthInUints32 < sizeof(bipPrefix) / sizeof(bipPrefix[0])) || (derivationPathLengthInUints32 < MIN_DERIVATION_PATH_LENGTH))
        return R_DERIVATION_PATH_TOO_SHORT;

    PRINTF("\nw: %.*H", derivationPathLengthInUints32 * 4, derivationPath);

    for (uint8_t i = 0; i < sizeof(bipPrefix) / sizeof(bipPrefix[0]); i++) {
        if (derivationPath[i] != bipPrefix[i])
            return R_WRONG_DERIVATION_PATH_HEADER;
    }

    BEGIN_TRY {
            TRY {
                    //todo: understand that in BLUE only has SLIP10, and document this
                    os_perso_derive_node_bip32(CX_CURVE_Ed25519, derivationPath, derivationPathLengthInUints32, keySeedBfr, chainCodeOut);

                    // weird custom initilization, code copied from Cardano's EdDSA implementaion
                    privateKey.curve = CX_CURVE_Ed25519;
                    privateKey.d_len = 64;
                    os_memmove(privateKey.d, keySeedBfr, 64);
                    

                    //uint8_t P[32], s[32]; os_memset(P, 0, 32); os_memset(s, 0, 32);

                    //keygen25519(P, s, keySeedBfr);

                    //PRINTF("\nCurvedPrivateKey = publicKey (Genereated to check against) = %.*H", 32, P);
                    
                    if (0 != publicKeyOut) { //todo check that the private keys still gets loaded if not generate_pair
                        
                        PRINTF("\n keySeedBfr %.*H", 64, keySeedBfr);

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

                        morph25519_e2m(publicKeyOut, publicKeyBE);

                        PRINTF("\nd5 Morhped Using New Derivation Scheme: %.*H", 32, publicKeyOut);
                    }

                    if (0 != keySeedBfrOut) {
                        os_memmove(keySeedBfrOut, keySeedBfr, 32); //the first of 32 bytes are used
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
                os_memset(shaOut, 0, sizeof(shaOut));
                os_memset(publicKeyBE, 0, sizeof(publicKeyBE));
                PRINTF("\nd10");
            }
        }
        END_TRY;

        PRINTF("\nd9");
    
    return R_SUCCESS;
}