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

#include "curve25519_i64.h"
#include "returnValues.h"
#include "config.h"

#include "ardor.h"




//the global state
states_t state;

#if defined(TARGET_NANOS)

    //This is a prepocessor function for dialogs, it allows long labels to go in circles, like long crypto addresses, I have no idea how this works :)
    unsigned int makeTextGoAround_preprocessor(bagl_element_t * const element)
    {
        //I guess we are filtering on the UI element
        if (element->component.userid > 0)
            UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
        
        return 1;
    }

#endif

//self explanatory
//output must point to buffer of 32 bytes in size
void sha256TwoBuffers(const uint8_t * const bufferTohash1, const uint16_t sizeOfBuffer1, const uint8_t * const bufferTohash2, const uint16_t sizeOfBuffer2, uint8_t * const output) {
    cx_sha256_t shaContext;

    os_memset(output, 0, 32);
    cx_sha256_init(&shaContext); //return value has no info

    cx_hash(&shaContext.header, 0, bufferTohash1, sizeOfBuffer1, output, 32);

    if (0 != bufferTohash2)
        cx_hash(&shaContext.header, 0, bufferTohash2, sizeOfBuffer2, output, 32);
    
    cx_hash(&shaContext.header, CX_LAST, 0, 0, output, 32);
}

//self explanatory
//output must point to buffer of 32 bytes in size
void sha256Buffer(const uint8_t * const bufferTohash, const uint16_t sizeOfBuffer, uint8_t * const output) {
    sha256TwoBuffers(bufferTohash, sizeOfBuffer, 0, 0, output);
}

//This is the EC-KCDSA siging implementation
//@param in: keySeedBfr should point to a 32 byte keyseed (privateKey ^ -1) - note this function can edit keySeedBfr in the process
//@parma in: msgSha256 should point to a 32 byte sha256 of the message we are signing
//@param out: sig should point to 64 bytes allocated to hold the signiture of the message
void signMsg(uint8_t * const keySeedBfr, const uint8_t * const msgSha256, uint8_t * const sig) {

    uint8_t publicKeyX[32], privateKey[32]; os_memset(publicKeyX, 0, sizeof(publicKeyX)); os_memset(privateKey, 0, sizeof(privateKey));

    keygen25519(publicKeyX, privateKey, keySeedBfr);

    uint8_t x[32]; os_memset(x, 0, sizeof(x));

    sha256TwoBuffers(msgSha256, 32, privateKey, sizeof(privateKey), x);

    uint8_t Y[32]; os_memset(Y, 0, sizeof(Y));

    keygen25519(Y, 0, x);

    uint8_t h[32]; os_memset(h, 0, sizeof(h));

    sha256TwoBuffers(msgSha256, 32, Y, sizeof(Y), h);

    os_memmove(sig + 32, h, 32);

    sign25519(sig, h, x, privateKey);
}


//from curveConversion.C
void morph25519_e2m(uint8_t *montgomery, const uint8_t *y);


//this function derives an ardor keeyseed (privatekey ^ -1), public key, ed255119 public key and chaincode
//For more info on how this derivation works, please read the readme
//@param in: derivationPath - a BIP42 derivation path, must be at least of length MIN_DERIVATION_PATH_LENGTH
//@param in: derivationPathLengthInUints32 - kinda what it says it is
//@param optional out: keySeedBfrOut - 32 byte EC-KCDSA keyseed for the derivation path
//@param optional out: publicKeyCurveXout - 32 byte EC-KCDSA public key for the derivation path
//@param optional out: publicKeyEd25519YLEWithXParityOut - 32 byte ED255119 public key for the derivation path (used for debuging), with the MSB as X's parity
//@param optional out: chainCodeOut - the 32 byte ED255119 derivation chaincode, used for external master public key derivation
//@param out: exceptionOut - iff the return code is R_EXCEPTION => exceptionOut will be filled with the Nano exception code
//@returns: regular return values
uint8_t ardorKeys(const uint32_t * const derivationPath, const uint8_t derivationPathLengthInUints32, 
                    uint8_t * const keySeedBfrOut, uint8_t * const publicKeyCurveXout, uint8_t * const publicKeyEd25519YLEWithXParityOut, uint8_t * const chainCodeOut, uint16_t * const exceptionOut) {
    
    uint8_t publicKeyYLE[32]; os_memset(publicKeyYLE, 0, sizeof(publicKeyYLE)); //declaring here although used later, so it can be acessable to the finally statement
    uint8_t KLKR[64]; os_memset(KLKR, 0, sizeof(KLKR));
    struct cx_ecfp_256_private_key_s privateKey; //Don't need to init, since the ->d is copied into from some other palce, this key is 32 bytes in size

    uint32_t bipPrefix[] = PATH_PREFIX; //defined in Makefile

    if ((MIN_DERIVATION_LENGTH > derivationPathLengthInUints32) || (MAX_DERIVATION_LENGTH < derivationPathLengthInUints32))
        return R_WRONG_SIZE_ERR;

    for (uint8_t i = 0; i < sizeof(bipPrefix) / sizeof(bipPrefix[0]); i++) {
        if (derivationPath[i] != bipPrefix[i])
            return R_WRONG_DERIVATION_PATH_HEADER;
    }

    BEGIN_TRY {
            TRY {
                    os_perso_derive_node_bip32(CX_CURVE_Ed25519, derivationPath, derivationPathLengthInUints32, KLKR, chainCodeOut);

                    // weird custom initilization, code copied from Cardano's EdDSA implementaion
                    privateKey.curve = CX_CURVE_Ed25519;
                    privateKey.d_len = 64; //don't know why the length is 64 instead of 32, it just works
                    os_memmove(privateKey.d, KLKR, 32); //Copy just the KL part
                    
                    //KL is the keeyseed, KR is used for key derivation
                    if (0 != keySeedBfrOut) {
                        //os_memmove(keySeedBfrOut, KLKR, 64); used for testing - DO NOT COMMIT THIS LINE! DO NOT COMMIT THIS LINE!, most functions expect a 32 private key and they will get stack overwtite
                        os_memmove(keySeedBfrOut, KLKR, 32);
                    }
                    
                    if ((0 != publicKeyCurveXout) || (0 != publicKeyEd25519YLEWithXParityOut)) {

                        cx_ecfp_public_key_t publicKey; 
                        cx_ecfp_init_public_key(CX_CURVE_Ed25519, 0, 0, &publicKey);

                        //This should return A = KL * B - B is the generator point in ED25519
                        //So publicKey.W = 04 Ax Ay in BE
                        cx_eddsa_get_public_key(
                                &privateKey,
                                CX_SHA512,
                                &publicKey,
                                NULL, 0, NULL, 0);

                        // copy public key from big endian to little endian
                        for (uint8_t i = 0; i < sizeof(publicKeyYLE); i++)
                            publicKeyYLE[i] = publicKey.W[64 - i];

                        if (0 != publicKeyCurveXout)
                            morph25519_e2m(publicKeyCurveXout, publicKeyYLE);

                        //We encode the pairty of X into the MSB of Y, since it's never used because of the feild size
                        //This allows us to compress X,Y into 32 bytes
                        if ((publicKey.W[32] & 1) != 0)
                            publicKeyYLE[31] |= 0x80;

                        if (0 != publicKeyEd25519YLEWithXParityOut)
                            os_memmove(publicKeyEd25519YLEWithXParityOut, publicKeyYLE, 32);
                    }
            }
            CATCH_OTHER(exception) {
                *exceptionOut = exception;
                return R_KEY_DERIVATION_EX;
            }
            FINALLY {
                os_memset(privateKey.d, 0, privateKey.d_len);
                os_memset(KLKR, 0, sizeof(KLKR));
                os_memset(publicKeyYLE, 0, sizeof(publicKeyYLE));
            }
        }
        END_TRY;
    
    return R_SUCCESS;
}

//Creates a shared AES encryption key one the matches the key related to the derivation path, the target public key and the nonce
//@param derivationPath - the derivation path
//@param derivationPathLengthInUints32 - kinda clear what this is
//@param targetPublicKey - the 32 byte public key
uint8_t getSharedEncryptionKey(const uint32_t * const derivationPath, const uint8_t derivationPathLengthInUints32, const uint8_t* const targetPublicKey, 
                                const uint8_t * const nonce, uint16_t * const exceptionOut, uint8_t * const aesKeyOut) {
    
    uint8_t keySeed[32]; os_memset(keySeed, 0, sizeof(keySeed));

    uint8_t ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, exceptionOut);

    if (R_SUCCESS != ret)
        return ret;

    uint8_t sharedKey[32]; os_memset(sharedKey, 0, sizeof(sharedKey));


    curve25519(sharedKey, keySeed, targetPublicKey); //should use only the first 32 bytes of keyseed
    
    for (uint8_t i = 0; i < sizeof(sharedKey); i++)
        sharedKey[i] ^= nonce[i];

    sha256Buffer(sharedKey, sizeof(sharedKey), aesKeyOut);

    return R_SUCCESS;
}

//param: publicKey should point to a 32 byte public key buffer
//returns: a 64bit public key id, used later with reedsolomon to create Ardor/NXT addresses
uint64_t publicKeyToId(const uint8_t * const publicKey) {
        
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


//app_stack_canary is defined by the link script to be at the start of the user data or end of the stack, something like that
//so if there is a stack overflow then it will be overwriten, this is how check_canary() works.
//make sure HAVE_BOLOS_APP_STACK_CANARY is defined in the makefile, so that the OS code will init it and check against it every io_exchange call
//if the canary is not the same, and if not, it will throw

extern unsigned int app_stack_canary;

bool check_canary() {
    return 0xDEAD0031 == app_stack_canary;
}
