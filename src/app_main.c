/*******************************************************************************
*
*  (c) 2016 Ledger
*  (c) 2018 Nebulous
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

#include "config.h"
#include "ardor.h"
#include "returnValues.h"
#include "ui/menu.h"

// The APDU protocol uses a single-byte instruction code (INS) to specify
// which command should be executed. We'll use this code to dispatch on a
// table of function pointers.
#define INS_GET_VERSION    					0x01
#define INS_AUTH_SIGN_TXN  					0x03
#define INS_ENCRYPT_DECRYPT_MSG				0x04
#define INS_SHOW_ADDRESS 					0x05
#define INS_GET_PUBLIC_KEY_AND_CHAIN_CODE 	0x06
#define INS_SIGN_TOKEN						0x07

// This is the function signature for a command handler. 'flags' and 'tx' are
// out-parameters that will control the behavior of the next io_exchange call
typedef void handler_fn_t(const uint8_t p1, const uint8_t p2, const uint8_t *dataBuffer, const uint16_t dataLength, uint8_t * const flags, uint8_t * const tx, const bool isLastCommandDifferent);

handler_fn_t getVersionHandler;
handler_fn_t authAndSignTxnHandler;
handler_fn_t encryptDecryptMessageHandler;
handler_fn_t showAddressHandler;
handler_fn_t getPublicKeyAndChainCodeHandler;
handler_fn_t signTokenMessageHandler;

//function translate command ID to function PTR
static handler_fn_t* lookupHandler(uint8_t ins) {
	switch (ins) {
	case INS_GET_VERSION:    					return getVersionHandler;
	case INS_AUTH_SIGN_TXN:   					return authAndSignTxnHandler;
	case INS_ENCRYPT_DECRYPT_MSG:				return encryptDecryptMessageHandler;
	case INS_SHOW_ADDRESS:						return showAddressHandler;
	case INS_GET_PUBLIC_KEY_AND_CHAIN_CODE: 	return getPublicKeyAndChainCodeHandler;
	case INS_SIGN_TOKEN:						return signTokenMessageHandler;
	default:                 		return NULL;
	}
}


//thit is used to clean state if we change command types
uint8_t lastCmdNumber = 0;


//Does what it says, in return buffers the first byte is the return code, 0 is sucess allways
//and all the buffer have 0x90,0x00 at the end, even on errors
void fillBufferWithAnswerAndEnding(const uint8_t answer, uint8_t * const tx) {
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




// This is the main loop that reads and writes APDUs. It receives request
// APDUs from the computer, looks up the corresponding command handler, and
// calls it on the APDU payload. Then it loops around and calls io_exchange
// again. The handler may set the 'flags' and 'tx' variables, which affect the
// subsequent io_exchange call. The handler may also throw an exception, which
// will be caught, converted to an error code, appended to the response APDU,
// and sent in the next io_exchange call.
void app_main(void) {

	ui_menu_main();

	lastCmdNumber = 0;

	uint8_t rx = 0;
	uint8_t tx = 0;
	uint8_t flags = 0;

	// Exchange APDUs until EXCEPTION_IO_RESET is thrown.
	for (;;) {
		// The Ledger SDK implements a form of exception handling. In addition
		// to explicit THROWs in user code, syscalls (prefixed with os_ or
		// cx_) may also throw exceptions.
		//
		// This TRY block serves to catch any thrown exceptions
		// and convert them to response codes, which are then sent in APDUs.
		// However, EXCEPTION_IO_RESET will be re-thrown and caught by the
		// "true" main function defined in the SDK.
		

		BEGIN_TRY {
			TRY {
				rx = tx;
				tx = 0; // ensure no race in CATCH_OTHER if io_exchange throws an error
				
				rx = io_exchange(CHANNEL_APDU | flags, rx);
				flags = 0;

				// No APDU received; trigger a reset.
				if (rx == 0) {
					THROW(EXCEPTION_IO_RESET); //lastCmdNumber will be zero'd when ardor_main will be called again
				}
				// Malformed APDU.
				if (CLA != G_io_apdu_buffer[OFFSET_CLA]) {
					lastCmdNumber = 0; //forces the next handler call to clean the state
					fillBufferWithAnswerAndEnding(R_BAD_CLA, &tx);
					CLOSE_TRY;
					continue;
				}

				// Lookup and call the requested command handler.
				handler_fn_t *handlerFn = lookupHandler(G_io_apdu_buffer[OFFSET_INS]);
				if (!handlerFn) {
					lastCmdNumber = 0; //force the next handler call to clean the state
					fillBufferWithAnswerAndEnding(R_UNKOWN_CMD, &tx);
					CLOSE_TRY;
					continue;
				}

				PRINTF("canary check %d last command number %d\n", check_canary(), lastCmdNumber);

				uint8_t lastCommandSaver = G_io_apdu_buffer[OFFSET_INS]; //the handler is going to write over the buffer, so the command needs to be put aside

				handlerFn(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
				          G_io_apdu_buffer + OFFSET_CDATA, G_io_apdu_buffer[OFFSET_LC], &flags, &tx, G_io_apdu_buffer[OFFSET_INS] != lastCmdNumber);

				lastCmdNumber = lastCommandSaver;
			}
			CATCH(EXCEPTION_IO_RESET) {
				THROW(EXCEPTION_IO_RESET); //lastCmdNumber will be zero'd when ardor_main will be called again
			}
			CATCH_OTHER(e) {

				//just to make sure there is no hacking going on
				//reset all the states
			    lastCmdNumber = 0;
				
				tx = 0;
				flags = 0;

				G_io_apdu_buffer[tx++] = R_EXCEPTION;
				G_io_apdu_buffer[tx++] = e >> 8;
				fillBufferWithAnswerAndEnding(e & 0xFF, &tx);
			}
			FINALLY {
				// intentionally blank
			}
		} END_TRY;
	}
}
