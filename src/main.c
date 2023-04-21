/*******************************************************************************
*
*  (c) 2016 Ledger
*  (c) 2018 Nebulous
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
#include <os_io_seproxyhal.h>
#include "glyphs.h"
#include "ux.h"

#include "config.h"
#include "ardor.h"
#include "returnValues.h"

ux_state_t G_ux;
bolos_ux_params_t G_ux_params;	

UX_STEP_NOCB(
    ux_idle_flow_1_step, 
    bn, 
    {
      "Application",
      "is ready",
    });
UX_STEP_NOCB(
    ux_idle_flow_2_step, 
    bn, 
    {
      "Version",
      APPVERSION,
    });
UX_STEP_VALID(
    ux_idle_flow_3_step,
    pb,
    os_sched_exit(-1),
    {
      &C_icon_dashboard,
      "Quit",
    });
const ux_flow_step_t * const ux_idle_flow [] = {
  &ux_idle_flow_1_step,
  &ux_idle_flow_2_step,
  &ux_idle_flow_3_step,
  FLOW_END_STEP,
};


// ui_idle displays the main menu. Note that your app isn't required to use a
// menu as its idle screen; you can define your own completely custom screen.
void ui_idle() {
    // reserve a display stack slot if none yet
    if(G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
}


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
static void ardor_main(void) {

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
		// "true" main function defined at the bottom of this file.
		

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
					continue;
				}

				// Lookup and call the requested command handler.
				handler_fn_t *handlerFn = lookupHandler(G_io_apdu_buffer[OFFSET_INS]);
				if (!handlerFn) {
					lastCmdNumber = 0; //force the next handler call to clean the state
					fillBufferWithAnswerAndEnding(R_UNKOWN_CMD, &tx);
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
			}
		}
		END_TRY;
	}
}


// Everything below this point is Ledger magic. And the magic isn't well-
// documented, so if you want to understand it, you'll need to read the
// source, which you can find in the nanos-secure-sdk repo. Fortunately, you
// don't need to understand any of this in order to write an app.
//
// Next, we'll look at how the various commands are implemented. We'll start
// with the sizeofmplest command, signHash.c.

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
	io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

unsigned char io_event(unsigned char channel) {

	UNUSED(channel);

	// can't have more than one tag in the reply, not supported yet.
	switch (G_io_seproxyhal_spi_buffer[0]) {
	case SEPROXYHAL_TAG_FINGER_EVENT:
		UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
		break;

	case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
		UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
		break;

#ifdef HAVE_BLE
    // Make automatically discoverable again when disconnected
    case SEPROXYHAL_TAG_BLE_CONNECTION_EVENT:
        if (G_io_seproxyhal_spi_buffer[3] == 0) {
            // TODO : cleaner reset sequence
            // first disable BLE before turning it off
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 0;
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
            // send BLE power on (default parameters)
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 3; // ble on & advertise
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
        }
        break;
#endif
        
	case SEPROXYHAL_TAG_STATUS_EVENT:
		if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
			!(U4BE(G_io_seproxyhal_spi_buffer, 3) &
			  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
			THROW(EXCEPTION_IO_RESET);
		}
		UX_DEFAULT_EVENT();
		break;

	case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
		UX_DISPLAYED_EVENT({});
		break;

	case SEPROXYHAL_TAG_TICKER_EVENT:
		UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
		break;

	default:
		UX_DEFAULT_EVENT();
		break;
	}

	// close the event if not done previously (by a display or whatever)
	if (!io_seproxyhal_spi_is_status_sent()) {
		io_seproxyhal_general_status();
	}

	// command has been processed, DO NOT reset the current APDU transport
	return 1;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
	switch (channel & ~(IO_FLAGS)) {
	case CHANNEL_KEYBOARD:
		break;
	// multiplexed io exchange over a SPI channel and TLV encapsulated protocol
	case CHANNEL_SPI:
		if (tx_len) {
			io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);
			if (channel & IO_RESET_AFTER_REPLIED) {
				reset();
			}
			return 0; // nothing received from the master so far (it's a tx transaction)
		} else {
			return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
		}
	default:
		THROW(INVALID_PARAMETER);
	}
	return 0;
}

static void app_exit(void) {
	BEGIN_TRY_L(exit) {
		TRY_L(exit) {
			os_sched_exit(-1);
		}
		FINALLY_L(exit) {
		}
	}
	END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
	// exit critical section
	__asm volatile("cpsie i");

	for (;;) {
		UX_INIT();
		os_boot();
		BEGIN_TRY {
			TRY {
				io_seproxyhal_init();
				#ifdef TARGET_NANOX
            		// grab the current plane mode setting
            		G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
				#endif // TARGET_NANOX
				USB_power(0);
				USB_power(1);
				ui_idle();

				#ifdef HAVE_BLE
            		BLE_power(0, NULL);
            		BLE_power(1, "Nano X");
				#endif // HAVE_BLE

            	ardor_main();

			}
			CATCH(EXCEPTION_IO_RESET) {
				// reset IO and UX before continuing
				continue;
			}
			CATCH_ALL {
				break;
			}
			FINALLY {
			}
		}
		END_TRY;
	}
	app_exit();
	return 0;
}
