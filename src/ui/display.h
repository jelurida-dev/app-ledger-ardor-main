#pragma once

#include <stdint.h> // uint64_t

typedef void (*ui_callback)(void);

void showAddressScreen(const uint64_t publicKey, ui_callback callback);

void showSignTokenScreen(ui_callback cb_accept, ui_callback cb_reject);

void showSignTransactionScreen(ui_callback cb_accept, ui_callback cb_reject);