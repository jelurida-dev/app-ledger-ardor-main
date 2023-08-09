from constants import RESPONSE_SUFFIX, R_SUCCESS, ROOT_SCREENSHOT_PATH, PATH_STR_0, PATH_STR_1
from ragger.navigator import NavInsID
from ardor_command_sender import ArdorCommandSender

RET_VAL_TRANSACTION_ACCEPTED = 8 # R_FINISHED
RET_VAL_TRANSACTION_REJECTED = 1 # R_REJECT

def _sign_tx_test(backend, navigator, unsigned_bytes_hex: str, expected_signature: str, test_name: str, instructions, signing_account = PATH_STR_0):
    tx_bytes = bytes.fromhex(unsigned_bytes_hex)
    client = ArdorCommandSender(backend)
    with client.load_tx(tx_bytes):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == RET_VAL_TRANSACTION_ACCEPTED

    signature = client.sign_tx(signing_account)
    assert signature.hex() == expected_signature

def _sign_tx_reject(backend, navigator, unsigned_bytes_hex: str, test_name: str, instructions):
    tx_bytes = bytes.fromhex(unsigned_bytes_hex)
    client = ArdorCommandSender(backend)
    with client.load_tx(tx_bytes):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == RET_VAL_TRANSACTION_REJECTED

    client.sign_tx_reject(PATH_STR_0)

def get_nano_instructions(firmware, nanos_screens: int, nanoxsp_screens: int):
    if firmware.device == 'nanos':
        return [NavInsID.RIGHT_CLICK] * nanos_screens + [NavInsID.BOTH_CLICK]
    elif firmware.device == 'nanox' or firmware.device == 'nanosp':
        return [NavInsID.RIGHT_CLICK] * nanoxsp_screens + [NavInsID.BOTH_CLICK]
    else:
        assert False

def get_stax_instructions(num_taps: int):
    return [NavInsID.USE_CASE_REVIEW_TAP] * num_taps + [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]

def test_send_money_tx(backend, navigator, firmware):   
    tx_bytes = "020000000000011d98fe090f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb00c2eb0b0000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "ad92efeb45e2d0866b22a20ad3bbc75b3fbcd63a32b451665857815598d13800404feca2d6f33730fae127ce89a2213e06afb9e8dbb44e06c7514cb56475e642"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        instructions = get_nano_instructions(firmware, 7, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_money_tx", instructions)

def test_send_money_tx_reject(backend, navigator, firmware):
    tx_bytes = "020000000000011d98fe090f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb00c2eb0b0000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000000000000000000000000000000000000000000000000000000000000000000000000000"
    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_REVIEW_TAP] * 3 + [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
    else:
        instructions = get_nano_instructions(firmware, 8, 6)
    _sign_tx_reject(backend, navigator, tx_bytes, "test_send_money_tx_reject", instructions)

def test_send_ardr_tx(backend, navigator, firmware):
    tx_bytes = "01000000fe0001f944910a0f00a45834eef72000e08093cb1e23d9c873a9acea0a893bb02738bf8328ba1d076533ece497d15c7f343090b7000000000000e1f5050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc95800000000"
    expected_signature = "65ee18432849dc797092287436cfb849f1ddf0f288c79f3cb99cb4dc754bac0c1e7dc2f5b6e1cc6542750954d2a5f0572a7fe721bd0bbf9d60f9336a85818ca4"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        instructions = get_nano_instructions(firmware, 7, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_ardr_tx", instructions, PATH_STR_1)

def test_send_ardr(backend, navigator, firmware):
    tx_bytes = "01000000fe0001ab77050a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb00c2eb0b0000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000"
    expected_signature = "7acc118c59b17814e8b5d38b3ecd44153e82934725d3c2ffa1433862bd2f580edfb68701a5c9a4a0b7ceec8065738c71837ab6a47b07694c67875be48ae0c4fd"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        instructions = get_nano_instructions(firmware, 7, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_ardr", instructions)

def test_ardor_coin_exchange(backend, navigator, firmware):
    tx_bytes = "01000000fc0001ca81050a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a200000000000000000000000000000000080f0fa02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d12000000000101000000020000000084d7170000000080f0fa0200000000"
    expected_signature = "c21135e4b982ff3af00185cab80f9aba1c5eaba8d2d9867e841123d3c2c17c0bb2bc3bc769e6714844751c105be64622f94efec668ca41d09b1524e3ee421747"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(2)
    else:
        instructions = get_nano_instructions(firmware, 6, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_ardor_coin_exchange", instructions)

def test_coin_exchange(backend, navigator, firmware):
    tx_bytes = "020000000b0001a089050a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a200000000000000000000000000000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d120000000001020000000400000000c2eb0b0000000080d1f00800000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "26d36905267146675fc76c4ccac52242d0b8afc60007485386448f2bd1031c04f9819069ce6331248a55745643a2f2e4211d08cba0d50ba2de0284bca6125541"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(2)
    else:
        instructions = get_nano_instructions(firmware, 6, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_coin_exchange", instructions)

def test_asset_transfer(backend, navigator, firmware):
    tx_bytes = "02000000020101ee8e050a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb000000000000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000013ba0719534c294dcd007000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "76aaddf7af7fc01f5dc925b3755e7c46072b13ce9a7d46c232711aaa932c6306b437fa833bee1535a0dadb34a8d1f6b5e2131a39086d4ccb80e5eceb028624e0"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        instructions = get_nano_instructions(firmware, 9, 6)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_asset_transfer", instructions)