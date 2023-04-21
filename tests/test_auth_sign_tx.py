from constants import RESPONSE_SUFFIX, R_SUCCESS, ROOT_SCREENSHOT_PATH, PATH_STR_0
from ragger.navigator import NavInsID
from ardor_command_sender import ArdorCommandSender

RET_VAL_TRANSACTION_ACCEPTED = 8

# Sign a sendMoney transaction.
# {
#   "minimumFeeFQT": "1000000",
#   "transactionJSON": {
#     "senderPublicKey": "6e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20",
#     "chain": 2,
#     "feeNQT": "100000000",
#     "type": 0,
#     "version": 1,
#     "fxtTransaction": "0",
#     "phased": false,
#     "ecBlockId": "1318911886063902233",
#     "attachment": {
#       "version.OrdinaryPayment": 0
#     },
#     "senderRS": "ARDOR-BV3M-U8DY-CWAX-5WUZA",
#     "subtype": 0,
#     "amountNQT": "200000000",
#     "sender": "3782844267280788531",
#     "recipientRS": "ARDOR-EVHD-5FLM-3NMQ-G46NR",
#     "recipient": "16992224448242675179",
#     "ecBlockHeight": 0,
#     "deadline": 15,
#     "timestamp": 167680029,
#     "height": 2147483647
#   },
#   "unsignedTransactionBytes": "020000000000011d98fe090f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb00c2eb0b0000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000000000000000000000000000000000000000000000000000000000000000000000000000",
#   "broadcasted": false,
#   "requestProcessingTime": 3
# }
def test_send_money_tx(backend, navigator, firmware):
    tx_bytes = bytes.fromhex("020000000000011d98fe090f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb00c2eb0b0000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000000000000000000000000000000000000000000000000000000000000000000000000000")
    if firmware.device == 'nanos':
        num_screens = 7
    elif firmware.device == 'nanox':
        num_screens = 5
    else:
        assert False

    client = ArdorCommandSender(backend)
    with client.load_tx(tx_bytes):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, "test_send_money_tx", instructions=[NavInsID.RIGHT_CLICK] * num_screens + [NavInsID.BOTH_CLICK])

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == RET_VAL_TRANSACTION_ACCEPTED

    signature = client.sign_tx(PATH_STR_0)
    assert signature.hex() == "ad92efeb45e2d0866b22a20ad3bbc75b3fbcd63a32b451665857815598d13800404feca2d6f33730fae127ce89a2213e06afb9e8dbb44e06c7514cb56475e642"