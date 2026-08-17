from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, R_SUCCESS, RESPONSE_SUFFIX, R_REJECT
from utils import blind_review, decline_blind_signing

TOKEN_TIMESTAMP = 167772040

def _send_token_for_signing(backend) -> ArdorCommandSender:
    msg = "Token Data"

    client = ArdorCommandSender(backend)
    rapdu = client.sign_token_init()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1
    assert rapdu.data[0] == R_SUCCESS

    rapdu = client.sign_token_send_bytes(msg.encode())
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1
    assert rapdu.data[0] == R_SUCCESS
    return client

def test_sign_token(backend, navigator, scenario_navigator, device, test_name):
    expected_token = "6e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a2088ffff094b85d2d6ba9b42993f8d1cf585cd64d09be0632e1f303e3142a4421296683f055a1f816e7e414bf51389416659ff6ff32beee4b08d5d1ce299f43a448f6b9fb0"

    client = _send_token_for_signing(backend)

    navigate = blind_review(navigator, scenario_navigator, device, test_name)

    with client.sign_token_sign(PATH_STR_0, TOKEN_TIMESTAMP):
        navigate()

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1 + 100
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1:].hex() == expected_token

def test_sign_token_reject_blind(backend, navigator, device, test_name):
    client = _send_token_for_signing(backend)

    navigate = decline_blind_signing(navigator, device, test_name)

    with client.sign_token_sign(PATH_STR_0, TOKEN_TIMESTAMP):
        navigate()

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == R_REJECT

def test_sign_token_reject_tx(backend, navigator, scenario_navigator, device, test_name):
    client = _send_token_for_signing(backend)

    navigate = blind_review(navigator, scenario_navigator, device, test_name, approve=False)

    with client.sign_token_sign(PATH_STR_0, TOKEN_TIMESTAMP):
        navigate()

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == R_REJECT
