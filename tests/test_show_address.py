from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, ROOT_SCREENSHOT_PATH
from ragger.navigator import NavInsID


def test_show_address(backend, navigator, firmware):
    if firmware.device == 'nanos':
        num_screens = 2
    elif firmware.device == 'nanox':
        num_screens = 1
    else:
        assert False

    client = ArdorCommandSender(backend)
    with client.show_address(PATH_STR_0):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, "test_show_address", instructions=[NavInsID.RIGHT_CLICK] * num_screens + [NavInsID.BOTH_CLICK])