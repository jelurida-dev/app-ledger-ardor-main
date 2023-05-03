from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, ROOT_SCREENSHOT_PATH, PATH_STR_3
from ragger.navigator import NavInsID

def show_address_test(backend, navigator, firmware, path, test_name):
    if firmware.device == 'nanos':
        num_screens = 2
    elif firmware.device == 'nanox':
        num_screens = 1
    elif firmware.device == 'nanosp':
        num_screens = 1
    else:
        assert False

    client = ArdorCommandSender(backend)
    with client.show_address(path):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions=[NavInsID.RIGHT_CLICK] * num_screens + [NavInsID.BOTH_CLICK])

def test_show_address0(backend, navigator, firmware):
    show_address_test(backend, navigator, firmware, PATH_STR_0, "test_show_address0")

def test_show_address3(backend, navigator, firmware):
    show_address_test(backend, navigator, firmware, PATH_STR_3, "test_show_address3")