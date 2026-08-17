from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, ROOT_SCREENSHOT_PATH, PATH_STR_3
from ragger.navigator import NavInsID
from utils import get_nano_instructions

def show_address_test(backend, navigator, device, path, test_name):
    if device.is_nano:
        instructions = get_nano_instructions(1)
    else:
        instructions = [NavInsID.USE_CASE_REVIEW_TAP, NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM]

    client = ArdorCommandSender(backend)
    with client.show_address(path):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)

def test_show_address0(backend, navigator, device):
    show_address_test(backend, navigator, device, PATH_STR_0, "test_show_address0")

def test_show_address3(backend, navigator, device):
    show_address_test(backend, navigator, device, PATH_STR_3, "test_show_address3")
