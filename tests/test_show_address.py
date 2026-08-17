from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, PATH_STR_3

def show_address_test(backend, scenario_navigator, device, path):
    client = ArdorCommandSender(backend)
    with client.show_address(path):
        # The nano flow ends on a "Done" screen instead of a standard approval label
        scenario_navigator.address_review_approve(
            custom_screen_text="^Done$" if device.is_nano else None)

def test_show_address0(backend, scenario_navigator, device):
    show_address_test(backend, scenario_navigator, device, PATH_STR_0)

def test_show_address3(backend, scenario_navigator, device):
    show_address_test(backend, scenario_navigator, device, PATH_STR_3)
