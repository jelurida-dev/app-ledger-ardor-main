from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, PATH_STR_3

def show_address_test(backend, scenario_navigator, path):
    client = ArdorCommandSender(backend)
    with client.show_address(path):
        scenario_navigator.address_review_approve()

def test_show_address0(backend, scenario_navigator):
    show_address_test(backend, scenario_navigator, PATH_STR_0)

def test_show_address3(backend, scenario_navigator):
    show_address_test(backend, scenario_navigator, PATH_STR_3)
