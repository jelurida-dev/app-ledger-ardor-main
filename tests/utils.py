from ragger.navigator import NavInsID

def enable_blind_signing(navigator):
    navigator.navigate([NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK,
                        NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK, 
                        NavInsID.BOTH_CLICK], screen_change_before_first_instruction=False)

def get_nano_instructions(num_screens: int):
    return [NavInsID.RIGHT_CLICK] * num_screens + [NavInsID.BOTH_CLICK]

def get_stax_instructions(num_taps: int):
    return [NavInsID.USE_CASE_REVIEW_TAP] * num_taps + [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]

def get_accept_instructions(device, num_taps: int, num_screens: int):
    if device.is_nano:
        return get_nano_instructions(num_screens)
    return get_stax_instructions(num_taps)