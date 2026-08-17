from ragger.navigator import NavInsID

def enable_blind_signing(navigator):
    navigator.navigate([NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK,
                        NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK,
                        NavInsID.BOTH_CLICK], screen_change_before_first_instruction=False)

def get_nano_instructions(num_screens: int):
    return [NavInsID.RIGHT_CLICK] * num_screens + [NavInsID.BOTH_CLICK]

def get_touch_instructions(device, num_taps: int, num_taps_flex: int = None):
    # The Flex screen fits fewer tag-value pairs per page than the Stax, so some
    # reviews need an extra tap; pass num_taps_flex for those.
    if device.name == "flex" and num_taps_flex is not None:
        num_taps = num_taps_flex
    return [NavInsID.USE_CASE_REVIEW_TAP] * num_taps + [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]

def get_accept_instructions(device, num_taps: int, num_screens: int, num_taps_flex: int = None):
    if device.is_nano:
        return get_nano_instructions(num_screens)
    return get_touch_instructions(device, num_taps, num_taps_flex)
