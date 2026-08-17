from constants import ROOT_SCREENSHOT_PATH
from ragger.navigator import NavInsID

# Validation instruction tails for touch devices (Stax/Flex), run on the last
# review page once "Hold to sign" is visible.
_TOUCH_APPROVE = [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
_TOUCH_REJECT = [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM,
                 NavInsID.USE_CASE_STATUS_DISMISS]

def _enable_blind_signing(navigator):
    # Nano only: toggle the blind-signing setting from the main menu.
    navigator.navigate([NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK,
                        NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK,
                        NavInsID.BOTH_CLICK], screen_change_before_first_instruction=False)

def _touch_blind_review(navigator, test_name, validation_instructions):
    # Touch review of a signing operation that requires blind signing: the app first
    # asks to enable the setting, then the SDK shows its blind-signing warning; from
    # there, paginate until the last review page and run the validation there.
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name,
                                   [NavInsID.USE_CASE_CHOICE_CONFIRM,  # enable blind signing
                                    NavInsID.USE_CASE_CHOICE_REJECT])  # "Continue anyway" on the warning
    navigator.navigate_until_text_and_compare(NavInsID.SWIPE_CENTER_TO_LEFT,
                                              validation_instructions,
                                              "^Hold to sign$",
                                              ROOT_SCREENSHOT_PATH, test_name,
                                              timeout=30,
                                              screen_change_before_first_instruction=False,
                                              snap_start_idx=2)

def blind_review(navigator, scenario_navigator, device, test_name, approve = True, nano_screen_text = None):
    # Returns the navigation callable for reviewing a signing operation that
    # requires blind signing. On nano the setting is enabled from the settings menu
    # up front (before the review is started); on touch devices the review itself
    # starts with the app's "enable blind signing?" choice.
    if device.is_nano:
        _enable_blind_signing(navigator)
        if approve:
            return lambda: scenario_navigator.review_approve(custom_screen_text=nano_screen_text)
        return scenario_navigator.review_reject
    return lambda: _touch_blind_review(navigator, test_name,
                                       _TOUCH_APPROVE if approve else _TOUCH_REJECT)

def decline_blind_signing(navigator, device, test_name):
    # Returns the navigation callable for declining the "enable blind signing?"
    # prompt, which aborts the signing operation.
    if device.is_nano:
        instructions = [NavInsID.BOTH_CLICK]                # "blind signing not enabled" screen
    else:
        instructions = [NavInsID.USE_CASE_CHOICE_REJECT,    # reject enabling blind signing
                        NavInsID.USE_CASE_STATUS_DISMISS]   # dismiss status screen
    return lambda: navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)
