# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Derive Native Script Hash check
"""

import pytest

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from application_client.app_def import Errors
from application_client.command_sender import CommandSender

from input_files.derive_native_script import ValidNativeScriptTestCases, ValidNativeScriptTestCase
from input_files.derive_native_script import NativeScript, NativeScriptType
from input_files.derive_native_script import NativeScriptParamsPubkey, NativeScriptHashDisplayFormat
from input_files.derive_native_script import NativeScriptParamsScripts, NativeScriptParamsNofK
from input_files.derive_native_script import InvalidScriptTestCases

from utils import idTestFunc


@pytest.mark.parametrize(
    "testCase",
    ValidNativeScriptTestCases,
    ids=idTestFunc
)
def test_derive_native_script_hash(firmware: Firmware,
                                   backend: BackendInterface,
                                   navigator: Navigator,
                                   scenario_navigator: NavigateWithScenario,
                                   testCase: ValidNativeScriptTestCase,
                                   appFlags: dict) -> None:
    """Check Derive Native Script Hash"""

    if appFlags['isAppXS']:
        pytest.skip("Operational Certificate is not supported by 'AppXS' version")

    if firmware.is_nano and testCase.nano_skip is True:
        pytest.skip("Not supported yet on Nano because Navigation should be reviewed")

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    _deriveNativeScriptHash_addScript(firmware, navigator, client, testCase.script, False)

    _deriveNativeScriptHash_finishWholeNativeScript(firmware, navigator, scenario_navigator, client, testCase)


def _deriveNativeScriptHash_addScript(firmware: Firmware,
                                      navigator: Navigator,
                                      client: CommandSender,
                                      script: NativeScript,
                                      complex_nav: bool) -> None:
    """Send the different add commands

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        script (NativeScript): The test case
        complex_nav (bool): The complex navigation flag
    """

    if script.type in [NativeScriptType.ALL, NativeScriptType.ANY, NativeScriptType.N_OF_K]:
        _deriveScriptHash_startComplexScript(firmware, navigator, client, script, complex_nav)
        assert isinstance(script.params, (NativeScriptParamsScripts, NativeScriptParamsNofK))
        for subscript in script.params.scripts:
            _deriveNativeScriptHash_addScript(firmware, navigator, client, subscript, True)
    else:
        _deriveNativeScriptHash_addSimpleScript(firmware, navigator, client, script, complex_nav)


def _deriveNativeScriptHash_addSimpleScript(firmware: Firmware,
                                            navigator: Navigator,
                                            client: CommandSender,
                                            script: NativeScript,
                                            complex_nav: bool) -> None:
    """Send the add command for a simple script

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        script (NativeScript): The script
        complex_nav (bool): The complex navigation flag
    """

    with client.derive_script_add_simple(script):
        moves = []
        if firmware.is_nano:
            if complex_nav:
                moves += [NavInsID.BOTH_CLICK]
            if complex_nav or script.type == NativeScriptType.PUBKEY_THIRD_PARTY:
                moves += [NavInsID.RIGHT_CLICK]
            moves += [NavInsID.BOTH_CLICK]
            navigator.navigate(moves)
        else:
            if complex_nav:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
            navigator.navigate(moves,
                               screen_change_before_first_instruction=False,
                               screen_change_after_last_instruction=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _deriveScriptHash_startComplexScript(firmware: Firmware,
                                         navigator: Navigator,
                                         client: CommandSender,
                                         script: NativeScript,
                                         complex_nav: bool) -> None:
    """Send the add command for a complex script

    Args:
        firmware (Firmware): The firmware version
        client (CommandSender): The command sender instance
        navigator (Navigator): The navigator instance
        script (NativeScript): The script
        complex_nav (bool): The complex navigation flag
    """

    with client.derive_script_add_complex(script):
        moves = []
        if firmware.is_nano:
            if complex_nav:
                moves += [NavInsID.BOTH_CLICK]
            if complex_nav or isinstance(script.params, NativeScriptParamsPubkey):
                moves += [NavInsID.RIGHT_CLICK]
            moves += [NavInsID.BOTH_CLICK]
        else:
            if complex_nav:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            moves += [NavInsID.SWIPE_CENTER_TO_LEFT]

        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _deriveNativeScriptHash_finishWholeNativeScript(firmware: Firmware,
                                                    navigator: Navigator,
                                                    scenario_navigator: NavigateWithScenario,
                                                    client: CommandSender,
                                                    testCase: ValidNativeScriptTestCase) -> None:
    """Send the finish command for the whole native script

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        testCase (ValidNativeScriptTestCase): The test case
    """

    with client.derive_script_finish(testCase.displayFormat):
        if firmware.is_nano:
            moves = []
            if testCase.script.type in (NativeScriptType.INVALID_BEFORE, NativeScriptType.INVALID_HEREAFTER):
                if testCase.script.params.slot > 1000:
                    moves += [NavInsID.RIGHT_CLICK]
            elif testCase.displayFormat != NativeScriptHashDisplayFormat.POLICY_ID and \
                not (testCase.script.type == NativeScriptType.N_OF_K and testCase.script.params.requiredCount > 0):
                moves += [NavInsID.RIGHT_CLICK]
            moves += [NavInsID.BOTH_CLICK]

            navigator.navigate(moves)
        else:
            scenario_navigator.address_review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS
    # Check the response
    assert response.data.hex() == testCase.expected.hash
    # TODO: Generate the payload and verify the signature


@pytest.mark.parametrize(
    "testCase",
    InvalidScriptTestCases,
    ids=idTestFunc
)
def test_derive_native_script_hash_reject(firmware: Firmware,
                backend: BackendInterface,
                navigator: Navigator,
                scenario_navigator: NavigateWithScenario,
                testCase: ValidNativeScriptTestCase,
                appFlags: dict) -> None:
    """Check Derive Native Script Hash Reject"""

    # TODO - Navigation should be set for each test case
    if firmware.is_nano:
        pytest.skip("Not supported yet on Nano because Navigation should be reviewed")

    with pytest.raises(ExceptionRAPDU) as err:
        # Send the APDU
        test_derive_native_script_hash(firmware, backend, navigator, scenario_navigator, testCase, appFlags)
    assert err.value.status == testCase.expected.sw
