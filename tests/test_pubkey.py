# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Public Key check
"""

from typing import List
import pytest

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from application_client.app_def import Errors
from application_client.command_sender import CommandSender
from application_client.command_builder import P1Type

from input_files.pubkey import PubKeyTestCase
from input_files.pubkey import rejectTestCases, testsShelleyUsualNoConfirm, testsCVoteKeysNoConfirm
from input_files.pubkey import byronTestCases, testsShelleyUsual, testsShelleyUnusual, testsColdKeys, testsCVoteKeys

from utils import idTestFunc, get_device_pubkey

@pytest.mark.parametrize(
    "testCase",
    byronTestCases + testsShelleyUsual + testsShelleyUnusual + testsColdKeys + testsCVoteKeys,
    ids=idTestFunc
)
def test_pubkey_confirm(firmware: Firmware,
                        backend: BackendInterface,
                        navigator: Navigator,
                        scenario_navigator: NavigateWithScenario,
                        testCase: PubKeyTestCase) -> None:
    """Check Public Key with confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    if firmware.is_nano:
        nav_inst = NavInsID.BOTH_CLICK
        if firmware == Firmware.NANOS:
            valid_instr = [NavInsID.RIGHT_CLICK]
        else:
            valid_instr = [NavInsID.BOTH_CLICK]

    # Send the APDU
    with client.get_pubkey_async(P1Type.P1_KEY_INIT, testCase.path):
        if testCase.nav:
            if firmware.is_nano:
                navigator.navigate_until_text(nav_inst, valid_instr, "Confirm")
            else:
                scenario_navigator.address_review_approve(do_comparison=False)
        else:
            pass
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Check the response
    _check_pubkey_result(response.data, testCase.path)


@pytest.mark.parametrize(
    "testCase",
    [
        (byronTestCases + testsShelleyUsual + testsColdKeys + testsCVoteKeys),
        (testsShelleyUnusual + byronTestCases + testsColdKeys + testsShelleyUsual),
    ],
)
def test_pubkey_several(firmware: Firmware,
                        backend: BackendInterface,
                        navigator: Navigator,
                        scenario_navigator: NavigateWithScenario,
                        testCase: List[PubKeyTestCase]) -> None:
    """Check Several Public Key with confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    if firmware.is_nano:
        nav_inst = NavInsID.BOTH_CLICK
        if firmware == Firmware.NANOS:
            valid_instr = [NavInsID.RIGHT_CLICK]
        else:
            valid_instr = [NavInsID.BOTH_CLICK]
    else:
        valid_instr = [NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM]
    p1 = P1Type.P1_KEY_INIT
    remainingKeysData = len(testCase) - 1
    for test in testCase:
        # Send the APDU
        with client.get_pubkey_async(p1, test.path, remainingKeysData):
            if p1 == P1Type.P1_KEY_INIT:
                navigator.navigate(valid_instr,
                                   screen_change_after_last_instruction=False)
            if test.nav_with_several:
                if firmware.is_nano:
                    navigator.navigate_until_text(nav_inst, valid_instr, "Confirm")
                else:
                    scenario_navigator.address_review_approve(do_comparison=False)
            else:
                pass
        # Check the status (Asynchronous)
        response = client.get_async_response()
        assert response and response.status == Errors.SW_SUCCESS

        # Check the response
        _check_pubkey_result(response.data, test.path)

        remainingKeysData = 0
        p1 = P1Type.P1_KEY_NEXT


@pytest.mark.parametrize(
    "testCase",
    testsShelleyUsualNoConfirm + testsCVoteKeysNoConfirm,
    ids=idTestFunc
)
def test_pubkey(backend: BackendInterface, testCase: PubKeyTestCase) -> None:
    """Check Public Key without confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Send the APDU
    response = client.get_pubkey(P1Type.P1_KEY_INIT, testCase.path)

    # Check the status
    assert response and response.status == Errors.SW_SUCCESS

    # Check the response
    _check_pubkey_result(response.data, testCase.path)


@pytest.mark.parametrize(
    "testCase",
    rejectTestCases,
    ids=idTestFunc
)
def test_pubkey_reject(backend: BackendInterface,
                       testCase: PubKeyTestCase) -> None:
    """Check Reject Public Key"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as err:
        # Send the APDU
        client.get_pubkey(P1Type.P1_KEY_INIT, testCase.path)
    assert err.value.status == Errors.SW_REJECTED_BY_POLICY


def _check_pubkey_result(data: bytes, path: str) -> None:
    ref_pk, ref_chaincode = get_device_pubkey(path)
    assert data.hex() == ref_pk.hex() + ref_chaincode
