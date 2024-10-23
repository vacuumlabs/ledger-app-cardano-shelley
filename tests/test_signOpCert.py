# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Operational Certificate check
"""

import pytest

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.app_def import Errors
from application_client.command_sender import CommandSender

from input_files.signOpCert import opCertTestCases, OpCertTestCase

from utils import idTestFunc, verify_signature


@pytest.mark.parametrize(
    "testCase",
    opCertTestCases,
    ids=idTestFunc
)
def test_opCert(firmware: Firmware,
                backend: BackendInterface,
                navigator: Navigator,
                scenario_navigator: NavigateWithScenario,
                testCase: OpCertTestCase,
                appFlags: dict) -> None:
    """Check Sign Operational Certificate"""

    if appFlags['isAppXS']:
        pytest.skip("Operational Certificate is not supported by 'AppXS' version")

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    if firmware.is_nano:
        moves = []
        moves += [NavInsID.BOTH_CLICK] * 2
        moves += [NavInsID.RIGHT_CLICK]
        moves += [NavInsID.BOTH_CLICK]
        moves += [NavInsID.RIGHT_CLICK]
        moves += [NavInsID.BOTH_CLICK]
        moves += [NavInsID.BOTH_CLICK] * 3

    # Send the INIT APDU
    with client.sign_opCert(testCase):
        if firmware.is_nano:
            navigator.navigate(moves)
        else:
            scenario_navigator.review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    # Check the response
    assert response.data.hex() == testCase.expected.signatureHex

    msg = bytes()
    msg += bytes.fromhex(testCase.opCert.kesPublicKeyHex)
    msg += testCase.opCert.issueCounter.to_bytes(8, 'big')
    msg += testCase.opCert.kesPeriod.to_bytes(8, 'big')

    verify_signature(testCase.opCert.path, response.data, msg)
