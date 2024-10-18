# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the application definitions.
"""
from enum import IntEnum


class Errors(IntEnum):
    """Application Errors definitions"""

    SW_MALFORMED_REQUEST_HEADER   = 0x6E01
    SW_BAD_CLA                    = 0x6E02
    SW_UNKNOWN_INS                = 0x6E03
    SW_STILL_IN_CALL              = 0x6E04
    SW_INVALID_REQUEST_PARAMETERS = 0x6E05
    SW_INVALID_STATE              = 0x6E06
    SW_INVALID_DATA               = 0x6E07
    SW_REJECTED_BY_USER           = 0x6E09
    SW_REJECTED_BY_POLICY         = 0x6E10
    SW_DEVICE_LOCKED              = 0x6E11
    SW_SWAP_CHECKING_FAIL         = 0x6E13
    SW_SUCCESS                    = 0x9000


class InsType(IntEnum):
    GET_VERSION = 0x00
    GET_SERIAL = 0x01
    GET_PUBLIC_ADDR = 0x10
    DERIVE_PUBLIC_ADDR = 0x11
    DERIVE_SCRIPT_HASH = 0x12
    SIGN_TX = 0x21
    SIGN_OP_CERT = 0x22
    SIGN_CIP36_VOTE = 0x23
    SIGN_MSG = 0x24

