# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Public Key check
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class PubKeyTestCase:
    name: str
    path: str
    nav: Optional[bool] = True
    nav_with_several: Optional[bool] = True


# pylint: disable=line-too-long
byronTestCases = [
    PubKeyTestCase("byron/path 1",
                   "m/44'/1815'/1'", nav_with_several=False),
    PubKeyTestCase("byron/path 2",
                   "m/44'/1815'/1'/0/55'"),
    PubKeyTestCase("byron/path 3",
                   "m/44'/1815'/1'/0/12'"),
]

testsShelleyUsualNoConfirm = [
    PubKeyTestCase("shelley usual no confirm",
                   "m/1852'/1815'/4'"),
]

testsShelleyUsual = [
    PubKeyTestCase("shelley usual/path 0",
                   "m/1852'/1815'/4'",
                   False,
                   False),
    PubKeyTestCase("shelley usual/path 1",
                   "m/1852'/1815'/0'/0/1",
                   nav_with_several=False),
    PubKeyTestCase("shelley usual/path 2",
                   "m/1852'/1815'/0'/2/0",
                   nav_with_several=False),
    PubKeyTestCase("shelley usual/path 3",
                   "m/1852'/1815'/0'/2/1001",
                   nav_with_several=False),
    PubKeyTestCase("shelley usual/path 4",
                   "m/1852'/1815'/0'/3/0",
                   nav_with_several=False),
    PubKeyTestCase("shelley usual/path 5",
                   "m/1852'/1815'/0'/4/0",
                   nav_with_several=False),
    PubKeyTestCase("shelley usual/path 6",
                   "m/1852'/1815'/1'/5/0",
                   nav_with_several=False),
]

testsShelleyUnusual = [
    PubKeyTestCase("shelley unusual/path 1",
                   "m/1852'/1815'/101'"),
    PubKeyTestCase("shelley unusual/path 2",
                   "m/1852'/1815'/100'/0/1000001'"),
    PubKeyTestCase("shelley unusual/path 3",
                   "m/1852'/1815'/0'/2/1000001"),
    PubKeyTestCase("shelley unusual/path 4",
                   "m/1852'/1815'/101'/3/0"),
    PubKeyTestCase("shelley unusual/path 5",
                   "m/1852'/1815'/101'/4/0"),
    PubKeyTestCase("shelley unusual/path 6",
                   "m/1852'/1815'/101'/5/0"),
]

testsColdKeys = [
     PubKeyTestCase("cold case",
                    "m/1853'/1815'/0'/0'"),
]

testsCVoteKeysNoConfirm = [
    PubKeyTestCase("CVote keys/path 2",
                   "m/1694'/1815'/100'"),
]

testsCVoteKeys = [
    PubKeyTestCase("CVote keys/path 1",
                   "m/1694'/1815'/0'/0/1",
                   nav_with_several=False),
    PubKeyTestCase("CVote keys/path 2",
                   "m/1694'/1815'/100'",
                   False,
                   False),
    PubKeyTestCase("CVote keys/path 3",
                   "m/1694'/1815'/101'",
                   nav_with_several=True),
]

rejectTestCases = [
    PubKeyTestCase("path shorter than 3 indexes",
                   "m/44'/1815'"),
    PubKeyTestCase("path not matching cold key structure",
                   "m/1853'/1900'/0'/0/0"),
    PubKeyTestCase("invalid vote key path 1",
                   "m/1694'/1815'/0'/1/0"),
    PubKeyTestCase("invalid vote key path 2",
                   "m/1694'/1815'/17"),
    PubKeyTestCase("invalid vote key path 3",
                   "m/1694'/1815'/0'/1"),
]
