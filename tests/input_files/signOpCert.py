# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Sign Operational Certificate
"""

from dataclasses import dataclass


@dataclass
class OperationalCertificateSignature:
    signatureHex: str

@dataclass
class operationalCertificate:
    kesPublicKeyHex: str
    kesPeriod: int
    issueCounter: int
    path: str

@dataclass
class OpCertTestCase:
    name: str
    opCert: operationalCertificate
    expected: OperationalCertificateSignature


# pylint: disable=line-too-long
opCertTestCases = [
    OpCertTestCase("Should correctly sign a basic operational certificate",
                   operationalCertificate("3d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822",
                                          47,
                                          42,
                                          "m/1853'/1815'/0'/0'"),
                   OperationalCertificateSignature("ce8d7cab55217ed17f1cceb8cb487dcbe6172fdb5794cc26f78c2f1d2495598e72beb6209f113562f9488ef6e81e3e8f758ea072c3cf9c17095868f2e9213f0a")
    )
]
