# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command building part.
"""

from application_client.app_def import InsType


class CommandBuilder:
    _CLA: int = 0xd7

    def _serialize(self,
                   ins: InsType,
                   p1: int = 0x00,
                   p2: int = 0x00,
                   cdata: bytes = bytes()) -> bytes:

        header = bytearray()
        header.append(self._CLA)
        header.append(ins)
        header.append(p1)
        header.append(p2)
        header.append(len(cdata))
        return header + cdata


    def get_version(self) -> bytes:
        """APDU Builder for App version"""

        return self._serialize(InsType.GET_VERSION)


    def get_serial(self) -> bytes:
        """APDU Builder for App serial"""

        return self._serialize(InsType.GET_SERIAL)
