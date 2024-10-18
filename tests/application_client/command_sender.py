# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command sending part.
"""

from typing import Generator, Optional

from ragger.backend.interface import BackendInterface, RAPDU

from application_client.command_builder import CommandBuilder
from application_client.app_def import Errors


class CommandSender:
    """Base class to send APDU to the selected backend"""

    def __init__(self, backend: BackendInterface) -> None:
        """Class initializer"""

        self._backend = backend
        self._firmware = backend.firmware
        self._cmd_builder = CommandBuilder()


    def _exchange(self, payload: bytes) -> RAPDU:
        """Synchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Response APDU
        """

        return self._backend.exchange_raw(payload)


    @contextmanager
    def _exchange_async(self, payload: bytes) -> Generator[None, None, None]:
        """Asynchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Generator
        """

        with self._backend.exchange_async_raw(payload):
            yield


    def get_async_response(self) -> Optional[RAPDU]:
        """Asynchronous APDU response

        Returns:
            Response APDU
        """

        return self._backend.last_async_response


    def send_raw(self, cla: int, ins: int, p1: int, p2: int, payload: bytes) -> RAPDU:
        header = bytearray()
        header.append(cla)
        header.append(ins)
        header.append(p1)
        header.append(p2)
        header.append(len(payload))
        return self._exchange(header + payload)


    def get_version(self) -> bytes:
        """APDU Get Version

        Returns:
            Version data
        """

        rapdu = self._exchange(self._cmd_builder.get_version())
        assert rapdu.status == Errors.SW_SUCCESS
        return rapdu.data


    def get_serial(self) -> bytes:
        """APDU Get Serial

        Returns:
            Serial data
        """

        rapdu = self._exchange(self._cmd_builder.get_serial())
        assert rapdu.status == Errors.SW_SUCCESS
        return rapdu.data

