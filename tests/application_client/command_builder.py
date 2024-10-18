# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command building part.
"""

from enum import IntEnum

from ragger.bip import pack_derivation_path

from input_files.derive_address import DeriveAddressTestCase
from application_client.app_def import InsType, AddressType, StakingDataSourceType


class P1Type(IntEnum):
    P1_RETURN = 0x01
    P1_DISPLAY = 0x02


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


    def derive_address(self, p1: P1Type, testCase: DeriveAddressTestCase) -> bytes:
        """APDU Builder for Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            testCase (DeriveAddressTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format (from the documentation):
        # address type 1B
        # if address type == BYRON
        #     protocol magic 4B
        # else
        #     network id 1B
        # payment public key derivation path (1B for length + [0-10] x 4B) or script hash 28B
        # staking choice 1B
        #     if NO_STAKING:
        #         nothing more
        #     if STAKING_KEY_PATH:
        #         staking public key derivation path (1B for length + [0-10] x 4B)
        #     if STAKING_KEY_HASH:
        #         stake key hash 28B
        #     if BLOCKCHAIN_POINTER:
        #         certificate blockchain pointer 3 x 4B

        data = bytes()
        data += testCase.addrType.to_bytes(1, "big")
        if testCase.addrType == AddressType.BYRON:
            data += testCase.netDesc.protocol.to_bytes(4, "big")
        else:
            data += testCase.netDesc.networkId.to_bytes(1, "big")

        if not testCase.spendingValue.startswith("m/"):
            data += bytes.fromhex(testCase.spendingValue)
        elif testCase.spendingValue:
            data += pack_derivation_path(testCase.spendingValue)

        if testCase.addrType in (AddressType.BYRON, AddressType.ENTERPRISE_KEY,
                        AddressType.ENTERPRISE_SCRIPT):
            staking = StakingDataSourceType.NONE
        elif testCase.addrType in (AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
                          AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
                          AddressType.REWARD_SCRIPT):
            staking = StakingDataSourceType.SCRIPT_HASH
        elif testCase.addrType in (AddressType.POINTER_KEY, AddressType.POINTER_SCRIPT):
            staking = StakingDataSourceType.BLOCKCHAIN_POINTER
        elif not testCase.stakingValue.startswith("m/"):
            staking = StakingDataSourceType.KEY_HASH
        else:
            staking = StakingDataSourceType.KEY_PATH
        data += staking.to_bytes(1, "big")


        if staking == StakingDataSourceType.KEY_PATH:
            data += pack_derivation_path(testCase.stakingValue)
        elif staking in (StakingDataSourceType.KEY_HASH,
                         StakingDataSourceType.SCRIPT_HASH,
                         StakingDataSourceType.BLOCKCHAIN_POINTER):
            data += bytes.fromhex(testCase.stakingValue)
        elif staking != StakingDataSourceType.NONE:
            raise NotImplementedError("Not implemented yet")

        return self._serialize(InsType.DERIVE_PUBLIC_ADDR, p1, 0x00, data)
