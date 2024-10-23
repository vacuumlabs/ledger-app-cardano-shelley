# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command building part.
"""

from enum import IntEnum
from typing import List

from ragger.bip import pack_derivation_path

from input_files.derive_address import DeriveAddressTestCase
from input_files.cvote import MAX_CIP36_PAYLOAD_SIZE, CVoteTestCase
from input_files.signOpCert import OpCertTestCase
from input_files.signMsg import SignMsgTestCase, MessageAddressFieldType

from application_client.app_def import InsType, AddressType, StakingDataSourceType


class P1Type(IntEnum):
    # Derive Address
    P1_RETURN = 0x01
    P1_DISPLAY = 0x02
    # Get Pub Key
    P1_KEY_INIT = 0x00
    P1_KEY_NEXT = 0x01
    # Sign CIP36 Vote
    P1_INIT = 0x01
    P1_CHUNK = 0x02
    P1_CONFIRM = 0x03
    P1_WITNESS = 0x04


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

        data = self._serializeAddressParams(testCase)
        return self._serialize(InsType.DERIVE_PUBLIC_ADDR, p1, 0x00, data)


    def get_pubkey(self, p1: P1Type, path: str, remainingKeysData: int = 0) -> bytes:
        """APDU Builder for Public Key

        Args:
            p1 (P1Type): APDU Parameter 1
            path (str): Test parameters
            remainingKeysData (int): Nb of remaining paths

        Returns:
            Response APDU
        """

        data = bytes()
        data += pack_derivation_path(path)
        if remainingKeysData > 0:
            data += remainingKeysData.to_bytes(4, "big")
        return self._serialize(InsType.GET_PUBLIC_ADDR, p1, 0x00, data)


    def sign_cip36_init(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Full length of voteCastDataHex (4B)
        #    voteCastDataHex (up to 240 B)
        data = bytes()
        # 2 hex chars per byte
        data_size = int(len(testCase.cVote.voteCastDataHex) / 2)
        chunk_size = min(MAX_CIP36_PAYLOAD_SIZE * 2, len(testCase.cVote.voteCastDataHex))
        data += data_size.to_bytes(4, "big")
        data += bytes.fromhex(testCase.cVote.voteCastDataHex[:chunk_size])
        # Remove the data sent in this step
        testCase.cVote.voteCastDataHex = testCase.cVote.voteCastDataHex[chunk_size:]
        return self._serialize(InsType.SIGN_CIP36_VOTE, P1Type.P1_INIT, 0x00, data)


    def sign_cip36_chunk(self, testCase: CVoteTestCase) -> List[bytes]:
        """APDU Builder for CIP36 Vote - CHUNK step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        # Serialization format:
        #    voteCastDataHex (following data, up to MAX_CIP36_PAYLOAD_SIZE B each)
        chunks = []
        payload = testCase.cVote.voteCastDataHex
        max_payload_size = MAX_CIP36_PAYLOAD_SIZE * 2 # 2 hex chars per byte
        while len(payload) > 0:
            chunks.append(self._serialize(InsType.SIGN_CIP36_VOTE,
                                          P1Type.P1_CHUNK,
                                          0x00,
                                          bytes.fromhex(payload[:max_payload_size])))
            payload = payload[max_payload_size:]

        return chunks


    def sign_cip36_confirm(self) -> bytes:
        """APDU Builder for CIP36 Vote - CONFIRM step

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_CIP36_VOTE, P1Type.P1_CONFIRM, 0x00)


    def sign_cip36_witness(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - WITNESS step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #     witness path (1B for length + [0-10] x 4B)
        return self._serialize(InsType.SIGN_CIP36_VOTE,
                               P1Type.P1_WITNESS,
                               0x00,
                               pack_derivation_path(testCase.cVote.witnessPath))


    def sign_opCert(self, testCase: OpCertTestCase) -> bytes:
        """APDU Builder for Sign Operational Certificate

        Args:
            testCase (OpCertTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        # kesPublicKeyHex hex string (32B)
        # kesPeriod (8B)
        # issueCounter (8B)
        # derivation path (1B for length + [0-10] x 4B)
        data = bytes()
        data += bytes.fromhex(testCase.opCert.kesPublicKeyHex)
        data += testCase.opCert.kesPeriod.to_bytes(8, "big")
        data += testCase.opCert.issueCounter.to_bytes(8, "big")
        data += pack_derivation_path(testCase.opCert.path)
        return self._serialize(InsType.SIGN_OP_CERT, 0x00, 0x00, data)


    def sign_msg_init(self, testCase: SignMsgTestCase) -> bytes:
        """APDU Builder for Sign Message - INIT step

        Args:
            testCase (SignMsgTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Full length of messageHex (4B)
        #    signingPath (1B for length + [0-10] x 4B)
        #    hashPayload (1B)
        #    isAscii display (1B)
        #    addressFieldType (1B)
        #    addressBuffer, if any
        data = bytes()
        # 2 hex chars per byte
        data_size = int(len(testCase.msgData.messageHex) / 2)
        data += data_size.to_bytes(4, "big")
        data += pack_derivation_path(testCase.msgData.signingPath)

        data += testCase.msgData.hashPayload.to_bytes(1, "big")
        data += testCase.msgData.isAscii.to_bytes(1, "big")
        data += testCase.msgData.addressFieldType.to_bytes(1, "big")
        if testCase.msgData.addressFieldType == MessageAddressFieldType.ADDRESS:
            assert testCase.msgData.addressDesc is not None
            data += self._serializeAddressParams(testCase.msgData.addressDesc)
        return self._serialize(InsType.SIGN_MSG, P1Type.P1_INIT, 0x00, data)


    def sign_msg_chunk(self, testCase: SignMsgTestCase) -> List[bytes]:
        """APDU Builder for Sign Message - CHUNK step

        Args:
            testCase (SignMsgTestCase): Test parameters

        Returns:
            Response APDU
        """

        MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE = 198 * 2
        MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE = 99 * 2
        MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE = 250 * 2
        # Serialization format:
        #    messageHex (up to MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE B each, started by the length)
        chunks = []
        if testCase.msgData.isAscii:
            firstChunkSize = MAX_CIP8_MSG_FIRST_CHUNK_ASCII_SIZE
        else:
            firstChunkSize = MAX_CIP8_MSG_FIRST_CHUNK_HEX_SIZE
        chunk_size = min(firstChunkSize, len(testCase.msgData.messageHex))
        payload = testCase.msgData.messageHex
        while True:
            data = bytes()
            data += int(chunk_size / 2).to_bytes(4, "big")
            data += bytes.fromhex(payload[:chunk_size])
            chunks.append(self._serialize(InsType.SIGN_MSG, P1Type.P1_CHUNK, 0x00, data))
            payload = payload[chunk_size:]
            chunk_size = min(MAX_CIP8_MSG_HIDDEN_CHUNK_SIZE, len(payload))
            if len(payload) == 0:
                break

        return chunks


    def sign_msg_confirm(self) -> bytes:
        """APDU Builder for Sign Message - CONFIRM step

        Returns:
            Serial data APDU
        """

        return self._serialize(InsType.SIGN_MSG, P1Type.P1_CONFIRM, 0x00)


    def _serializeAddressParams(self, testCase: DeriveAddressTestCase) -> bytes:
        """Serialize address parameters"""

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

        return data
