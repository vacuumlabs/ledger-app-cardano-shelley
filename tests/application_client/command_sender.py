# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests Client application.
It contains the command sending part.
"""

from typing import Generator, Optional
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU

from input_files.derive_address import DeriveAddressTestCase
from input_files.cvote import CVoteTestCase
from input_files.signOpCert import OpCertTestCase
from input_files.signMsg import SignMsgTestCase
from input_files.signTx import SignTxTestCase, TxInput, TxOutput, TxAuxiliaryData, TxAuxiliaryDataCIP36, CIP36VoteDelegation
from input_files.signTx import Withdrawal, Certificate, VoterVotes, AssetGroup, Token, RequiredSigner, Datum
from input_files.signTx import PoolRegistrationParams, PoolKey, Relay, PoolMetadataParams

from application_client.command_builder import CommandBuilder, P1Type, P2Type
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


    @contextmanager
    def derive_address_async(self, p1: P1Type, testCase: DeriveAddressTestCase) -> Generator[None, None, None]:
        """APDU Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            testCase (DeriveAddressTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.derive_address(p1, testCase)):
            yield


    def derive_address(self, p1: P1Type, testCase: DeriveAddressTestCase) -> RAPDU:
        """APDU Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            testCase (DeriveAddressTestCase): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.derive_address(p1, testCase))


    @contextmanager
    def get_pubkey_async(self, p1: P1Type, path: str, remainingKeysData: int = 0) -> Generator[None, None, None]:
        """APDU Get Public Key

        Args:
            p1 (P1Type): APDU Parameter 1
            path (str): Test parameters
            remainingKeysData (int): Nb of remaining paths

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.get_pubkey(p1, path, remainingKeysData)):
            yield


    def get_pubkey(self, p1: P1Type, path: str, remainingKeysData: int = 0) -> RAPDU:
        """APDU Get Public Key

        Args:
            p1 (P1Type): APDU Parameter 1
            path (str): Test parameters
            remainingKeysData (int): Nb of remaining paths

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.get_pubkey(p1, path, remainingKeysData))


    @contextmanager
    def sign_cip36_init(self, testCase: CVoteTestCase) -> Generator[None, None, None]:
        """APDU CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cip36_init(testCase)):
            yield


    def sign_cip36_chunk(self, testCase: CVoteTestCase) -> RAPDU:
        """APDU CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        chunks = self._cmd_builder.sign_cip36_chunk(testCase)
        for chunk in chunks[:-1]:
            resp = self._exchange(chunk)
            assert resp.status == Errors.SW_SUCCESS
        return self._exchange(chunks[-1])


    @contextmanager
    def sign_cip36_confirm(self) -> Generator[None, None, None]:
        """APDU CIP36 Vote - CONFIRM step

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cip36_confirm()):
            yield


    @contextmanager
    def sign_cip36_witness(self, testCase: CVoteTestCase) -> Generator[None, None, None]:
        """APDU CIP36 Vote - WITNESS step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cip36_witness(testCase)):
            yield


    @contextmanager
    def sign_opCert(self, testCase: OpCertTestCase) -> Generator[None, None, None]:
        """APDU Sign Operational Certificate

        Args:
            testCase (OpCertTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_opCert(testCase)):
            yield


    @contextmanager
    def sign_msg_init(self, testCase: SignMsgTestCase) -> Generator[None, None, None]:
        """APDU Sign Message - INIT step

        Args:
            testCase (SignMsgTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_msg_init(testCase)):
            yield


    @contextmanager
    def sign_msg_chunk(self, testCase: SignMsgTestCase) -> Generator[None, None, None]:
        """APDU Sign Message - INIT step

        Args:
            testCase (SignMsgTestCase): Test parameters

        Returns:
            Response APDU
        """

        chunks = self._cmd_builder.sign_msg_chunk(testCase)
        with self._exchange_async(chunks[0]):
            yield
        for chunk in chunks[1:]:
            resp = self._exchange(chunk)
            assert resp.status == Errors.SW_SUCCESS


    @contextmanager
    def sign_msg_confirm(self) -> Generator[None, None, None]:
        """APDU Sign Message - CONFIRM step

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_msg_confirm()):
            yield


    @contextmanager
    def sign_tx_init(self, testCase: SignTxTestCase, nbWitnessPaths: int) -> Generator[None, None, None]:
        """APDU Sign TX - INIT step

        Args:
            testCase (SignTxTestCase): Test parameters
            nbWitnessPaths (int): The number of unique witness paths

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_init(testCase, nbWitnessPaths)):
            yield


    @contextmanager
    def sign_tx_aux_data_serialize(self, auxData: TxAuxiliaryData) -> Generator[None, None, None]:
        """APDU Sign TX - AUX_DATA step - SERIALIZE mode

        Args:
            auxData (TxAuxiliaryData): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_aux_data_serialize(auxData)):
            yield


    def sign_tx_aux_data_init(self, auxData: TxAuxiliaryDataCIP36) -> RAPDU:
        """APDU Sign TX - AUX_DATA step - INIT mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_aux_data_init(auxData))


    @contextmanager
    def sign_tx_aux_data_vote_key(self, auxData: TxAuxiliaryDataCIP36) -> Generator[None, None, None]:
        """APDU Sign TX - AUX_DATA step - VOTE KEY mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_aux_data_vote_key(auxData)):
            yield


    @contextmanager
    def sign_tx_aux_data_delegation(self, delegation: CIP36VoteDelegation) -> Generator[None, None, None]:
        """APDU Sign TX - AUX_DATA step - DELEGATION mode

        Args:
            delegation (CIP36VoteDelegation): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_aux_data_delegation(delegation)):
            yield


    @contextmanager
    def sign_tx_aux_data_staking(self, auxData: TxAuxiliaryDataCIP36) -> Generator[None, None, None]:
        """APDU Sign TX - AUX_DATA step - STAKING mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_aux_data_staking(auxData)):
            yield


    @contextmanager
    def sign_tx_aux_data_payment(self, auxData: TxAuxiliaryDataCIP36) -> Generator[None, None, None]:
        """APDU Sign TX - AUX_DATA step - PAYMENT mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_aux_data_payment(auxData)):
            yield


    @contextmanager
    def sign_tx_aux_data_nonce(self, auxData: TxAuxiliaryDataCIP36) -> Generator[None, None, None]:
        """APDU Sign TX - AUX_DATA step - NONCE mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_aux_data_nonce(auxData)):
            yield


    def sign_tx_aux_data_voting_purpose(self, auxData: TxAuxiliaryDataCIP36) -> RAPDU:
        """APDU Sign TX - AUX_DATA step - VOTING PURPOSE mode

        Args:
            auxData (TxAuxiliaryDataCIP36): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_aux_data_voting_purpose(auxData))


    @contextmanager
    def sign_tx_aux_data_confirm(self) -> Generator[None, None, None]:
        """APDU Sign TX - AUX_DATA step - CONFIRM mode

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_aux_data_confirm()):
            yield


    def sign_tx_inputs(self, txInput: TxInput) -> RAPDU:
        """APDU Sign TX - INPUTS step

        Args:
            txInput (TxInput): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_inputs(txInput))


    @contextmanager
    def sign_tx_outputs_basic(self, txOutput: TxOutput) -> Generator[None, None, None]:
        """APDU Sign TX - OUTPUTS step - BASIC DATA level

        Args:
            txOutput (TxOutput): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_outputs_basic(txOutput)):
            yield


    def sign_tx_outputs_datum(self, datum: Datum) -> RAPDU:
        """APDU Sign TX - OUTPUTS step - DATUM level

        Args:
            datum (Datum): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_outputs_datum(datum))


    def sign_tx_outputs_ref_script(self, referenceScriptHex: str) -> RAPDU:
        """APDU Sign TX - OUTPUTS step - REFERENCE SCRIPT level

        Args:
            referenceScriptHex (str): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_outputs_ref_script(referenceScriptHex))


    def sign_tx_outputs_chunk(self, p2: P2Type, chunkHex: str) -> RAPDU:
        """APDU Sign TX - OUTPUTS step - xxx CHUNKS level

        Args:
            p2 (P2Type): APDU Parameter 2
            chunkHex (str): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_outputs_chunk(p2, chunkHex))


    @contextmanager
    def sign_tx_outputs_confirm(self) -> Generator[None, None, None]:
        """APDU Sign TX - OUTPUTS step -CONFIRM level

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_outputs_confirm()):
            yield


    @contextmanager
    def sign_tx_fee(self, testCase: SignTxTestCase) -> Generator[None, None, None]:
        """APDU Sign TX - FEE step

        Args:
            testCase (SignTxTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_fee(testCase)):
            yield


    def sign_tx_ttl(self, testCase: SignTxTestCase) -> RAPDU:
        """APDU Sign TX - TTL step

        Args:
            testCase (SignTxTestCase): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_ttl(testCase))


    @contextmanager
    def sign_tx_withdrawal(self, withdrawal: Withdrawal) -> Generator[None, None, None]:
        """APDU Sign TX - WITNESS step

        Args:
            withdrawal (Withdrawal): Input Test path

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_withdrawal(withdrawal)):
            yield


    def sign_tx_validity(self, validity: int) -> RAPDU:
        """APDU Sign TX - VALIDITY START step

        Args:
            validity (int): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_validity(validity))


    def sign_tx_script_data_hash(self, script: str) -> RAPDU:
        """APDU Sign TX - SCRIPT DATA HASH step

        Args:
            script (str): Input Test script data hash

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_script_data_hash(script))


    @contextmanager
    def sign_tx_mint_init(self, nbMints: int) -> Generator[None, None, None]:
        """APDU Sign TX - MINT step - INIT mode

        Args:
            nbMints (int): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_mint_init(nbMints)):
            yield


    @contextmanager
    def sign_tx_mint_confirm(self,) -> Generator[None, None, None]:
        """APDU Sign TX - MINT step - CONFIRM mode

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_mint_confirm()):
            yield


    @contextmanager
    def sign_tx_asset_group(self, p1: P1Type, asset: AssetGroup) -> Generator[None, None, None]:
        """APDU Sign TX - TOKEN BUNDLE step - ASSET mode

        Args:
            p1 (P1Type): APDU Parameter 1
            token (AssetGroup): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_asset_group(p1, asset)):
            yield


    @contextmanager
    def sign_tx_token(self, p1: P1Type, token: Token) -> Generator[None, None, None]:
        """APDU Sign TX - TOKEN BUNDLE step - TOKEN mode

        Args:
            p1 (P1Type): APDU Parameter 1
            asset (AssetGroup): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_token(p1, token)):
            yield


    @contextmanager
    def sign_tx_voting_procedure(self, votingProcedure: VoterVotes) -> Generator[None, None, None]:
        """APDU Sign TX - VOTING PROCEDURES step

        Args:
            votingProcedure (VoterVotes): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_voting_procedure(votingProcedure)):
            yield


    @contextmanager
    def sign_tx_treasury(self, treasury: int) -> Generator[None, None, None]:
        """APDU Sign TX - TREASURY step

        Args:
            treasury (int): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_treasury(treasury)):
            yield


    @contextmanager
    def sign_tx_donation(self, donation: int) -> Generator[None, None, None]:
        """APDU Sign TX - DONATION step

        Args:
            donation (int): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_donation(donation)):
            yield


    def sign_tx_collateral_inputs(self, txInput: TxInput) -> RAPDU:
        """APDU Sign TX - COLLATERAL INPUTS step

        Args:
            txInput (TxInput): Input Test data

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_collateral_inputs(txInput))


    @contextmanager
    def sign_tx_collateral_output_basic(self, txOutput: TxOutput) -> Generator[None, None, None]:
        """APDU Sign TX - COLLATERAL OUTPUTS step - BASIC DATA level

        Args:
            txOutput (TxOutput): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_collateral_output_basic(txOutput)):
            yield


    @contextmanager
    def sign_tx_collateral_output_confirm(self) -> Generator[None, None, None]:
        """APDU Sign TX - COLLATERAL OUTPUTS step - CONFIRM level

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_collateral_output_confirm()):
            yield


    @contextmanager
    def sign_tx_total_collateral(self, total: int) -> Generator[None, None, None]:
        """APDU Sign TX - TOTAL COLLATERAL step

        Args:
            total (int): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_total_collateral(total)):
            yield


    def sign_tx_reference_inputs(self, txInput: TxInput) -> RAPDU:
        """APDU Sign TX - REFERENCE INPUTS step

        Args:
            txInput (TxInput): Input Test data

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_reference_inputs(txInput))


    def sign_tx_required_signers(self, signer: RequiredSigner) -> RAPDU:
        """APDU Sign TX - REQUIRED SIGNERS step

        Args:
            signer (RequiredSigner): Input Test data

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_required_signers(signer))


    @contextmanager
    def sign_tx_certificate(self, certificate: Certificate) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step

        Args:
            withdrawal (Withdrawal): Input Test path

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_certificate(certificate)):
            yield


    @contextmanager
    def sign_tx_cert_pool_reg_init(self, pool: PoolRegistrationParams) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - POOL INITIAL PARAMS level

        Args:
            pool (PoolRegistrationParams): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_init(pool)):
            yield


    def sign_tx_cert_pool_reg_pool_key(self, pool: PoolKey) -> RAPDU:
        """APDU Sign TX - CERTIFICATE step - POOL KEY level

        Args:
            pool (PoolKey): Input Test data

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.sign_tx_cert_pool_reg_pool_key(pool))


    @contextmanager
    def sign_tx_cert_pool_reg_vrf(self, pool: str) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - VRF level

        Args:
            pool (str): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_vrf(pool)):
            yield


    @contextmanager
    def sign_tx_cert_pool_reg_financials(self, pool: PoolRegistrationParams) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - FINANCIALS level

        Args:
            pool (PoolRegistrationParams): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_financials(pool)):
            yield


    @contextmanager
    def sign_tx_cert_pool_reg_reward(self, pool: PoolKey) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - REWARD ACCOUNT level

        Args:
            pool (PoolKey): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_reward(pool)):
            yield


    @contextmanager
    def sign_tx_cert_pool_reg_owner(self, pool: PoolKey) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - POOL OWNER level

        Args:
            pool (PoolKey): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_owner(pool)):
            yield


    @contextmanager
    def sign_tx_cert_pool_reg_relay(self, pool: Relay) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - POOL RELAY level

        Args:
            pool (Relay): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_relay(pool)):
            yield


    @contextmanager
    def sign_tx_cert_pool_reg_metadata(self, pool: PoolMetadataParams) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - POOL METADATA level

        Args:
            pool (PoolMetadataParams): Input Test data

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_metadata(pool)):
            yield


    @contextmanager
    def sign_tx_cert_pool_reg_confirm(self) -> Generator[None, None, None]:
        """APDU Sign TX - CERTIFICATE step - CONFIRM level

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_cert_pool_reg_confirm()):
            yield


    @contextmanager
    def sign_tx_confirm(self) -> Generator[None, None, None]:
        """APDU Sign TX - CONFIRM step

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_confirm()):
            yield


    @contextmanager
    def sign_tx_witness(self, path: str) -> Generator[None, None, None]:
        """APDU Sign TX - WITNESS step

        Args:
            path (str): Input Test path

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_witness(path)):
            yield
