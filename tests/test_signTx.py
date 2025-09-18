# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Sign TX check
"""

from typing import List, Tuple
import pytest

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from application_client.app_def import Errors, NetworkIds
from application_client.command_sender import CommandSender
from application_client.command_builder import P1Type, P2Type

from input_files.derive_address import AddressType
from input_files.signTx import MAX_SIGN_TX_CHUNK_SIZE, SignTxTestCase, DeriveAddressTestCase, ThirdPartyAddressParams
from input_files.signTx import AssetGroup, TxAuxiliaryDataCIP36, TxOutputBabbage
from input_files.signTx import CertificateType, CredentialParamsType, DRepParamsType, VoterType, TxOutputDestinationType
from input_files.signTx import TxAuxiliaryDataType, CIP36VoteDelegationType, TransactionSigningMode, DatumType
from input_files.signTx import DRepUpdateParams, DRepRegistrationParams, StakeRegistrationConwayParams
from input_files.signTx import ResignCommitteeParams, AuthorizeCommitteeParams, VoteDelegationParams
from input_files.signTx import testsByron, testsShelleyNoCertificates, testsShelleyWithCertificates
from input_files.signTx import testsConwayWithCertificates, testsMultisig, testsAllegra, testsMary
from input_files.signTx import testsAlonzoTrezorComparison, testsBabbageTrezorComparison
from input_files.signTx import testsMultidelegation, testsConwayWithoutCertificates, testsConwayVotingProcedures
from input_files.signTx import testsCatalystRegistration, testsCVoteRegistrationCIP36, testsAlonzo, testsBabbage
from input_files.signTx import poolRegistrationOwnerTestCases, poolRegistrationOperatorTestCases
from input_files.signTx import transactionInitRejectTestCases, addressParamsRejectTestCases, certificateStakingRejectTestCases
from input_files.signTx import withdrawalRejectTestCases, witnessRejectTestCases, testsInvalidTokenBundleOrdering
from input_files.signTx import singleAccountRejectTestCases, collateralOutputRejectTestCases, testsCVoteRegistrationRejects
from input_files.signTx import certificateRejectTestCases, certificateStakePoolRetirementRejectTestCases
from input_files.signTx import poolRegistrationOwnerRejectTestCases, invalidCertificates, invalidPoolMetadataTestCases
from input_files.signTx import invalidRelayTestCases, stakePoolRegistrationPoolIdRejectTestCases
from input_files.signTx import stakePoolRegistrationOwnerRejectTestCases, outputRejectTestCases
from utils import idTestFunc, verify_signature


@pytest.mark.parametrize(
    "testCase",
    testsByron + testsShelleyNoCertificates + testsShelleyWithCertificates + \
    testsConwayWithCertificates + testsMultisig + testsAllegra + testsMary + \
    testsAlonzoTrezorComparison + testsBabbageTrezorComparison + \
    testsMultidelegation + testsConwayWithoutCertificates + testsConwayVotingProcedures + \
    testsCatalystRegistration + testsCVoteRegistrationCIP36 + testsAlonzo + testsBabbage + \
    poolRegistrationOwnerTestCases + poolRegistrationOperatorTestCases,
    ids=idTestFunc
)
def test_signTx(firmware: Firmware,
                backend: BackendInterface,
                navigator: Navigator,
                scenario_navigator: NavigateWithScenario,
                testCase: SignTxTestCase,
                appFlags: dict) -> None:
    """Check Sign TX"""

    pytest.skip("TODO - Navigation DO NOT WORK ANY MORE")

    if appFlags['isAppXS']:
        pytest.skip("Not supported by 'AppXS' version")

    if firmware.is_nano and testCase.nano_skip is True:
        pytest.skip("Not supported yet on Nano because Navigation should be reviewed")

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    witnessPaths = _gatherWitnessPaths(testCase)

    # Send the INIT APDU
    _signTx_init(firmware, navigator, client, testCase, len(witnessPaths))

    # Send the AUX DATA APDU
    auxData: bool = _signTx_setAuxiliaryData(firmware, navigator, scenario_navigator, client, testCase)

    # Send the INPUTS APDUs
    _signTx_addInput(client, testCase)

    # Send the OUTPUTS APDUs
    _signTx_addOutputs(firmware, navigator, scenario_navigator, client, testCase, auxData)

    # Send the FEE APDU
    _signTx_setFee(firmware, navigator, client, testCase)

    # Send the TTL APDU
    _signTx_setTtl(client, testCase)

    # Send the CERTIFICATES APDUs
    _signTx_setCertificates(firmware, navigator, scenario_navigator, client, testCase)

    # Send the WITHDRAWALS APDUs
    _signTx_setWithdrawals(client, testCase)

    # Send the VALIDITY START APDU
    _signTx_setValidityIntervalStart(client, testCase)

    # Send the MINT APDU
    _signTx_setMint(firmware, navigator, scenario_navigator, client, testCase)

    # Send the SCRIPT DATA HASH APDU
    _signTx_setScriptDataHash(client, testCase)

    # Send the COLLATERAL INPUTS APDU
    _signTx_addCollateralInputs(client, testCase)

    # Send the REQUIRED SIGNERS APDU
    _signTx_addRequiredSigners(client, testCase)

     # Send the COLLATERAL OUTPUTS APDU
    _signTx_addCollateralOutputs(firmware, navigator, scenario_navigator, client, testCase)

    # Send the TOTAL COLLATERAL APDU
    _signTx_addTotalCollateral(firmware, navigator, client, testCase)

    # Send the REFERENCE INPUTS APDU
    _signTx_addReferenceInputs(client, testCase)

    # Send the VOTING PROCEDURES APDUs
    _signTx_addVoterVotes(firmware, navigator, scenario_navigator, client, testCase)

    # Send the TREASURY APDU
    _signTx_addTreasury(firmware, navigator, client, testCase)

    # Send the DONATION APDU
    _signTx_addDonation(firmware, navigator, client, testCase)

    # Send the CONFIRM APDU
    data = _signTx_confirm(firmware, navigator, scenario_navigator, client, testCase.signingMode)

    # Send the WITNESS APDUs
    signatures = _signTx_setWitnesses(firmware, navigator, scenario_navigator, client, testCase, witnessPaths, auxData)

    # Check the signatures validity
    for path, sig in signatures:
        verify_signature(path, sig, data)


def _signTx_init(firmware: Firmware,
                 navigator: Navigator,
                 client: CommandSender,
                 testCase: SignTxTestCase,
                 nbWitnessPaths: int) -> None:
    """Sign TX INIT

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
        nbWitnessPaths (int): The number of unique witness paths
    """
    moves = []
    if firmware.is_nano:
        moves += [NavInsID.BOTH_CLICK]
        if testCase.tx.network.networkId == NetworkIds.TESTNET:
            moves += [NavInsID.BOTH_CLICK]
        if len(testCase.tx.outputs) == 0 and testCase.tx.scriptDataHash is None:
            moves += [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK]
        if testCase.signingMode == TransactionSigningMode.PLUTUS_TRANSACTION:
            moves += [NavInsID.BOTH_CLICK]
            if testCase.tx.scriptDataHash is None:
                moves += [NavInsID.BOTH_CLICK] * 2
    else:
        moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
        if len(testCase.tx.outputs) == 0:
            moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
        if testCase.signingMode == TransactionSigningMode.PLUTUS_TRANSACTION:
            moves += [NavInsID.SWIPE_CENTER_TO_LEFT] * 3
    with client.sign_tx_init(testCase, nbWitnessPaths):
        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _signTx_setAuxiliaryData(firmware: Firmware,
                             navigator: Navigator,
                             scenario_navigator: NavigateWithScenario,
                             client: CommandSender,
                             testCase: SignTxTestCase) -> bool:
    """Sign TX Set AUX DATA

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case

    Returns:
        bool: True if the auxiliary data is set, False otherwise
    """

    if testCase.tx.auxiliaryData is None:
        return False
    with client.sign_tx_aux_data_serialize(testCase.tx.auxiliaryData):
        if testCase.tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
            if firmware.is_nano:
                moves = [NavInsID.BOTH_CLICK]
            else:
                moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
            navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS
    if testCase.tx.auxiliaryData.type == TxAuxiliaryDataType.ARBITRARY_HASH:
        return True

    assert isinstance(testCase.tx.auxiliaryData.params, TxAuxiliaryDataCIP36)
    response = client.sign_tx_aux_data_init(testCase.tx.auxiliaryData.params)
    # Check the status
    assert response.status == Errors.SW_SUCCESS

    if testCase.tx.auxiliaryData.params.voteKey:
        if firmware.is_nano:
            moves = [NavInsID.RIGHT_CLICK]
            moves += [NavInsID.BOTH_CLICK]
        else:
            moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
        with client.sign_tx_aux_data_vote_key(testCase.tx.auxiliaryData.params):
            navigator.navigate(moves)
        # Check the status (Asynchronous)
        response = client.get_async_response()
        assert response and response.status == Errors.SW_SUCCESS
    elif testCase.tx.auxiliaryData.params.delegations:
        for delegation in testCase.tx.auxiliaryData.params.delegations:
            if firmware.is_nano:
                moves = [NavInsID.RIGHT_CLICK]
                moves += [NavInsID.BOTH_CLICK]
            else:
                moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
                if delegation.type == CIP36VoteDelegationType.PATH:
                    moves += [NavInsID.TAPPABLE_CENTER_TAP]
            with client.sign_tx_aux_data_delegation(delegation):
                navigator.navigate(moves)
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS

    with client.sign_tx_aux_data_staking(testCase.tx.auxiliaryData.params):
        if firmware.is_nano:
            moves = [NavInsID.BOTH_CLICK]
        else:
            moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    if firmware.is_nano:
        moves = [NavInsID.RIGHT_CLICK]
        moves += [NavInsID.BOTH_CLICK]
    else:
        moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
        if testCase.tx.validityIntervalStart is None:
            moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
        if testCase.tx.auxiliaryData.params.paymentDestination.type == TxOutputDestinationType.THIRD_PARTY:
            moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
    with client.sign_tx_aux_data_payment(testCase.tx.auxiliaryData.params):
        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    with client.sign_tx_aux_data_nonce(testCase.tx.auxiliaryData.params):
        if firmware.is_nano:
            moves = [NavInsID.BOTH_CLICK]
        else:
            moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    response = client.sign_tx_aux_data_voting_purpose(testCase.tx.auxiliaryData.params)
    # Check the status
    assert response.status == Errors.SW_SUCCESS

    with client.sign_tx_aux_data_confirm():
        if firmware.is_nano:
            navigator.navigate([NavInsID.BOTH_CLICK], screen_change_after_last_instruction=False)
        else:
            scenario_navigator.address_review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    return True


def _signTx_addInput(client: CommandSender,
                     testCase: SignTxTestCase) -> None:
    """Sign TX Add INPUTS

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    for txInput in testCase.tx.inputs:
        response = client.sign_tx_inputs(txInput)
        # Check the status
        assert response.status == Errors.SW_SUCCESS


def _signTx_addOutputs(firmware: Firmware,
                       navigator: Navigator,
                       scenario_navigator: NavigateWithScenario,
                       client: CommandSender,
                       testCase: SignTxTestCase,
                       auxData: bool) -> None:
    """Sign TX Add OUTPUTS

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
        auxData (bool): True if the auxiliary data is set, False otherwise
    """

    for txOutput in testCase.tx.outputs:
        # Send Basic DATA
        moves = []
        if testCase.txBody == "":
            pass
        elif testCase.tx.auxiliaryData is not None and \
            testCase.tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
            pass
        elif isinstance(txOutput.destination.params, ThirdPartyAddressParams):
            if firmware.is_nano:
                if testCase.signingMode == TransactionSigningMode.MULTISIG_TRANSACTION and \
                    len(testCase.tx.certificates) == 0 and len(testCase.tx.withdrawals) == 0:
                    moves += [NavInsID.RIGHT_CLICK]
                if testCase.signingMode != TransactionSigningMode.POOL_REGISTRATION_AS_OWNER:
                    moves += [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2
                if testCase.signingMode == TransactionSigningMode.MULTISIG_TRANSACTION and \
                    len(testCase.tx.certificates) == 0 and len(testCase.tx.withdrawals) == 0:
                    moves += [NavInsID.BOTH_CLICK]
            else:
                if testCase.tx.network.networkId == NetworkIds.TESTNET:
                    moves = [NavInsID.TAPPABLE_CENTER_TAP]
                if txOutput.datum is None:
                    moves += [NavInsID.TAPPABLE_CENTER_TAP] + [NavInsID.SWIPE_CENTER_TO_LEFT]
                if testCase.signingMode == TransactionSigningMode.MULTISIG_TRANSACTION and \
                    len(testCase.tx.certificates) == 0 and len(testCase.tx.withdrawals) == 0:
                    moves += [NavInsID.TAPPABLE_CENTER_TAP] + [NavInsID.SWIPE_CENTER_TO_LEFT]
                if firmware == Firmware.FLEX and txOutput.amount > 10000000:
                    moves += [NavInsID.TAPPABLE_CENTER_TAP]

        elif isinstance(txOutput.destination.params, DeriveAddressTestCase):
            if txOutput.destination.params.addrType == AddressType.POINTER_KEY:
                if firmware.is_nano:
                    moves = [NavInsID.BOTH_CLICK] * 3 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2
                else:
                    moves = [NavInsID.TAPPABLE_CENTER_TAP] + [NavInsID.SWIPE_CENTER_TO_LEFT] + [NavInsID.TAPPABLE_CENTER_TAP] * 2
            elif txOutput.destination.params.addrType == AddressType.ENTERPRISE_KEY:
                if firmware.is_nano:
                    moves = [NavInsID.BOTH_CLICK] * 5
                else:
                    moves = [NavInsID.TAPPABLE_CENTER_TAP] + [NavInsID.SWIPE_CENTER_TO_LEFT] + [NavInsID.TAPPABLE_CENTER_TAP] * 2
            elif auxData:
                if firmware.is_nano:
                    moves = [NavInsID.BOTH_CLICK] * 3 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2
                else:
                    moves = [NavInsID.SWIPE_CENTER_TO_LEFT] + [NavInsID.TAPPABLE_CENTER_TAP] + [NavInsID.TAPPABLE_CENTER_TAP]
            elif not txOutput.destination.params.stakingValue.startswith("m/"):
                if firmware.is_nano:
                    moves = [NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK]
                    moves += [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2
                else:
                    moves = [NavInsID.TAPPABLE_CENTER_TAP] + [NavInsID.SWIPE_CENTER_TO_LEFT] + [NavInsID.TAPPABLE_CENTER_TAP] * 2

        with client.sign_tx_outputs_basic(txOutput):
            if len(moves) > 0:
                navigator.navigate(moves)
            else:
                pass
        # Check the status (Asynchronous)
        response = client.get_async_response()
        # Check the status (Asynchronous)
        assert response and response.status == Errors.SW_SUCCESS

        # Send TOKEN BUNDLE
        with_nav: bool = txOutput.destination.type == TxOutputDestinationType.THIRD_PARTY
        _signTx_addTokenBundle(firmware, navigator, client, P1Type.P1_OUTPUTS, txOutput.tokenBundle, with_nav)

        # Send DATUM
        if txOutput.datum is not None:
            response = client.sign_tx_outputs_datum(txOutput.datum)
            # Check the status
            assert response and response.status == Errors.SW_SUCCESS
            if txOutput.datum.type == DatumType.INLINE:
                if len(txOutput.datum.datumHex) // 2 > MAX_SIGN_TX_CHUNK_SIZE:
                    payload = txOutput.datum.datumHex[MAX_SIGN_TX_CHUNK_SIZE * 2:]
                    max_payload_size = MAX_SIGN_TX_CHUNK_SIZE * 2
                    while len(payload) > 0:
                        response = client.sign_tx_outputs_chunk(P2Type.P2_DATUM_CHUNK, payload[:max_payload_size])
                        # Check the status
                        assert response and response.status == Errors.SW_SUCCESS
                        payload = payload[max_payload_size:]

        # Send REFERENCE SCRIPT
        if isinstance(txOutput, TxOutputBabbage) and txOutput.referenceScriptHex is not None:
            response = client.sign_tx_outputs_ref_script(txOutput.referenceScriptHex)
            # Check the status
            assert response and response.status == Errors.SW_SUCCESS
            if len(txOutput.referenceScriptHex) // 2 > MAX_SIGN_TX_CHUNK_SIZE:
                payload = txOutput.referenceScriptHex[MAX_SIGN_TX_CHUNK_SIZE * 2:]
                max_payload_size = MAX_SIGN_TX_CHUNK_SIZE * 2
                while len(payload) > 0:
                    response = client.sign_tx_outputs_chunk(P2Type.P2_SCRIPT_CHUNK, payload[:max_payload_size])
                    # Check the status
                    assert response and response.status == Errors.SW_SUCCESS
                    payload = payload[max_payload_size:]

        # Send CONFIRM
        with client.sign_tx_outputs_confirm():
            if (testCase.signingMode == TransactionSigningMode.MULTISIG_TRANSACTION and \
                len(testCase.tx.certificates) == 0 and len(testCase.tx.withdrawals) == 0) or \
                (len(txOutput.tokenBundle) > 0 and with_nav):
                if firmware.is_nano:
                    navigator.navigate([NavInsID.BOTH_CLICK])
                else:
                    scenario_navigator.address_review_approve(do_comparison=False)
            else:
                pass
        # Check the status (Asynchronous)
        response = client.get_async_response()
        # Check the status (Asynchronous)
        assert response and response.status == Errors.SW_SUCCESS


def _signTx_setFee(firmware: Firmware,
                   navigator: Navigator,
                   client: CommandSender,
                   testCase: SignTxTestCase) -> None:
    """Sign TX Set FEE

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    with client.sign_tx_fee(testCase):
        moves = []
        if firmware.is_nano:
            if testCase.signingMode != TransactionSigningMode.POOL_REGISTRATION_AS_OWNER:
                moves += [NavInsID.BOTH_CLICK]
            if testCase.tx.fee > 5 * 1000000:
                moves += [NavInsID.BOTH_CLICK]
        else:
            if testCase.tx.fee > 5 * 1000000:
                moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
            else:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
        if len(moves) > 0:
            navigator.navigate(moves)
        else:
            pass
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _signTx_setTtl(client: CommandSender,
                   testCase: SignTxTestCase) -> None:
    """Sign TX Set TTL

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """
    if testCase.tx.ttl is None:
        return
    response = client.sign_tx_ttl(testCase)
    # Check the status
    assert response.status == Errors.SW_SUCCESS


def _signTx_setCertificates(firmware: Firmware,
                            navigator: Navigator,
                            scenario_navigator: NavigateWithScenario,
                            client: CommandSender,
                            testCase: SignTxTestCase) -> None:
    """Sign TX Set CERTIFICATES

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    for certificate in testCase.tx.certificates:
        with client.sign_tx_certificate(certificate):
            if firmware.is_nano:
                moves = []
                if testCase.signingMode == TransactionSigningMode.MULTISIG_TRANSACTION:
                    if certificate.type in (CertificateType.STAKE_REGISTRATION,
                                            CertificateType.STAKE_DEREGISTRATION,
                                            CertificateType.STAKE_DELEGATION):
                        moves += [NavInsID.BOTH_CLICK]
                        if certificate.params.stakeCredential.type == CredentialParamsType.KEY_PATH:
                            moves += [NavInsID.BOTH_CLICK]
                        moves += [NavInsID.RIGHT_CLICK]
                if certificate.type == CertificateType.STAKE_POOL_RETIREMENT:
                    moves += [NavInsID.RIGHT_CLICK]
                moves += [NavInsID.BOTH_CLICK]
                if testCase.signingMode == TransactionSigningMode.MULTISIG_TRANSACTION:
                    if certificate.type not in (CertificateType.STAKE_REGISTRATION,
                                                CertificateType.STAKE_DEREGISTRATION,
                                                CertificateType.STAKE_DELEGATION):
                        moves += [NavInsID.BOTH_CLICK]
                else:
                    moves += [NavInsID.BOTH_CLICK]
                if isinstance(certificate.params, (AuthorizeCommitteeParams, ResignCommitteeParams)) and \
                    certificate.params.coldCredential.type != CredentialParamsType.KEY_PATH:
                    moves += [NavInsID.RIGHT_CLICK]
                if isinstance(certificate.params, AuthorizeCommitteeParams) and \
                    certificate.params.hotCredential.type != CredentialParamsType.KEY_PATH:
                    moves += [NavInsID.RIGHT_CLICK]
                if certificate.type == CertificateType.AUTHORIZE_COMMITTEE_HOT:
                    moves += [NavInsID.BOTH_CLICK]
                if isinstance(certificate.params, VoteDelegationParams):
                    if certificate.params.dRep.type in (DRepParamsType.KEY_HASH, DRepParamsType.SCRIPT_HASH):
                        moves += [NavInsID.RIGHT_CLICK]
                    moves += [NavInsID.BOTH_CLICK]
                if isinstance(certificate.params, DRepUpdateParams):
                    moves += [NavInsID.BOTH_CLICK]
                if isinstance(certificate.params, (StakeRegistrationConwayParams, DRepRegistrationParams)):
                    moves += [NavInsID.BOTH_CLICK]
                if isinstance(certificate.params, (ResignCommitteeParams,
                                                   DRepRegistrationParams,
                                                   DRepUpdateParams)) and \
                    certificate.params.anchor is not None:
                    if len(certificate.params.anchor.url) > 50:
                        # For URL, navigation depends on url length :(
                        moves += [NavInsID.RIGHT_CLICK] * 2
                if certificate.type == CertificateType.RESIGN_COMMITTEE_COLD:
                    moves += [NavInsID.BOTH_CLICK]
                if isinstance(certificate.params, (ResignCommitteeParams,
                                                   DRepRegistrationParams,
                                                   DRepUpdateParams)) and \
                    certificate.params.anchor is not None:
                    moves += [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK]
                moves += [NavInsID.BOTH_CLICK]

                navigator.navigate(moves)
            else:
                if certificate.type == CertificateType.STAKE_POOL_REGISTRATION:
                    navigator.navigate([NavInsID.SWIPE_CENTER_TO_LEFT])
                else:
                    scenario_navigator.address_review_approve(do_comparison=False)
        # Check the status (Asynchronous)
        response = client.get_async_response()
        # Check the status (Asynchronous)
        assert response and response.status == Errors.SW_SUCCESS

        if certificate.type == CertificateType.STAKE_POOL_REGISTRATION:
            # additional data for pool certificate

            # Send POOL INITIAL PARAMS
            moves = []
            if firmware.is_nano:
                moves += [NavInsID.BOTH_CLICK]
            else:
                moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
                if testCase.signingMode == TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR:
                    moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
            with client.sign_tx_cert_pool_reg_init(certificate.params):
                navigator.navigate(moves)
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS

            # Send POOL KEY
            response = client.sign_tx_cert_pool_reg_pool_key(certificate.params.poolKey)
            # Check the status
            assert response.status == Errors.SW_SUCCESS

            # Send VRF
            moves = []
            if firmware.is_nano:
                moves += [NavInsID.BOTH_CLICK]
            else:
                if testCase.signingMode == TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR:
                    moves += [NavInsID.TAPPABLE_CENTER_TAP]
            with client.sign_tx_cert_pool_reg_vrf(certificate.params.vrfKeyHashHex):
                if len(moves) > 0:
                    navigator.navigate(moves)
                else:
                    pass
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS

            # Send FINANCIALS
            moves = []
            if firmware.is_nano:
                moves += [NavInsID.BOTH_CLICK]
            else:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            with client.sign_tx_cert_pool_reg_financials(certificate.params):
                navigator.navigate(moves)
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS

            # Send REWARD ACCOUNT
            moves = []
            if firmware.is_nano:
                moves += [NavInsID.BOTH_CLICK]
            else:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            with client.sign_tx_cert_pool_reg_reward(certificate.params.rewardAccount):
                navigator.navigate(moves)
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS

            # Send POOL OWNER
            for owner in certificate.params.poolOwners:
                with client.sign_tx_cert_pool_reg_owner(owner):
                    navigator.navigate(moves)
                # Check the status (Asynchronous)
                response = client.get_async_response()
                assert response and response.status == Errors.SW_SUCCESS

            # Send POOL RELAY
            moves = []
            if firmware.is_nano:
                moves += [NavInsID.BOTH_CLICK]
            else:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            for relay in certificate.params.relays:
                with client.sign_tx_cert_pool_reg_relay(relay):
                    navigator.navigate(moves)
                # Check the status (Asynchronous)
                response = client.get_async_response()
                assert response and response.status == Errors.SW_SUCCESS

            # Send POOL METADATA
            moves = []
            if firmware.is_nano:
                moves += [NavInsID.BOTH_CLICK]
            else:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            if len(certificate.params.poolOwners) <= 1 and len(certificate.params.relays) <= 1 and \
                certificate.params.metadata is not None:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            elif len(certificate.params.poolOwners) == 2 and len(certificate.params.relays) == 1 and \
                firmware == Firmware.STAX:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            with client.sign_tx_cert_pool_reg_metadata(certificate.params.metadata):
                navigator.navigate(moves)
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS

            # Send POOL CONFIRM
            with client.sign_tx_cert_pool_reg_confirm():
                if len(certificate.params.relays) == 0:
                    if firmware.is_nano:
                        navigator.navigate([NavInsID.BOTH_CLICK])
                    else:
                        scenario_navigator.review_approve(do_comparison=False)
                else:
                    pass
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS


def _signTx_setWithdrawals(client: CommandSender,
                           testCase: SignTxTestCase) -> None:
    """Sign TX Set WITHDRAWALS

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    for withdrawal in testCase.tx.withdrawals:
        with client.sign_tx_withdrawal(withdrawal):
            pass
        # Check the status (Asynchronous)
        response = client.get_async_response()
        # Check the status (Asynchronous)
        assert response and response.status == Errors.SW_SUCCESS


def _signTx_setValidityIntervalStart(client: CommandSender,
                                     testCase: SignTxTestCase) -> None:
    """Sign TX Set VALIDITY START

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    if testCase.tx.validityIntervalStart is None:
        return
    response = client.sign_tx_validity(testCase.tx.validityIntervalStart)
    # Check the status
    assert response.status == Errors.SW_SUCCESS


def _signTx_addTokenBundle(firmware: Firmware,
                           navigator: Navigator,
                           client: CommandSender,
                           p1: P1Type,
                           assetGroups: List[AssetGroup],
                           with_nav: bool = True) -> None:
    """Sign TX add TOKEN BUNDLE

    Args:
        client (CommandSender): The command sender instance
        p1 (P1Type): The P1 value
        assetGroups (List[AssetGroup]): The test case
    """

    moves = [NavInsID.BOTH_CLICK] * 2 if firmware.is_nano else [NavInsID.TAPPABLE_CENTER_TAP] * 2
    for assetGroup in assetGroups:
        with client.sign_tx_asset_group(p1, assetGroup):
            if firmware.is_nano:
                pass
            else:
                navigator.navigate([NavInsID.SWIPE_CENTER_TO_LEFT])
        # Check the status (Asynchronous)
        response = client.get_async_response()
        assert response and response.status == Errors.SW_SUCCESS

        for token in assetGroup.tokens:
            with client.sign_tx_token(p1, token):
                if with_nav:
                    navigator.navigate(moves)
                else:
                    pass
            # Check the status (Asynchronous)
            response = client.get_async_response()
            assert response and response.status == Errors.SW_SUCCESS


def _signTx_setMint(firmware: Firmware,
                    navigator: Navigator,
                    scenario_navigator: NavigateWithScenario,
                    client: CommandSender,
                    testCase: SignTxTestCase) -> None:
    """Sign TX Set VALIDITY START

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    if len(testCase.tx.mint) == 0:
        return

    moves = [NavInsID.BOTH_CLICK] if firmware.is_nano else [NavInsID.SWIPE_CENTER_TO_LEFT] * 2
    with client.sign_tx_mint_init(len(testCase.tx.mint)):
        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS

    _signTx_addTokenBundle(firmware, navigator, client, P1Type.P1_MINT, testCase.tx.mint)

    with client.sign_tx_mint_confirm():
        if firmware.is_nano:
            navigator.navigate(moves)
        else:
            scenario_navigator.review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _signTx_setScriptDataHash(client: CommandSender,
                              testCase: SignTxTestCase) -> None:
    """Sign TX Set SCRIPT DATA HASH

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    if testCase.tx.scriptDataHash is None:
        return
    response = client.sign_tx_script_data_hash(testCase.tx.scriptDataHash)
    # Check the status
    assert response.status == Errors.SW_SUCCESS


def _signTx_addVoterVotes(firmware: Firmware,
                          navigator: Navigator,
                          scenario_navigator: NavigateWithScenario,
                          client: CommandSender,
                          testCase: SignTxTestCase) -> None:
    """Sign TX Add VOTING PROCEDURES

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    for votingProcedure in testCase.tx.votingProcedures:
        with client.sign_tx_voting_procedure(votingProcedure):
            if firmware.is_nano:
                moves = []
                # Vote
                moves += [NavInsID.BOTH_CLICK]
                # Voter Key / Path
                if not votingProcedure.voter.keyValue.startswith("m/"):
                    moves += [NavInsID.RIGHT_CLICK]
                moves += [NavInsID.BOTH_CLICK]
                # Action Tx Hash
                moves += [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK]
                # Action Index + Vote + Anchor
                moves += [NavInsID.BOTH_CLICK] * 3
                if votingProcedure.votes[0].votingProcedure.anchor is not None:
                    # Anchor tx Hash data
                    moves += [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK]
                # Confirm
                moves += [NavInsID.BOTH_CLICK]
                navigator.navigate(moves)
            else:
                scenario_navigator.address_review_approve(do_comparison=False)
        # Check the status (Asynchronous)
        response = client.get_async_response()
        # Check the status (Asynchronous)
        assert response and response.status == Errors.SW_SUCCESS


def _signTx_addCollateralInputs(client: CommandSender,
                                testCase: SignTxTestCase) -> None:
    """Sign TX Add COLLATERAL INPUTS

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    for txInput in testCase.tx.collateralInputs:
        response = client.sign_tx_collateral_inputs(txInput)
        # Check the status
        assert response and response.status == Errors.SW_SUCCESS


def _signTx_addCollateralOutputs(firmware: Firmware,
                                 navigator: Navigator,
                                 scenario_navigator: NavigateWithScenario,
                                 client: CommandSender,
                                 testCase: SignTxTestCase) -> None:
    """Sign TX Add COLLATERAL OUTPUTS

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    if testCase.tx.collateralOutput is None:
        return
    # Send Basic DATA
    with client.sign_tx_collateral_output_basic(testCase.tx.collateralOutput):
        moves = []
        if testCase.txBody == "":
            pass
        elif firmware.is_nano:
            moves += [NavInsID.BOTH_CLICK] + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK]
        else:
            moves += [NavInsID.TAPPABLE_CENTER_TAP] + [NavInsID.SWIPE_CENTER_TO_LEFT]
            if testCase.tx.totalCollateral is None:
                moves += [NavInsID.TAPPABLE_CENTER_TAP] * 2
        if len(moves) > 0:
            navigator.navigate(moves)
        else:
            pass
    # Check the status (Asynchronous)
    response = client.get_async_response()
    # Check the status (Asynchronous)
    assert response and response.status == Errors.SW_SUCCESS

    # Send TOKEN BUNDLE
    if len(testCase.tx.collateralOutput.tokenBundle) > 0:
        _signTx_addTokenBundle(firmware, navigator, client, P1Type.P1_COLLATERAL_OUTPUT, testCase.tx.collateralOutput.tokenBundle)

    # Send CONFIRM
    with client.sign_tx_collateral_output_confirm():
        if testCase.tx.totalCollateral is None and \
            testCase.tx.collateralOutput.destination.type == TxOutputDestinationType.THIRD_PARTY:
            pass
        else:
            if testCase.tx.totalCollateral is not None:
                pass
            elif firmware.is_nano:
                navigator.navigate([NavInsID.BOTH_CLICK])
            else:
                scenario_navigator.address_review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _signTx_addTotalCollateral(firmware: Firmware,
                               navigator: Navigator,
                               client: CommandSender,
                               testCase: SignTxTestCase) -> None:
    """Sign TX Add TOTAL COLLATERAL

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    if not testCase.tx.totalCollateral:
        return
    with client.sign_tx_total_collateral(testCase.tx.totalCollateral):
        if firmware.is_nano:
            navigator.navigate([NavInsID.BOTH_CLICK])
    # Check the status (Asynchronous)
    response = client.get_async_response()
    # Check the status (Asynchronous)
    assert response and response.status == Errors.SW_SUCCESS


def _signTx_addReferenceInputs(client: CommandSender,
                               testCase: SignTxTestCase) -> None:
    """Sign TX Add REFERENCE INPUTS

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    for txInput in testCase.tx.referenceInputs:
        response = client.sign_tx_reference_inputs(txInput)
        # Check the status
        assert response and response.status == Errors.SW_SUCCESS


def _signTx_addRequiredSigners(client: CommandSender,
                               testCase: SignTxTestCase) -> None:
    """Sign TX Add REQUIRED SIGNERS

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    for signer in testCase.tx.requiredSigners:
        response = client.sign_tx_required_signers(signer)
        # Check the status
        assert response and response.status == Errors.SW_SUCCESS


def _signTx_addTreasury(firmware: Firmware,
                        navigator: Navigator,
                        client: CommandSender,
                        testCase: SignTxTestCase) -> None:
    """Sign TX Add TREASURY

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    if testCase.tx.treasury is None:
        return
    with client.sign_tx_treasury(testCase.tx.treasury):
        if firmware.is_nano:
            moves = [NavInsID.BOTH_CLICK]
        else:
            moves = [NavInsID.TAPPABLE_CENTER_TAP]
        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _signTx_addDonation(firmware: Firmware,
                        navigator: Navigator,
                        client: CommandSender,
                        testCase: SignTxTestCase) -> None:
    """Sign TX Add DONATION

    Args:
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
    """

    if testCase.tx.donation is None:
        return
    with client.sign_tx_donation(testCase.tx.donation):
        if firmware.is_nano:
            moves = [NavInsID.BOTH_CLICK]
        else:
            moves = [NavInsID.TAPPABLE_CENTER_TAP]
        navigator.navigate(moves)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS


def _signTx_confirm(firmware: Firmware,
                    navigator: Navigator,
                    scenario_navigator: NavigateWithScenario,
                    client: CommandSender,
                    signingMode: TransactionSigningMode) -> bytes:
    """Sign TX Confirm

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        signingMode (TransactionSigningMode): The signing mode

    Returns:
        bytes: The signature
    """
    with client.sign_tx_confirm():
        if firmware.is_nano:
            moves = []
            if signingMode == TransactionSigningMode.PLUTUS_TRANSACTION:
                moves += [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK]
            moves += [NavInsID.BOTH_CLICK]
            navigator.navigate(moves)
        else:
            scenario_navigator.review_approve(do_comparison=False)
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == Errors.SW_SUCCESS
    return response.data


def _signTx_setWitnesses(firmware: Firmware,
                         navigator: Navigator,
                         scenario_navigator: NavigateWithScenario,
                         client: CommandSender,
                         testCase: SignTxTestCase,
                         withnessPaths: List[str],
                         auxData: bool) -> List[Tuple[str, bytes]]:
    """Sign TX Set WITNESSES

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        testCase (SignTxTestCase): The test case
        withnessPaths (List[str]): The witness paths to send
        auxData (bool): True if the auxiliary data is set, False otherwise

    Returns:
        bytes: List of Tuples with path and signature
    """

    signatures = []
    for path in withnessPaths:
        moves = []
        path_elt = path.replace("'","").split("/") # Remove Hardened info
        if int(path_elt[1]) > 1852 or (len(path_elt) > 4 and int(path_elt[4]) > 2):
            moves += [NavInsID.BOTH_CLICK] * 2
        elif auxData:
            if testCase.tx.auxiliaryData is not None and \
                testCase.tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
                pass
            elif isinstance(testCase.tx.outputs[0].destination.params, ThirdPartyAddressParams):
                pass
            else:
                moves += [NavInsID.BOTH_CLICK] * 3
        elif testCase.signingMode == TransactionSigningMode.PLUTUS_TRANSACTION:
            moves += [NavInsID.BOTH_CLICK] * 2
        elif testCase.signingMode in (TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
                                      TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR):
            moves += [NavInsID.BOTH_CLICK]

        with client.sign_tx_witness(path):
            if len(moves) > 0:
                if firmware.is_nano:
                    navigator.navigate(moves)
                else:
                    scenario_navigator.address_review_approve(do_comparison=False)
            else:
                pass
        # Check the status (Asynchronous)
        response = client.get_async_response()
        # Check the status (Asynchronous)
        assert response and response.status == Errors.SW_SUCCESS
        signatures.append((path, response.data))

    return signatures


def _gatherWitnessPaths(testCase: SignTxTestCase) -> List[str]:
    """Gather the witness paths

    Args:
        testCase (SignTxTestCase): The test case

    Returns:
        list: The list of unique witness paths
    """

    witnessPaths = []
    if testCase.signingMode != TransactionSigningMode.MULTISIG_TRANSACTION:
        # input witnesses
        for txInput in testCase.tx.inputs:
            if txInput.path is not None:
                witnessPaths.append(txInput.path)

        # certificate witnesses
        if testCase.tx.certificates is not None:
            for cert in testCase.tx.certificates:
                if cert.type in (CertificateType.STAKE_DEREGISTRATION,
                                 CertificateType.STAKE_REGISTRATION_CONWAY,
                                 CertificateType.STAKE_DEREGISTRATION_CONWAY,
                                 CertificateType.STAKE_DELEGATION,
                                 CertificateType.VOTE_DELEGATION):
                    if cert.params.stakeCredential.type == CredentialParamsType.KEY_PATH:
                        witnessPaths.append(cert.params.stakeCredential.keyValue)

                elif cert.type in (CertificateType.AUTHORIZE_COMMITTEE_HOT,
                                   CertificateType.RESIGN_COMMITTEE_COLD):
                    if cert.params.coldCredential is not None and \
                        cert.params.coldCredential.type == CredentialParamsType.KEY_PATH:
                        witnessPaths.append(cert.params.coldCredential.keyValue)

                elif cert.type in (CertificateType.DREP_REGISTRATION,
                                   CertificateType.DREP_DEREGISTRATION,
                                   CertificateType.DREP_UPDATE):
                    assert cert.params.dRepCredential is not None
                    if cert.params.dRepCredential.type == CredentialParamsType.KEY_PATH:
                        witnessPaths.append(cert.params.dRepCredential.keyValue)

                elif cert.type == CertificateType.STAKE_POOL_RETIREMENT:
                    assert cert.params.poolKeyPath is not None
                    witnessPaths.append(cert.params.poolKeyPath)

                elif cert.type == CertificateType.STAKE_POOL_REGISTRATION:
                    for poolOwner in cert.params.poolOwners:
                        if poolOwner.type == TxOutputDestinationType.THIRD_PARTY and \
                            poolOwner.key.startswith("m/"):
                            witnessPaths.append(poolOwner.key)
                    if cert.params.poolKey.type == TxOutputDestinationType.THIRD_PARTY and \
                        cert.params.poolKey.key.startswith("m/"):
                        witnessPaths.append(cert.params.poolKey.key)

        # withdrawal witnesses
        for withdrawal in testCase.tx.withdrawals:
            if withdrawal.stakeCredential.type == CredentialParamsType.KEY_PATH:
                witnessPaths.append(withdrawal.stakeCredential.keyValue)

        # required signers witnesses
        for signer in testCase.tx.requiredSigners:
            if signer.type == CredentialParamsType.KEY_PATH:
                witnessPaths.append(signer.addressHex)

        # collateral inputs witnesses
        for collateral in testCase.tx.collateralInputs:
            if collateral.path is not None:
                witnessPaths.append(collateral.path)

        # voting procedures witnesses
        for voterVotes in testCase.tx.votingProcedures:
            if voterVotes.voter.type in (VoterType.COMMITTEE_KEY_PATH,
                                        VoterType.DREP_KEY_PATH,
                                        VoterType.STAKE_POOL_KEY_PATH):
                witnessPaths.append(voterVotes.voter.keyValue)

    for path in testCase.additionalWitnessPaths:
        witnessPaths.append(path)

    # return uniqness preserving the order
    return list(dict.fromkeys(witnessPaths))


@pytest.mark.parametrize(
    "testCase",
    transactionInitRejectTestCases + addressParamsRejectTestCases + certificateStakingRejectTestCases + \
    withdrawalRejectTestCases + witnessRejectTestCases + testsInvalidTokenBundleOrdering + \
    singleAccountRejectTestCases + collateralOutputRejectTestCases + testsCVoteRegistrationRejects + \
    certificateRejectTestCases + certificateStakePoolRetirementRejectTestCases +\
    poolRegistrationOwnerRejectTestCases + invalidCertificates + invalidPoolMetadataTestCases + \
    invalidRelayTestCases + stakePoolRegistrationPoolIdRejectTestCases + \
    stakePoolRegistrationPoolIdRejectTestCases + stakePoolRegistrationOwnerRejectTestCases + outputRejectTestCases,
    ids=idTestFunc
)
def test_signTx_reject(firmware: Firmware,
                backend: BackendInterface,
                navigator: Navigator,
                scenario_navigator: NavigateWithScenario,
                testCase: SignTxTestCase,
                appFlags: dict) -> None:
    """Check Sign TX Reject"""

    # TODO - Navigation should be set for each test case
    if firmware.is_nano:
        pytest.skip("Not supported yet on Nano because Navigation should be reviewed")

    pytest.skip("TODO - Navigation DO NOT WORK ANY MORE")

    with pytest.raises(ExceptionRAPDU) as err:
        # Send the APDU
        test_signTx(firmware, backend, navigator, scenario_navigator, testCase, appFlags)
    assert err.value.status == testCase.expected_sw
