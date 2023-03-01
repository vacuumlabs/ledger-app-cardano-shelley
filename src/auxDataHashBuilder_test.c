#ifdef DEVEL

#include "auxDataHashBuilder.h"
#include "cardano.h"
#include "hexUtils.h"
#include "textUtils.h"
#include "testUtils.h"

void test_CIP15()
{
	PRINTF("CIP15 voting registration\n");

	static const char* voteKey = "3B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7";
	static const char* stakingKey = "BC65BE1B0B9D7531778A1317C2AA6DE936963C3F9AC7D5EE9E9EDA25E0C97C5E";
	static const char* paymentAddress = "0180F9E2C88E6C817008F3A812ED889B4A4DA8E0BD103F86E7335422AA122A946B9AD3D2DDF029D3A828F0468AECE76895F15C9EFBD69B4277";
	static uint64_t nonce = 22634813;

	static const char* cVoteRegistrationSignature = "0EA4A424522DD485F16466CD5A754F3C8DBD4D1976C912624E3465C540B1D0776C92633FC64BE057F947AAC561012FE55ACD3C54EF7BECE0DA0B90CF02DC760D";

	static const char* expectedCVoteRegistrationPayloadHashHex = "2EEA6A5168066BDA411F80BE10B50646378616C3414C711A61D363C7879B5CBC";
	static const char* expectedAuxDataHashHex = "07cdec3a795626019739f275582433eabe32da80f82aeb74e4916b547c01a589";

	aux_data_hash_builder_t builder;

	auxDataHashBuilder_init(&builder);
	auxDataHashBuilder_cVoteRegistration_enter(&builder, CIP15);
	auxDataHashBuilder_cVoteRegistration_enterPayload(&builder);

	{
		uint8_t tmp[32] = {0};
		size_t tmpSize = decode_hex(voteKey, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addVoteKey(
		        &builder,
		        tmp, tmpSize
		);
	}

	{
		uint8_t tmp[32] = {0};
		size_t tmpSize = decode_hex(stakingKey, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addStakingKey(
		        &builder,
		        tmp, tmpSize
		);
	}

	{
		uint8_t tmp[57] = {0};
		size_t tmpSize = decode_hex(paymentAddress, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addPaymentAddress(
		        &builder,
		        tmp, tmpSize
		);
	}

	auxDataHashBuilder_cVoteRegistration_addNonce(&builder, nonce);

	{
		uint8_t result[AUX_DATA_HASH_LENGTH] = {0};
		auxDataHashBuilder_cVoteRegistration_finalizePayload(&builder, result, SIZEOF(result));

		uint8_t expected[AUX_DATA_HASH_LENGTH] = {0};
		decode_hex(expectedCVoteRegistrationPayloadHashHex, expected, SIZEOF(expected));

		PRINTF("registration payload hash hex\n");
		PRINTF("%.*h\n", 32, result);

		EXPECT_EQ_BYTES(result, expected, 32);
	}

	{
		uint8_t tmp[64] = {0};
		size_t tmpSize = decode_hex(cVoteRegistrationSignature, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addSignature(
		        &builder,
		        tmp, tmpSize
		);
	}

	auxDataHashBuilder_cVoteRegistration_addAuxiliaryScripts(&builder);

	{
		uint8_t result[AUX_DATA_HASH_LENGTH] = {0};
		auxDataHashBuilder_finalize(&builder, result, SIZEOF(result));

		uint8_t expected[AUX_DATA_HASH_LENGTH] = {0};
		decode_hex(expectedAuxDataHashHex, expected, SIZEOF(expected));

		PRINTF("Transaction auxiliary data hash hex\n");
		PRINTF("%.*h\n", 32, result);

		EXPECT_EQ_BYTES(result, expected, 32);
	}
}

void test_CIP36()
{
	PRINTF("CIP36 voting registration\n");

	// data from https://cips.cardano.org/cips/cip36/test-vector.md.html

	static const char* delegationKey1 = "a6a3c0447aeb9cc54cf6422ba32b294e5e1c3ef6d782f2acff4a70694c4d1663";
	static const uint64_t delegationWeight1 = 1;
	static const char* delegationKey2 = "00588e8e1d18cba576a4d35758069fe94e53f638b6faf7c07b8abd2bc5c5cdee";
	static const uint64_t delegationWeight2 = 3;

	static const char* stakingKey = "86870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e";
	static const char* paymentAddress = "e0ae3a0a7aeda4aea522e74e4fe36759fca80789a613a58a4364f6ecef";
	static const uint64_t nonce = 1234;
	static const uint64_t votingPurpose = 0;

	static const char* cVoteRegistrationSignature = "0ea4a424522dd485f16466cd5a754f3c8dbd4d1976c912624e3465c540b1d0776c92633fc64be057f947aac561012fe55acd3c54ef7bece0da0b90cf02dc760d";

	static const char* expectedCVoteRegistrationPayloadHashHex = "5bc0681f173efd76e1989037a3694b8a7abea22053f5940cbb5cfcdf721007d7";
	static const char* expectedAuxDataHashHex = "3786b3ad677129e43dbb3456e45e5af589e9aae81062ef7e26f15fde00df421d";

	aux_data_hash_builder_t builder;

	auxDataHashBuilder_init(&builder);
	auxDataHashBuilder_cVoteRegistration_enter(&builder, CIP36);
	auxDataHashBuilder_cVoteRegistration_enterPayload(&builder);

	auxDataHashBuilder_cVoteRegistration_enterDelegations(&builder, 2);
	{
		uint8_t tmp[32] = {0};
		size_t tmpSize = decode_hex(delegationKey1, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addDelegation(
		        &builder,
		        tmp, tmpSize,
		        delegationWeight1
		);
	}
	{
		uint8_t tmp[32] = {0};
		size_t tmpSize = decode_hex(delegationKey2, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addDelegation(
		        &builder,
		        tmp, tmpSize,
		        delegationWeight2
		);
	}

	{
		uint8_t tmp[32] = {0};
		size_t tmpSize = decode_hex(stakingKey, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addStakingKey(
		        &builder,
		        tmp, tmpSize
		);
	}

	{
		uint8_t tmp[57] = {0};
		size_t tmpSize = decode_hex(paymentAddress, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addPaymentAddress(
		        &builder,
		        tmp, tmpSize
		);
	}

	auxDataHashBuilder_cVoteRegistration_addNonce(&builder, nonce);
	auxDataHashBuilder_cVoteRegistration_addVotingPurpose(&builder, votingPurpose);

	{
		uint8_t result[AUX_DATA_HASH_LENGTH] = {0};
		auxDataHashBuilder_cVoteRegistration_finalizePayload(&builder, result, SIZEOF(result));

		uint8_t expected[AUX_DATA_HASH_LENGTH] = {0};
		decode_hex(expectedCVoteRegistrationPayloadHashHex, expected, SIZEOF(expected));

		PRINTF("registration payload hash hex\n");
		PRINTF("%.*h\n", 32, result);

		EXPECT_EQ_BYTES(result, expected, 32);
	}

	{
		uint8_t tmp[64] = {0};
		size_t tmpSize = decode_hex(cVoteRegistrationSignature, tmp, SIZEOF(tmp));
		auxDataHashBuilder_cVoteRegistration_addSignature(
		        &builder,
		        tmp, tmpSize
		);
	}

	auxDataHashBuilder_cVoteRegistration_addAuxiliaryScripts(&builder);

	{
		uint8_t result[AUX_DATA_HASH_LENGTH] = {0};
		auxDataHashBuilder_finalize(&builder, result, SIZEOF(result));

		uint8_t expected[AUX_DATA_HASH_LENGTH] = {0};
		decode_hex(expectedAuxDataHashHex, expected, SIZEOF(expected));

		PRINTF("Transaction auxiliary data hash hex\n");
		PRINTF("%.*h\n", 32, result);

		EXPECT_EQ_BYTES(result, expected, 32);
	}
}

void run_auxDataHashBuilder_test()
{
	PRINTF("auxDataHashBuilder test\n");

	test_CIP15();
	test_CIP36();
}

#endif // DEVEL
