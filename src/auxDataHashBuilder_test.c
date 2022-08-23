#ifdef DEVEL

#include "auxDataHashBuilder.h"
#include "cardano.h"
#include "hexUtils.h"
#include "textUtils.h"
#include "testUtils.h"


static const char* votingKey = "3B40265111D8BB3C3C608D95B3A0BF83461ACE32D79336579A1939B3AAD1C0B7";
static const char* stakingKey = "BC65BE1B0B9D7531778A1317C2AA6DE936963C3F9AC7D5EE9E9EDA25E0C97C5E";
static const char* votingRewardsAddress = "0180F9E2C88E6C817008F3A812ED889B4A4DA8E0BD103F86E7335422AA122A946B9AD3D2DDF029D3A828F0468AECE76895F15C9EFBD69B4277";
static uint64_t nonce = 22634813;

static const char* governanceVotingRegistrationSignature = "0EA4A424522DD485F16466CD5A754F3C8DBD4D1976C912624E3465C540B1D0776C92633FC64BE057F947AAC561012FE55ACD3C54EF7BECE0DA0B90CF02DC760D";

static const char* expectedGovernanceVotingRegistrationPayloadHashHex = "2EEA6A5168066BDA411F80BE10B50646378616C3414C711A61D363C7879B5CBC";
static const char* expectedAuxDataHashHex = "07cdec3a795626019739f275582433eabe32da80f82aeb74e4916b547c01a589";

void run_auxDataHashBuilder_test()
{
	PRINTF("auxDataHashBuilder test\n");
	aux_data_hash_builder_t builder;

	auxDataHashBuilder_init(&builder);
	auxDataHashBuilder_governanceVotingRegistration_enter(&builder);
	auxDataHashBuilder_governanceVotingRegistration_enterPayload(&builder);

	{
		uint8_t tmp[32] = {0};
		size_t tmpSize = decode_hex(votingKey, tmp, SIZEOF(tmp));
		auxDataHashBuilder_governanceVotingRegistration_addVotingKey(
		        &builder,
		        tmp, tmpSize
		);
	}

	{
		uint8_t tmp[32] = {0};
		size_t tmpSize = decode_hex(stakingKey, tmp, SIZEOF(tmp));
		auxDataHashBuilder_governanceVotingRegistration_addStakingKey(
		        &builder,
		        tmp, tmpSize
		);
	}

	{
		uint8_t tmp[57] = {0};
		size_t tmpSize = decode_hex(votingRewardsAddress, tmp, SIZEOF(tmp));
		auxDataHashBuilder_governanceVotingRegistration_addVotingRewardsAddress(
		        &builder,
		        tmp, tmpSize
		);
	}

	auxDataHashBuilder_governanceVotingRegistration_addNonce(&builder, nonce);

	{
		uint8_t result[AUX_DATA_HASH_LENGTH] = {0};
		auxDataHashBuilder_governanceVotingRegistration_finalizePayload(&builder, result, SIZEOF(result));

		uint8_t expected[AUX_DATA_HASH_LENGTH] = {0};
		decode_hex(expectedGovernanceVotingRegistrationPayloadHashHex, expected, SIZEOF(expected));

		PRINTF("Governance voting registration payload hash hex\n");
		PRINTF("%.*h\n", 32, result);

		EXPECT_EQ_BYTES(result, expected, 32);
	}

	{
		uint8_t tmp[64] = {0};
		size_t tmpSize = decode_hex(governanceVotingRegistrationSignature, tmp, SIZEOF(tmp));
		auxDataHashBuilder_governanceVotingRegistration_addSignature(
		        &builder,
		        tmp, tmpSize
		);
	}

	auxDataHashBuilder_governanceVotingRegistration_addAuxiliaryScripts(&builder);

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

#endif // DEVEL
