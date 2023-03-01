#ifdef DEVEL

#include "common.h"
#include "cardano.h"
#include "hexUtils.h"
#include "testUtils.h"
#include "tokens.h"
#include "uiScreens.h"

void testcase_assetFingerprint(
        const char* policyIdHex,
        const char* assetNameHex,
        const char* expected
)
{
	PRINTF("testcase %s %s\n", policyIdHex, assetNameHex);

	uint8_t policyId[28] = {0};
	decode_hex(policyIdHex, policyId, SIZEOF(policyId));

	uint8_t assetName[32] = {0};
	decode_hex(assetNameHex, assetName, SIZEOF(assetName));
	size_t assetNameSize = strlen(assetNameHex) / 2;

	char fingerprint[200] = {0};

	deriveAssetFingerprintBech32(
	        policyId, SIZEOF(policyId),
	        assetName, assetNameSize,
	        fingerprint, SIZEOF(fingerprint)
	);

	EXPECT_EQ(strcmp(fingerprint, expected), 0);
}

void test_assetFingerprint()
{
	// test vectors taken from CIP 14 proposal

	testcase_assetFingerprint(
	        "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
	        "",
	        "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3"
	);

	testcase_assetFingerprint(
	        "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
	        "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
	        "asset1aqrdypg669jgazruv5ah07nuyqe0wxjhe2el6f"
	);

	testcase_assetFingerprint(
	        "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
	        "504154415445",
	        "asset1hv4p5tv2a837mzqrst04d0dcptdjmluqvdx9k3"
	);

	testcase_assetFingerprint(
	        "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
	        "0000000000000000000000000000000000000000000000000000000000000000",
	        "asset1pkpwyknlvul7az0xx8czhl60pyel45rpje4z8w"
	);
}

typedef struct {
	uint8_t policyId[MINTING_POLICY_ID_SIZE];
	uint8_t assetNameBytes[ASSET_NAME_SIZE_MAX];
	size_t assetNameSize;
	uint64_t amountOutput;
	char expectedOutput[50];
	int64_t amountMint;
	char expectedMint[50];
} token_testcase_t;

const token_testcase_t tokenTestCases[] = {
	{
		{ 0x94, 0xcb, 0xb4, 0xfc, 0xbc, 0xaa, 0x29, 0x75, 0x77, 0x9f, 0x27, 0x3b, 0x26, 0x3e, 0xb3, 0xb5, 0xf2, 0x4a, 0x99, 0x51, 0xe4, 0x46, 0xd6, 0xdc, 0x4c, 0x13, 0x58, 0x64 },
		{ 0x52, 0x45, 0x56, 0x55 },
		4,
		234,
		"0.00000234 REVU", // cspell:disable-line
		-234,
		"-0.00000234 REVU" // cspell:disable-line
	},
	{
		// no decimal places in our table
		{ 0xaa, 0xcb, 0xb4, 0xfc, 0xbc, 0xaa, 0x29, 0x75, 0x77, 0x9f, 0x27, 0x3b, 0x26, 0x3e, 0xb3, 0xb5, 0xf2, 0x4a, 0x99, 0x51, 0xe4, 0x46, 0xd6, 0xdc, 0x4c, 0x13, 0x58, 0x64 },
		{ 0x52, 0x45, 0x56, 0x55 },
		4,
		2345,
		"2,345 (unknown decimals)",
		2345,
		" 2,345 (unknown decimals)"
	}
};

void test_decimalPlaces()
{
	for (size_t i = 0; i < ARRAY_LEN(tokenTestCases); i++) {
		char tokenAmountStr[60];
		token_group_t group;
		memcpy(group.policyId, tokenTestCases[i].policyId, MINTING_POLICY_ID_SIZE);

		str_formatTokenAmountOutput(
		        &group,
		        tokenTestCases[i].assetNameBytes, tokenTestCases[i].assetNameSize,
		        tokenTestCases[i].amountOutput,
		        tokenAmountStr, SIZEOF(tokenAmountStr)
		);
		EXPECT_EQ(strcmp(tokenAmountStr, tokenTestCases[i].expectedOutput), 0);

		str_formatTokenAmountMint(
		        &group,
		        tokenTestCases[i].assetNameBytes, tokenTestCases[i].assetNameSize,
		        tokenTestCases[i].amountMint,
		        tokenAmountStr, SIZEOF(tokenAmountStr)
		);
		EXPECT_EQ(strcmp(tokenAmountStr, tokenTestCases[i].expectedMint), 0);
	}
}

void run_tokens_test()
{
	test_assetFingerprint();
	test_decimalPlaces();
}

#endif
