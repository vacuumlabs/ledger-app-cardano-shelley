#ifdef DEVEL

#include "common.h"
#include "hexUtils.h"
#include "test_utils.h"
#include "uiScreens.h"

void testcase_assetFingerprint(
        const char* policyIdHex,
        const char* assetNameHex,
        const char* expected
)
{
	PRINTF("testcase %s %s\n", policyIdHex, assetNameHex);

	uint8_t policyId[28];
	decode_hex(policyIdHex, policyId, SIZEOF(policyId));

	uint8_t assetName[32];
	decode_hex(assetNameHex, assetName, SIZEOF(assetName));
    size_t assetNameSize = strlen(assetNameHex) / 2;

	char fingerprint[200];

	deriveAssetFingerprint(
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


void run_uiScreens_test()
{
	test_assetFingerprint();
}

#endif
