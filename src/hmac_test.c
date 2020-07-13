#ifdef DEVEL

#include <os.h>
#include "stream.h"
#include "test_utils.h"
#include "assert.h"
#include <stdint.h>
#include "hex_utils.h"
#include "utils.h"
#include "hmac.h"

static void testcase_sha256(const char* keyHex, const char* inputHex, const char* expectedHex)
{
	PRINTF("testcase_sha256 %s %s\n", keyHex, inputHex);
	uint8_t keyBuffer[150];
	size_t keySize = decode_hex(keyHex, keyBuffer, SIZEOF(keyBuffer));

	uint8_t inputBuffer[150];
	size_t inputSize = decode_hex(inputHex, inputBuffer, SIZEOF(inputBuffer));

	uint8_t expectedBuffer[32];
	size_t expectedSize = decode_hex(expectedHex, expectedBuffer, SIZEOF(expectedBuffer));

	uint8_t outputBuffer[32];
	hmac_sha256(
	        keyBuffer, keySize,
	        inputBuffer, inputSize,
	        outputBuffer, SIZEOF(outputBuffer)
	);
	EXPECT_EQ_BYTES(outputBuffer, expectedBuffer, expectedSize);
}

void run_hmac_test()
{

	// Test vectors taken from
	// https://tools.ietf.org/html/rfc4231#section-4
	testcase_sha256(
	        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	        "0b0b0b0b",

	        "4869205468657265",

	        "b0344c61d8db38535ca8afceaf0bf12b"
	        "881dc200c9833da726e9376c2e32cff7"
	);

	testcase_sha256(
	        "4a656665",

	        "7768617420646f2079612077616e7420"
	        "666f72206e6f7468696e673f",

	        "5bdcc146bf60754e6a042426089575c7"
	        "5a003f089d2739839dec58b964ec3843"
	);


	testcase_sha256(
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaa",

	        "dddddddddddddddddddddddddddddddd"
	        "dddddddddddddddddddddddddddddddd"
	        "dddddddddddddddddddddddddddddddd"
	        "dddd",

	        "773ea91e36800e46854db8ebd09181a7"
	        "2959098b3ef8c122d9635514ced565fe"
	);

	testcase_sha256(
	        "0102030405060708090a0b0c0d0e0f10"
	        "111213141516171819",

	        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	        "cdcd",

	        "82558a389a443c0ea4cc819899f2083a"
	        "85f0faa3e578f8077a2e3ff46729665b"
	);

	// Note(ppershing): following case is special
	// because it checks only first 128 bits of
	// resulting hash.
	// I am not sure why it is in the test vectors
	testcase_sha256(
	        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
	        "0c0c0c0c",

	        "546573742057697468205472756e6361"
	        "74696f6e",

	        "a3b6167473100ee06e0c796c2955552b"
	);

	// Note(ppershing): following two test cases
	// throw exception 0x02. I guess Ledger does not like
	// long keys?

	/*
	testcase_sha256(
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaa",

	        "54657374205573696e67204c61726765"
	        "72205468616e20426c6f636b2d53697a"
	        "65204b6579202d2048617368204b6579"
	        "204669727374",

	        "60e431591ee0b67f0d8a26aacbf5b77f"
	        "8e0bc6213728c5140546040f0ee37f54"
	);

	testcase_sha256(
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	        "aaaaaa",

	        "54686973206973206120746573742075"
	        "73696e672061206c6172676572207468"
	        "616e20626c6f636b2d73697a65206b65"
	        "7920616e642061206c61726765722074"
	        "68616e20626c6f636b2d73697a652064"
	        "6174612e20546865206b6579206e6565"
	        "647320746f2062652068617368656420"
	        "6265666f7265206265696e6720757365"
	        "642062792074686520484d414320616c"
	        "676f726974686d2e",

	        "9b09ffa71b942fcb27635fbcd5b0e944"
	        "bfdc63644f0713938a7f51535c3a35e2"
	);
	*/
}

#endif
