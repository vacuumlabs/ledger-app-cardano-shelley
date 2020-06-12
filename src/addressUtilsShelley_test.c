#ifdef DEVEL

#include "addressUtilsShelley.h"
#include "test_utils.h"
#include "hex_utils.h"
#include "bip44.h"

// Note(ppershing): Used in macros to have (parenthesis) => {initializer} magic
#define UNWRAP(...) __VA_ARGS__

#define HD HARDENED_BIP32
#define MAX_ADDRESS_LENGTH 128

static void pathSpec_init(bip44_path_t* pathSpec, const uint32_t* pathArray, uint32_t pathLength)
{
	pathSpec->length = pathLength;
	os_memmove(pathSpec->path, pathArray, pathLength * 4);
}

static void testcase_deriveAddressShelley(uint8_t header, const uint32_t* path, uint32_t pathLen,
        const char* stakingKeyHashHex, const certificatePointer_t* stakingKeyPointer,
        const char* expectedHex)
{
	bip44_path_t pathSpec;
	pathSpec_init(&pathSpec, path, pathLen);

	PRINTF("testcase_deriveAddressShelley 0x%02x ", header);
	bip44_PRINTF(&pathSpec);
    if (stakingKeyHashHex != NULL)
        PRINTF(" %s", stakingKeyHashHex);
    if (stakingKeyPointer != NULL) {
        PRINTF(" (%d, %d, %d)", stakingKeyPointer->blockIndex, stakingKeyPointer->txIndex, stakingKeyPointer->certificateIndex);
    }
	PRINTF("\n");

	uint8_t address[MAX_ADDRESS_LENGTH];
    size_t addressSize = 0;
    switch (getAddressType(header)) {
        case BASE:
            if (stakingKeyHashHex == NULL) {
                addressSize = deriveAddress_base_accountStakingKey(
                    header, &pathSpec, address, SIZEOF(address));
            } else {
				uint8_t stakingKeyHashBytes[PUBLIC_KEY_HASH_LENGTH];
                ASSERT(strlen(stakingKeyHashHex) == 2 * PUBLIC_KEY_HASH_LENGTH);
				parseHexString(stakingKeyHashHex, stakingKeyHashBytes, SIZEOF(stakingKeyHashBytes));
                addressSize = deriveAddress_base_foreignStakingKey(
                    header, &pathSpec, stakingKeyHashBytes, address, SIZEOF(address));
            }
            break;
        case POINTER:
            ASSERT(stakingKeyPointer != NULL);
            addressSize = deriveAddress_pointer(header, &pathSpec, stakingKeyPointer, address, SIZEOF(address));
            break;
        case ENTERPRISE:
            addressSize = deriveAddress_enterprise(header, &pathSpec, address, SIZEOF(address));
            break;
        case BYRON:
            addressSize = deriveAddress_byron(header, &pathSpec, address, SIZEOF(address));
            break;
        case REWARD:
            addressSize = deriveAddress_reward(header, &pathSpec, address, SIZEOF(address));
            break;
        default:
            ASSERT(false);
    }

	uint8_t expected[MAX_ADDRESS_LENGTH];
	size_t expectedSize = parseHexString(expectedHex, expected, SIZEOF(expected));

	EXPECT_EQ(addressSize, expectedSize);
	EXPECT_EQ_BYTES(address, expected, expectedSize);
}

static void testAddressDerivation()
{
#define NONE 149837493 // not supposed to be used
#define NO_STAKING_KEY_POINTER (NONE, NONE, NONE)
#define NO_STAKING_KEY_HASH NULL
#define TESTCASE(header_, path_, stakingKeyHashHex_, stakingKeyPointer_, expected_) \
	{ \
		uint32_t path[] = { UNWRAP path_ }; \
        certificatePointer_t p = { UNWRAP stakingKeyPointer_ }; \
        certificatePointer_t *stakingKeyPointer = (p.blockIndex != NONE) ? &p : NULL; \
		testcase_deriveAddressShelley(header_, path, ARRAY_LEN(path), stakingKeyHashHex_, stakingKeyPointer, expected_); \
	}

	TESTCASE(
	        BYRON | 0x00, (HD + 44, HD + 1815, HD + 0, 1, 55), NO_STAKING_KEY_HASH, NO_STAKING_KEY_POINTER,
	        "82d818582183581cb1999ee43d0c3a9fe4a1a5d959ae87069781fbb7f60ff7e8e0136881a0001ad7ed912f"
	);

    /*
    spending_key: b'b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb'
    spending part (hash): b'5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3'
    staking_key: b'66610efd336e1137c525937b76511fbcf2a0e6bcf0d340a67bcb39bc870d85e8'
    staking part (hash): b'1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c'
    header: b'03'
    address: b'035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c'
    human readable: addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqdquehe
    */    
	TESTCASE(
	        BASE | 0x03, (HD + 1852, HD + 1815, HD + 0, 0, 1), NO_STAKING_KEY_HASH, NO_STAKING_KEY_POINTER,
	        "035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"
            // bech32: addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqdquehe
	);
	TESTCASE(
	        BASE | 0x00, (HD + 1852, HD + 1815, HD + 0, 0, 1), NO_STAKING_KEY_HASH, NO_STAKING_KEY_POINTER,
	        "005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"
            // bech32: addr1qr0z6pge8kmqfvp3zmzdkp68rndxhnnxexxvyvpnp49vdx2m8v99fxq0yhzmv6al5873rv5mk7u2tyhtfkyymh45ayjquge8kw
	);
	TESTCASE(
	        BASE | 0x00, (HD + 1852, HD + 1815, HD + 0, 0, 1), "1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c", NO_STAKING_KEY_POINTER,
	        "005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c"
            // bech32: addr1qr0z6pge8kmqfvp3zmzdkp68rndxhnnxexxvyvpnp49vdx2m8v99fxq0yhzmv6al5873rv5mk7u2tyhtfkyymh45ayjquge8kw
	);
    /*
    spending_key: b'b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb'
    spending part (hash): b'5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3'
    staking part (hash): b'122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277'
    header: b'03'
    address: b'035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277'
    human readable: addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmswz93l5
    */
	TESTCASE(
	        BASE | 0x03, (HD + 1852, HD + 1815, HD + 0, 0, 1), "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277", NO_STAKING_KEY_POINTER,
	        "035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277"
            // bech32: addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmswz93l5
	);

	TESTCASE(
	        POINTER | 0x00, (HD + 1852, HD + 1815, HD + 0, 0, 1), NO_STAKING_KEY_HASH, (1, 2, 3),
	        "405a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3010203"
            // bech32: addr1gpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcpqgpsh506pr
	);
	TESTCASE(
	        POINTER | 0x03, (HD + 1852, HD + 1815, HD + 0, 0, 1), NO_STAKING_KEY_HASH, (24157, 177, 42),
	        "435a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b381bc5d81312a"
            // bech32: addr1gdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vuph3wczvf288aeyu
	);
	TESTCASE(
	        POINTER | 0x03, (HD + 1852, HD + 1815, HD + 0, 0, 1), NO_STAKING_KEY_HASH, (0, 0, 0),
	        "435a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3000000"
            // bech32: addr1gdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcqqqqqnnd32q
	);

	TESTCASE(
	        ENTERPRISE | 0x00, (HD + 1852, HD + 1815, HD + 0, 0, 1), NO_STAKING_KEY_HASH, NO_STAKING_KEY_POINTER,
	        "605a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3"
            // bech32: addr1vpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vc93wyej
	);
	TESTCASE(
	        ENTERPRISE | 0x03, (HD + 1852, HD + 1815, HD + 0, 0, 1), NO_STAKING_KEY_HASH, NO_STAKING_KEY_POINTER,
	        "635a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3"
            // bech32: addr1vdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vc9wh7em
	);

    // TODO add more for REWARD etc.

#undef TESTCASE
#undef NO_STAKING_KEY_HASH
#undef NO_STAKING_KEY_POINTER
#undef NONE
}


void run_addressUtilsShelley_test()
{
	testAddressDerivation();
}

#endif
