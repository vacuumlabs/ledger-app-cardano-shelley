#include "uiScreens.h"
#include "bech32.h"
#include "hexUtils.h"
#include "textUtils.h"
#include "cardanoCertificates.h"

void ui_displayPathScreen(
        const char* screenHeader,
        const bip44_path_t* path,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);

	char pathStr[1 + BIP44_MAX_PATH_STRING_LENGTH];
	bip44_printToStr(path, pathStr, SIZEOF(pathStr));

	ui_displayPaginatedText(
	        screenHeader,
	        pathStr,
	        callback
	);
}

// the given path typically corresponds to an account
// if it contains anything more, we display just the whole path
void ui_displayAccountScreen(
        const char* screenHeader,
        const bip44_path_t* path,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);

	ASSERT(bip44_hasValidCardanoPrefix(path));
	ASSERT(bip44_containsAccount(path));

	char accountDescription[160];
	explicit_bzero(accountDescription, SIZEOF(accountDescription));

	if (bip44_hasReasonableAccount(path) && !bip44_containsMoreThanAccount(path)) {
		uint32_t account = unharden(bip44_getAccount(path));
		if (bip44_hasByronPrefix(path)) {
			snprintf(
			        accountDescription, SIZEOF(accountDescription),
			        "Byron account #%u  ", account + 1
			);
		} else if (bip44_hasShelleyPrefix(path)) {
			snprintf(
			        accountDescription, SIZEOF(accountDescription),
			        "Account #%u  ", account + 1
			);
		} else {
			ASSERT(false);
		}
	}

	{
		size_t len = strlen(accountDescription);
		ASSERT(len + 1 < SIZEOF(accountDescription));

		bip44_printToStr(path, accountDescription + len, SIZEOF(accountDescription) - len);
	}

	{
		size_t len = strlen(accountDescription);
		ASSERT(len > 0);
		ASSERT(len + 1 < SIZEOF(accountDescription));
	}

	ui_displayPaginatedText(
	        screenHeader,
	        accountDescription,
	        callback
	);
}

void ui_displayAddressScreen(
        const char* screenHeader,
        const uint8_t* addressBuffer, size_t addressSize,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);
	ASSERT(addressSize > 0);
	ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

	char humanAddress[MAX_HUMAN_ADDRESS_SIZE];
	explicit_bzero(humanAddress, SIZEOF(humanAddress));

	size_t length = humanReadableAddress(
	                        addressBuffer, addressSize,
	                        humanAddress, SIZEOF(humanAddress)
	                );
	ASSERT(length > 0);
	ASSERT(strlen(humanAddress) == length);

	ui_displayPaginatedText(
	        screenHeader,
	        humanAddress,
	        callback
	);
}

static const char STAKING_HEADING_PATH[]    = "Staking key path: ";
static const char STAKING_HEADING_HASH[]    = "Staking key hash: ";
static const char STAKING_HEADING_POINTER[] = "Staking key pointer: ";
static const char STAKING_HEADING_WARNING[] = "WARNING: ";

void ui_displayStakingInfoScreen(
        const addressParams_t* addressParams,
        ui_callback_fn_t callback
)
{
	const char *heading = NULL;
	char stakingInfo[120];
	explicit_bzero(stakingInfo, SIZEOF(stakingInfo));

	switch (addressParams->stakingChoice) {

	case NO_STAKING:
		if (addressParams->type == BYRON) {
			heading = STAKING_HEADING_WARNING;
			strncpy(stakingInfo, "legacy Byron address (no staking rewards)", SIZEOF(stakingInfo));

		} else if (addressParams->type == ENTERPRISE) {
			heading = STAKING_HEADING_WARNING;
			strncpy(stakingInfo, "no staking rewards", SIZEOF(stakingInfo));

		} else if (addressParams->type == REWARD) {
			heading = STAKING_HEADING_WARNING;
			strncpy(stakingInfo, "reward account", SIZEOF(stakingInfo));

		} else {
			ASSERT(false);
		}
		break;

	case STAKING_KEY_PATH:
		heading = STAKING_HEADING_PATH;
		bip44_printToStr(&addressParams->stakingKeyPath, stakingInfo, SIZEOF(stakingInfo));
		break;

	case STAKING_KEY_HASH:
		heading = STAKING_HEADING_HASH;
		size_t length = encode_hex(
		                        addressParams->stakingKeyHash, SIZEOF(addressParams->stakingKeyHash),
		                        stakingInfo, SIZEOF(stakingInfo)
		                );
		ASSERT(length == strlen(stakingInfo));
		ASSERT(length == 2 * SIZEOF(addressParams->stakingKeyHash));
		break;

	case BLOCKCHAIN_POINTER:
		heading = STAKING_HEADING_POINTER;
		printBlockchainPointerToStr(addressParams->stakingKeyBlockchainPointer, stakingInfo, SIZEOF(stakingInfo));
		break;

	default:
		ASSERT(false);
	}

	ASSERT(heading != NULL);
	ASSERT(strlen(stakingInfo) > 0);

	ui_displayPaginatedText(
	        heading,
	        stakingInfo,
	        callback
	);
}

#define ASSET_FINGERPRINT_SIZE 20

size_t deriveAssetFingerprint(
        uint8_t* policyId,
        size_t policyIdSize,
        uint8_t* assetName,
        size_t assetNameSize,
        char* fingerprint,
        size_t fingerprintMaxSize
)
{
	ASSERT(policyIdSize == MINTING_POLICY_ID_SIZE);

	uint8_t hashInput[MINTING_POLICY_ID_SIZE + ASSET_NAME_SIZE_MAX];
	const size_t hashInputSize = policyIdSize + assetNameSize;
	{
		write_view_t view = make_write_view(hashInput, hashInput + SIZEOF(hashInput));
		view_appendData(&view, policyId, policyIdSize);
		view_appendData(&view, assetName, assetNameSize);
		ASSERT(view_processedSize(&view) == hashInputSize);
	}

	uint8_t fingerprintBuffer[ASSET_FINGERPRINT_SIZE];
	blake2b_160_hash(hashInput, hashInputSize, fingerprintBuffer, SIZEOF(fingerprintBuffer));

	size_t len = bech32_encode("asset", fingerprintBuffer, SIZEOF(fingerprintBuffer), fingerprint, fingerprintMaxSize);
	ASSERT(len == strlen(fingerprint));
	ASSERT(len + 1 <= fingerprintMaxSize);

	return len;
}

void ui_displayAssetFingerprintScreen(
        token_group_t* tokenGroup,
        token_amount_t* token,
        ui_callback_fn_t callback
)
{
	char fingerprint[200];

	deriveAssetFingerprint(
	        tokenGroup->policyId, SIZEOF(tokenGroup->policyId),
	        token->assetNameBytes, token->assetNameSize,
	        fingerprint, SIZEOF(fingerprint)
	);
	ASSERT(strlen(fingerprint) + 1 <= SIZEOF(fingerprint));

	ui_displayPaginatedText(
	        "Asset fingerprint",
	        fingerprint,
	        callback
	);
}

void ui_displayAdaAmountScreen(
        const char* screenHeader,
        uint64_t amount,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);

	char adaAmountStr[50];
	str_formatAdaAmount(amount, adaAmountStr, SIZEOF(adaAmountStr));

	ui_displayPaginatedText(
	        screenHeader,
	        adaAmountStr,
	        callback
	);
}

void ui_displayUint64Screen(
        const char* screenHeader,
        uint64_t value,
        ui_callback_fn_t callback
)
{
	char valueStr[30];
	str_formatUint64(value, valueStr, SIZEOF(valueStr));

	ui_displayPaginatedText(
	        screenHeader,
	        valueStr,
	        callback
	);
}

void ui_displayValidityBoundaryScreen(
        const char* screenHeader,
        uint64_t boundary,
        uint8_t networkId, uint32_t protocolMagic,
        ui_callback_fn_t callback
)
{
	char boundaryStr[30];
	explicit_bzero(boundaryStr, SIZEOF(boundaryStr));

	if ((networkId == MAINNET_NETWORK_ID) && (protocolMagic == MAINNET_PROTOCOL_MAGIC)) {
		// nicer formatting could only be used for mainnet
		// since it depends on network params that could differ for testnets
		str_formatValidityBoundary(boundary, boundaryStr, SIZEOF(boundaryStr));
		ui_displayPaginatedText(
		        screenHeader,
		        boundaryStr,
		        callback
		);
	} else {
		ui_displayUint64Screen(
		        screenHeader,
		        boundary,
		        callback
		);
	}
}

void ui_displayNetworkParamsScreen(
        const char* screenHeader,
        uint8_t networkId,
        uint32_t protocolMagic,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);
	ASSERT(isValidNetworkId(networkId));

	char networkParams[100];
	explicit_bzero(networkParams, SIZEOF(networkParams));

	snprintf(
	        networkParams, SIZEOF(networkParams),
	        "network id %d / protocol magic %u",
	        (int) networkId, (unsigned) protocolMagic
	);
	ASSERT(strlen(networkParams) + 1 < SIZEOF(networkParams));

	ui_displayPaginatedText(
	        screenHeader,
	        networkParams,
	        callback
	);
}

void ui_displayHexBufferScreen(
        const char* screenHeader,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(screenHeader) > 0);
	ASSERT(strlen(screenHeader) < BUFFER_SIZE_PARANOIA);
	ASSERT(bufferSize > 0);
	ASSERT(bufferSize <= 32); // this is used for hashes, all are <= 32 bytes

	char bufferHex[2 * 32 + 1];
	explicit_bzero(bufferHex, SIZEOF(bufferHex));

	size_t length = encode_hex(
	                        buffer, bufferSize,
	                        bufferHex, SIZEOF(bufferHex)
	                );
	ASSERT(length == strlen(bufferHex));
	ASSERT(length == 2 * bufferSize);

	ui_displayPaginatedText(
	        screenHeader,
	        bufferHex,
	        callback
	);
}

void ui_displayPoolIdScreen(
        const uint8_t* poolIdBuffer,
        size_t poolIdSize,
        ui_callback_fn_t callback
)
{
	{
		// assert inputs
		ASSERT(poolIdSize == POOL_KEY_HASH_LENGTH);
	}

	char poolIdStr[12 + 2 * POOL_KEY_HASH_LENGTH]; // rough upper bound on required size
	explicit_bzero(poolIdStr, SIZEOF(poolIdStr));

	{
		size_t len = bech32_encode("pool", poolIdBuffer, poolIdSize, poolIdStr, SIZEOF(poolIdStr));

		ASSERT(len == strlen(poolIdStr));
		ASSERT(len + 1 <= SIZEOF(poolIdStr));
	}

	ui_displayPaginatedText(
	        "Pool ID",
	        poolIdStr,
	        callback
	);
}

void ui_displayPoolMarginScreen(
        uint64_t marginNumerator, uint64_t marginDenominator,
        ui_callback_fn_t callback
)
{
	TRACE("%d %d", marginNumerator, marginDenominator);
	TRACE_BUFFER((uint8_t *) &marginNumerator, 8);
	TRACE_BUFFER((uint8_t *) &marginDenominator, 8);

	ASSERT(marginDenominator != 0);
	ASSERT(marginNumerator <= marginDenominator);
	ASSERT(marginDenominator <= MARGIN_DENOMINATOR_MAX);

	char marginStr[20];
	explicit_bzero(marginStr, SIZEOF(marginStr));

	{
		// marginPercentage is a multiple of 1/100th of 1%, i.e. the fractional part of the percentage has two digits
		// adding marginDenominator / 2 to have a rounded result
		uint64_t marginPercentage = (10000 * marginNumerator + (marginDenominator / 2)) / marginDenominator;
		ASSERT(marginPercentage <= 10000);

		unsigned int percentage = (unsigned int) marginPercentage;

		snprintf(marginStr, SIZEOF(marginStr), "%u.%u %%", percentage / 100, percentage % 100);
		ASSERT(strlen(marginStr) + 1 < SIZEOF(marginStr));
	}

	TRACE("%s", marginStr);

	ui_displayPaginatedText(
	        "Profit margin",
	        marginStr,
	        callback
	);
}

void ui_displayPoolOwnerScreen(
        const pool_owner_t* owner,
        uint32_t ownerIndex,
        uint8_t networkId,
        ui_callback_fn_t callback
)
{
	{
		// assert inputs
		ASSERT(isValidNetworkId(networkId));
		ASSERT(ownerIndex < POOL_MAX_OWNERS);

		switch (owner->ownerType) {

		case SIGN_TX_POOL_OWNER_TYPE_KEY_HASH:
			ASSERT(SIZEOF(owner->keyHash) == ADDRESS_KEY_HASH_LENGTH);
			break;

		case SIGN_TX_POOL_OWNER_TYPE_PATH:
			ASSERT(bip44_isValidStakingKeyPath(&owner->path));
			break;

		default:
			ASSERT(false);
		}
	}

	// we display the owner as bech32-encoded reward address for his staking key
	uint8_t rewardAddress[1 + ADDRESS_KEY_HASH_LENGTH];
	{
		if (owner->ownerType == SIGN_TX_POOL_OWNER_TYPE_PATH) {
			addressParams_t rewardAddressParams = {
				.type = REWARD,
				.networkId = networkId,
				.spendingKeyPath = owner->path,
				.stakingChoice = NO_STAKING,
			};

			deriveAddress(
			        &rewardAddressParams,
			        rewardAddress, SIZEOF(rewardAddress)
			);
		} else {
			constructRewardAddress(
			        networkId,
			        owner->keyHash, SIZEOF(owner->keyHash),
			        rewardAddress, SIZEOF(rewardAddress)
			);
		}
	}

	char firstLine[20];
	explicit_bzero(firstLine, SIZEOF(firstLine));
	{
		snprintf(firstLine, SIZEOF(firstLine), "Owner #%u", ownerIndex + 1);
	}

	char ownerDescription[BIP44_MAX_PATH_STRING_LENGTH + MAX_HUMAN_ADDRESS_SIZE + 1];
	explicit_bzero(ownerDescription, SIZEOF(ownerDescription));
	size_t descLen = 0; // owner description length

	if (owner->ownerType == SIGN_TX_POOL_OWNER_TYPE_PATH) {
		descLen += bip44_printToStr(&owner->path, ownerDescription, SIZEOF(ownerDescription));
	}

	{
		// add owner (represented as bech32-encoded reward account for owner's staking key)
		ASSERT(descLen <= BIP44_MAX_PATH_STRING_LENGTH);
		ASSERT(descLen + 1 <= SIZEOF(ownerDescription));

		if (descLen > 0) {
			// add a space after path if the path is present
			ASSERT(descLen + 2 <= SIZEOF(ownerDescription));
			ownerDescription[descLen++] = ' ';
			ownerDescription[descLen] = '\0';
		}

		descLen += humanReadableAddress(
		                   rewardAddress, SIZEOF(rewardAddress),
		                   ownerDescription + descLen, SIZEOF(ownerDescription) - descLen
		           );
		ASSERT(descLen == strlen(ownerDescription));
		ASSERT(descLen + 1 <= SIZEOF(ownerDescription));
	}

	ui_displayPaginatedText(
	        firstLine,
	        ownerDescription,
	        callback
	);
}
