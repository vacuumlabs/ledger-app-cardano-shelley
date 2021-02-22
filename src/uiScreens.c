#include "uiScreens.h"
#include "bech32.h"
#include "cardanoCertificates.h"
#include "hexUtils.h"
#include "ipUtils.h"
#include "textUtils.h"
#include "signTx.h"
#include "signTxPoolRegistration.h"


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

	ASSERT(bip44_hasValidCardanoWalletPrefix(path));
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

void ui_displayTokenNameScreen(
        token_amount_t* token,
        ui_callback_fn_t callback
)
{
	if (str_isAsciiPrintableBuffer(token->assetNameBytes, token->assetNameSize)) {
		char name[ASSET_NAME_SIZE_MAX + 1];
		ASSERT(token->assetNameSize + 1 <= SIZEOF(name));
		os_memmove(name, token->assetNameBytes, token->assetNameSize);
		name[token->assetNameSize] = '\0';

		bool isEmpty = (token->assetNameSize == 0);

		ui_displayPaginatedText(
		        (isEmpty) ? "Asset name is empty" : "Asset name (ASCII):",
		        name,
		        callback
		);
	} else {
		ui_displayHexBufferScreen(
		        "Asset name (hex):",
		        token->assetNameBytes, token->assetNameSize,
		        callback
		);
	}
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

#define BECH32_BUFFER_SIZE_MAX 150
#define BECH32_PREFIX_LENGTH_MAX 10

// works for bufferSize <= 150 and prefix length <= 10
void ui_displayBech32Screen(
        const char* screenHeader,
        const char* bech32Prefix,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
)
{
	{
		// assert inputs
		ASSERT(strlen(screenHeader) > 0);

		ASSERT(strlen(bech32Prefix) > 0);
		ASSERT(strlen(bech32Prefix) <= BECH32_PREFIX_LENGTH_MAX);

		ASSERT(bufferSize <= BECH32_BUFFER_SIZE_MAX);
	}

	char encodedStr[10 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX]; // rough upper bound on required size
	explicit_bzero(encodedStr, SIZEOF(encodedStr));

	{
		size_t len = bech32_encode(bech32Prefix, buffer, bufferSize, encodedStr, SIZEOF(encodedStr));

		ASSERT(len == strlen(encodedStr));
		ASSERT(len + 1 <= SIZEOF(encodedStr));
	}

	ui_displayPaginatedText(
	        screenHeader,
	        encodedStr,
	        callback
	);
}

void ui_displayPoolMarginScreen(
        uint64_t marginNumerator, uint64_t marginDenominator,
        ui_callback_fn_t callback
)
{
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

		switch (owner->descriptionKind) {

		case DATA_DESCRIPTION_HASH:
			ASSERT(SIZEOF(owner->keyHash) == ADDRESS_KEY_HASH_LENGTH);
			break;

		case DATA_DESCRIPTION_PATH:
			ASSERT(bip44_isValidStakingKeyPath(&owner->path));
			break;

		default:
			ASSERT(false);
		}
	}

	char ownerDescription[BIP44_MAX_PATH_STRING_LENGTH + MAX_HUMAN_REWARD_ACCOUNT_SIZE + 1];

	explicit_bzero(ownerDescription, SIZEOF(ownerDescription));
	size_t descLen = 0; // owner description length

	if (owner->descriptionKind == DATA_DESCRIPTION_PATH) {
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

		{
			uint8_t rewardAddress[REWARD_ACCOUNT_SIZE];

			switch (owner->descriptionKind) {
			case DATA_DESCRIPTION_PATH: {
				constructRewardAddressFromKeyPath(
				        &owner->path, networkId, rewardAddress, SIZEOF(rewardAddress)
				);
				break;
			}
			case DATA_DESCRIPTION_HASH: {
				constructRewardAddressFromKeyHash(
				        networkId,
				        owner->keyHash, SIZEOF(owner->keyHash),
				        rewardAddress, SIZEOF(rewardAddress)
				);
				break;
			}
			default:
				ASSERT(false);
			}

			descLen += humanReadableAddress(
			                   rewardAddress, SIZEOF(rewardAddress),
			                   ownerDescription + descLen, SIZEOF(ownerDescription) - descLen
			           );
		}
		ASSERT(descLen == strlen(ownerDescription));
		ASSERT(descLen + 1 <= SIZEOF(ownerDescription));
	}

	char firstLine[20];
	explicit_bzero(firstLine, SIZEOF(firstLine));
	{
		snprintf(firstLine, SIZEOF(firstLine), "Owner #%u", ownerIndex + 1);
	}

	ui_displayPaginatedText(
	        firstLine,
	        ownerDescription,
	        callback
	);
}

void ui_displayIpv4Screen(
        ipv4_t* ipv4,
        ui_callback_fn_t callback
)
{
	char ipStr[IPV4_STR_SIZE_MAX];
	explicit_bzero(ipStr, SIZEOF(ipStr));

	if (ipv4->isNull) {
		snprintf(ipStr, SIZEOF(ipStr), "(none)");
	} else {
		inet_ntop4(ipv4->ip, ipStr, SIZEOF(ipStr));
	}

	ASSERT(strlen(ipStr) + 1 <= SIZEOF(ipStr));

	ui_displayPaginatedText(
	        "IPv4 address",
	        ipStr,
	        callback
	);
}

void ui_displayIpv6Screen(
        ipv6_t* ipv6,
        ui_callback_fn_t callback
)
{
	char ipStr[IPV6_STR_SIZE_MAX];
	explicit_bzero(ipStr, SIZEOF(ipStr));

	if (ipv6->isNull) {
		snprintf(ipStr, SIZEOF(ipStr), "(none)");
	} else {
		inet_ntop6(ipv6->ip, ipStr, SIZEOF(ipStr));
	}

	ASSERT(strlen(ipStr) + 1 <= SIZEOF(ipStr));

	ui_displayPaginatedText(
	        "IPv6 address",
	        ipStr,
	        callback
	);
}

void ui_displayIpPortScreen(
        ipport_t* port,
        ui_callback_fn_t callback
)
{
	char portStr[sizeof "65536"];
	explicit_bzero(portStr, SIZEOF(portStr));

	if (port->isNull) {
		snprintf(portStr, SIZEOF(portStr), "(none)");
	} else {
		snprintf(portStr, SIZEOF(portStr), "%u", port->number);
	}

	ASSERT(strlen(portStr) + 1 <= SIZEOF(portStr));

	ui_displayPaginatedText(
	        "Port",
	        portStr,
	        callback
	);
}
