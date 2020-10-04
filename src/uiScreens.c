#include "uiScreens.h"
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

	char pathStr[120];
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
			        "Byron account %u  ", account
			);
		} else if (bip44_hasShelleyPrefix(path)) {
			snprintf(
			        accountDescription, SIZEOF(accountDescription),
			        "Account %u  ", account
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

void ui_displayAmountScreen(
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

void ui_displayMarginScreen(
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
		ASSERT(strlen(marginStr) < SIZEOF(marginStr) - 1);
	}

	TRACE("%s", marginStr);

	ui_displayPaginatedText(
	        "Profit margin",
	        marginStr,
	        callback
	);
}
