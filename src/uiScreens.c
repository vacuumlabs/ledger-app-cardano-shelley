#include "uiScreens.h"
#include "bech32.h"
#include "cardano.h"
#include "hexUtils.h"
#include "ipUtils.h"
#include "textUtils.h"
#include "signTx.h"
#include "signTxPoolRegistration.h"
#include "tokens.h"


#define BECH32_BUFFER_SIZE_MAX 150
#define BECH32_PREFIX_LENGTH_MAX 16

// encodes a buffer into bech32 and displays it (works for bufferSize <= 150 and prefix length <= 12)
void ui_displayBech32Screen(
        const char* firstLine,
        const char* bech32Prefix,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
)
{
	{
		// assert inputs
		ASSERT(strlen(firstLine) > 0);
		ASSERT(strlen(firstLine) < BUFFER_SIZE_PARANOIA);

		ASSERT(strlen(bech32Prefix) > 0);
		ASSERT(strlen(bech32Prefix) <= BECH32_PREFIX_LENGTH_MAX);

		ASSERT(bufferSize <= BECH32_BUFFER_SIZE_MAX);
	}

	// rough upper bound on required size is used
	char encodedStr[11 + BECH32_PREFIX_LENGTH_MAX + 2 * BECH32_BUFFER_SIZE_MAX] = {0};
	explicit_bzero(encodedStr, SIZEOF(encodedStr));

	{
		size_t len = bech32_encode(bech32Prefix, buffer, bufferSize, encodedStr, SIZEOF(encodedStr));

		ASSERT(len == strlen(encodedStr));
		ASSERT(len + 1 < SIZEOF(encodedStr));
	}

	ui_displayPaginatedText(
	        firstLine,
	        encodedStr,
	        callback
	);
}

void ui_displayHexBufferScreen(
        const char* firstLine,
        const uint8_t* buffer, size_t bufferSize,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(firstLine) > 0);
	ASSERT(strlen(firstLine) < BUFFER_SIZE_PARANOIA);
	ASSERT(bufferSize > 0);
	ASSERT(bufferSize <= 32); // this is used for hashes, all are <= 32 bytes

	char bufferHex[2 * 32 + 1] = {0};
	explicit_bzero(bufferHex, SIZEOF(bufferHex));

	size_t length = encode_hex(
	                        buffer, bufferSize,
	                        bufferHex, SIZEOF(bufferHex)
	                );
	ASSERT(length == strlen(bufferHex));
	ASSERT(length == 2 * bufferSize);

	ui_displayPaginatedText(
	        firstLine,
	        bufferHex,
	        callback
	);
}

void ui_displayPathScreen(
        const char* firstLine,
        const bip44_path_t* path,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(firstLine) > 0);
	ASSERT(strlen(firstLine) < BUFFER_SIZE_PARANOIA);

	char pathStr[BIP44_PATH_STRING_SIZE_MAX + 1] = {0};
	explicit_bzero(pathStr, SIZEOF(pathStr));
	bip44_printToStr(path, pathStr, SIZEOF(pathStr));
	ASSERT(strlen(pathStr) + 1 < SIZEOF(pathStr));

	ui_displayPaginatedText(
	        firstLine,
	        pathStr,
	        callback
	);
}

__noinline_due_to_stack__
static void _ui_displayAccountWithDescriptionScreen(
        const char* firstLine,
        const bip44_path_t* path,
        bool showAccountDescription,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(firstLine) > 0);
	ASSERT(strlen(firstLine) < BUFFER_SIZE_PARANOIA);

	ASSERT(bip44_hasOrdinaryWalletKeyPrefix(path));
	ASSERT(bip44_containsAccount(path));

	char accountDescription[160] = {0};
	explicit_bzero(accountDescription, SIZEOF(accountDescription));

	if (showAccountDescription) {
		uint32_t account = unharden(bip44_getAccount(path));
		STATIC_ASSERT(sizeof(account + 1) <= sizeof(unsigned), "oversized type for %u");
		STATIC_ASSERT(!IS_SIGNED(account + 1), "signed type for %u");
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
	        firstLine,
	        accountDescription,
	        callback
	);
}

// the given path typically corresponds to an account
// if it contains anything more, we display just the whole path
void ui_displayGetPublicKeyPathScreen(
        const bip44_path_t* path,
        ui_callback_fn_t callback
)
{
	switch (bip44_classifyPath(path)) {
	case PATH_POOL_COLD_KEY: {
		ui_displayPathScreen("Export cold public key", path, callback);
		return;
	}

	case PATH_ORDINARY_ACCOUNT: {
		_ui_displayAccountWithDescriptionScreen("Export public key", path, true, callback);
		return;
	}

	default:
		ui_displayPathScreen("Export public key", path,	callback);
		return;
	}

}

void ui_displayStakingKeyScreen(
        const bip44_path_t* stakingPath,
        ui_callback_fn_t callback
)
{
	ASSERT(bip44_isOrdinaryStakingKeyPath(stakingPath));

	bool showAccountDescription = bip44_isPathReasonable(stakingPath);

	_ui_displayAccountWithDescriptionScreen(
	        "Staking key",
	        stakingPath,
	        showAccountDescription,
	        callback
	);
}

// bech32 for Shelley, base58 for Byron
void ui_displayAddressScreen(
        const char* firstLine,
        const uint8_t* addressBuffer, size_t addressSize,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(firstLine) > 0);
	ASSERT(strlen(firstLine) < BUFFER_SIZE_PARANOIA);
	ASSERT(addressSize > 0);
	ASSERT(addressSize < BUFFER_SIZE_PARANOIA);

	char humanAddress[MAX_HUMAN_ADDRESS_SIZE] = {0};
	explicit_bzero(humanAddress, SIZEOF(humanAddress));

	size_t length = humanReadableAddress(
	                        addressBuffer, addressSize,
	                        humanAddress, SIZEOF(humanAddress)
	                );
	ASSERT(length > 0);
	ASSERT(strlen(humanAddress) == length);

	ui_displayPaginatedText(
	        firstLine,
	        humanAddress,
	        callback
	);
}

// display bech32-encoded reward account preceded by staking key derivation path (if given)
static void _displayRewardAccountWithDescriptionScreen(
        const key_reference_type_t keyReferenceType,
        const bip44_path_t* path,
        const uint8_t* rewardAccountBuffer,
        const char* firstLine,
        ui_callback_fn_t callback
)
{
	char description[BIP44_PATH_STRING_SIZE_MAX + MAX_HUMAN_REWARD_ACCOUNT_SIZE + 2] = {0};
	explicit_bzero(description, SIZEOF(description));
	size_t descLen = 0; // description length

	if (keyReferenceType == KEY_REFERENCE_PATH) {
		descLen += bip44_printToStr(path, description, SIZEOF(description));
	}
	{
		// add bech32-encoded reward account
		ASSERT(descLen < BIP44_PATH_STRING_SIZE_MAX);
		ASSERT(descLen + 1 < SIZEOF(description));

		if (descLen > 0) {
			// add a space after path if the path is present
			ASSERT(descLen + 2 < SIZEOF(description));
			description[descLen++] = ' ';
			description[descLen] = '\0';
		}

		{
			descLen += humanReadableAddress(
			                   rewardAccountBuffer, REWARD_ACCOUNT_SIZE,
			                   description + descLen, SIZEOF(description) - descLen
			           );
		}
		ASSERT(descLen == strlen(description));
		ASSERT(descLen + 1 < SIZEOF(description));
	}

	ui_displayPaginatedText(
	        firstLine,
	        description,
	        callback
	);
}

// displays bech32-encoded reward account preceded by path (if given)
void ui_displayRewardAccountScreen(
        const reward_account_t* rewardAccount,
        uint8_t networkId,
        ui_callback_fn_t callback
)
{
	// WARNING: reward account must be displayed in full (not just a key derivation path)
	// because the network id security policy relies on it

	ASSERT(isValidNetworkId(networkId));

	uint8_t rewardAccountBuffer[REWARD_ACCOUNT_SIZE] = {0};
	char firstLine[32] = {0};
	explicit_bzero(firstLine, SIZEOF(firstLine));

	switch (rewardAccount->keyReferenceType) {

	case KEY_REFERENCE_PATH: {
		ASSERT(bip44_isOrdinaryStakingKeyPath(&rewardAccount->path));

		{
			uint32_t account = unharden(bip44_getAccount(&rewardAccount->path));
			STATIC_ASSERT(sizeof(account + 1) <= sizeof(unsigned), "oversized type for %u");
			STATIC_ASSERT(!IS_SIGNED(account + 1), "signed type for %u");
			snprintf(
			        firstLine, SIZEOF(firstLine),
			        "Reward account #%u  ", account + 1
			);
		}

		constructRewardAddressFromKeyPath(
		        &rewardAccount->path, networkId,
		        rewardAccountBuffer, SIZEOF(rewardAccountBuffer)
		);
		break;
	}

	case KEY_REFERENCE_HASH: {
		snprintf(
		        firstLine, SIZEOF(firstLine),
		        "Reward account"
		);

		STATIC_ASSERT(SIZEOF(rewardAccountBuffer) == REWARD_ACCOUNT_SIZE, "wrong reward account buffer size");
		STATIC_ASSERT(SIZEOF(rewardAccount->hashBuffer) == REWARD_ACCOUNT_SIZE, "wrong reward account hash buffer size");
		memmove(rewardAccountBuffer, rewardAccount->hashBuffer, REWARD_ACCOUNT_SIZE);
		break;
	}

	default:
		ASSERT(false);
	}

	{
		const size_t len = strlen(firstLine);
		ASSERT(len > 0);
		// make sure all the information is displayed to the user
		ASSERT(len + 1 < SIZEOF(firstLine));
	}

	_displayRewardAccountWithDescriptionScreen(
	        rewardAccount->keyReferenceType,
	        &rewardAccount->path,
	        rewardAccountBuffer,
	        firstLine,
	        callback
	);
}

void ui_displaySpendingInfoScreen(
        const addressParams_t* addressParams,
        ui_callback_fn_t callback
)
{
	switch (determineSpendingChoice(addressParams->type)) {

	case SPENDING_PATH: {
		ui_displayPathScreen(
		        "Spending path",
		        &addressParams->spendingKeyPath,
		        callback
		);
		return;
	}

	case SPENDING_SCRIPT_HASH: {
		ui_displayBech32Screen(
		        "Spending script hash",
		        "script",
		        addressParams->spendingScriptHash,
		        SIZEOF(addressParams->spendingScriptHash),
		        callback
		);
		return;
	}

	default: {
		// includes SPENDING_NONE
		ASSERT(false);
	}
	}
}

static const char STAKING_HEADING_PATH[]        = "Staking key path";
static const char STAKING_HEADING_KEY_HASH[]    = "Staking key hash";
static const char STAKING_HEADING_SCRIPT_HASH[] = "Staking script hash";
static const char STAKING_HEADING_POINTER[]     = "Staking key pointer";
static const char STAKING_HEADING_WARNING[]     = "WARNING:";

void ui_displayStakingInfoScreen(
        const addressParams_t* addressParams,
        ui_callback_fn_t callback
)
{
	const char* heading = NULL;
	char stakingInfo[120] = {0};
	explicit_bzero(stakingInfo, SIZEOF(stakingInfo));

	switch (addressParams->stakingDataSource) {

	case NO_STAKING: {
		switch (addressParams->type) {

		case BYRON:
			heading = STAKING_HEADING_WARNING;
			strncpy(stakingInfo, "legacy Byron address (no staking rewards)", SIZEOF(stakingInfo));
			break;

		case ENTERPRISE_KEY:
		case ENTERPRISE_SCRIPT:
			heading = STAKING_HEADING_WARNING;
			strncpy(stakingInfo, "no staking rewards", SIZEOF(stakingInfo));
			break;

		default:
			ASSERT(false);
		}
		break;
	}

	case STAKING_KEY_PATH: {
		heading = STAKING_HEADING_PATH;
		bip44_printToStr(&addressParams->stakingKeyPath, stakingInfo, SIZEOF(stakingInfo));
		break;
	}

	case STAKING_KEY_HASH: {
		heading = STAKING_HEADING_KEY_HASH;
		bech32_encode(
		        "stake_vkh", // shared keys never go into address directly
		        addressParams->stakingKeyHash, SIZEOF(addressParams->stakingKeyHash),
		        stakingInfo, SIZEOF(stakingInfo)
		);
		break;
	}

	case STAKING_SCRIPT_HASH: {
		heading = STAKING_HEADING_SCRIPT_HASH;
		bech32_encode(
		        "script",
		        addressParams->stakingScriptHash, SIZEOF(addressParams->stakingScriptHash),
		        stakingInfo, SIZEOF(stakingInfo)
		);
		break;
	}

	case BLOCKCHAIN_POINTER:
		heading = STAKING_HEADING_POINTER;
		printBlockchainPointerToStr(addressParams->stakingKeyBlockchainPointer, stakingInfo, SIZEOF(stakingInfo));
		break;


	default:
		ASSERT(false);
	}

	ASSERT(heading != NULL);
	ASSERT(strlen(stakingInfo) > 0);
	ASSERT(strlen(stakingInfo) + 1 < SIZEOF(stakingInfo));

	ui_displayPaginatedText(
	        heading,
	        stakingInfo,
	        callback
	);
}

void ui_displayAssetFingerprintScreen(
        const token_group_t* tokenGroup,
        const uint8_t* assetNameBytes, size_t assetNameSize,
        ui_callback_fn_t callback
)
{
	ASSERT(assetNameSize <= ASSET_NAME_SIZE_MAX);

	char fingerprint[200] = {0};
	explicit_bzero(fingerprint, SIZEOF(fingerprint));

	deriveAssetFingerprintBech32(
	        tokenGroup->policyId, SIZEOF(tokenGroup->policyId),
	        assetNameBytes, assetNameSize,
	        fingerprint, SIZEOF(fingerprint)
	);
	ASSERT(strlen(fingerprint) + 1 < SIZEOF(fingerprint));

	ui_displayPaginatedText(
	        "Asset fingerprint",
	        fingerprint,
	        callback
	);
}

void ui_displayAdaAmountScreen(
        const char* firstLine,
        uint64_t amount,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(firstLine) > 0);
	ASSERT(strlen(firstLine) < BUFFER_SIZE_PARANOIA);

	char adaAmountStr[50] = {0};
	explicit_bzero(adaAmountStr, SIZEOF(adaAmountStr));
	str_formatAdaAmount(amount, adaAmountStr, SIZEOF(adaAmountStr));

	ui_displayPaginatedText(
	        firstLine,
	        adaAmountStr,
	        callback
	);
}

void ui_displayTokenAmountOutputScreen(
        const token_group_t* tokenGroup,
        const uint8_t* assetNameBytes, size_t assetNameSize,
        uint64_t tokenAmount,
        ui_callback_fn_t callback
)
{
	char tokenAmountStr[70] = {0};
	explicit_bzero(tokenAmountStr, SIZEOF(tokenAmountStr));
	str_formatTokenAmountOutput(
	        tokenGroup,
	        assetNameBytes, assetNameSize,
	        tokenAmount,
	        tokenAmountStr, SIZEOF(tokenAmountStr)
	);

	ui_displayPaginatedText(
	        "Token amount",
	        tokenAmountStr,
	        callback
	);
}

void ui_displayTokenAmountMintScreen(
        const token_group_t* tokenGroup,
        const uint8_t* assetNameBytes, size_t assetNameSize,
        int64_t tokenAmount,
        ui_callback_fn_t callback
)
{
	char tokenAmountStr[70] = {0};
	explicit_bzero(tokenAmountStr, SIZEOF(tokenAmountStr));
	str_formatTokenAmountMint(
	        tokenGroup,
	        assetNameBytes, assetNameSize,
	        tokenAmount,
	        tokenAmountStr, SIZEOF(tokenAmountStr)
	);

	ui_displayPaginatedText(
	        "Token amount",
	        tokenAmountStr,
	        callback
	);
}

void ui_displayUint64Screen(
        const char* firstLine,
        uint64_t value,
        ui_callback_fn_t callback
)
{
	char valueStr[30] = {0};
	explicit_bzero(valueStr, SIZEOF(valueStr));
	str_formatUint64(value, valueStr, SIZEOF(valueStr));

	ui_displayPaginatedText(
	        firstLine,
	        valueStr,
	        callback
	);
}

void ui_displayInt64Screen(
        const char* screenHeader,
        int64_t value,
        ui_callback_fn_t callback
)
{
	char valueStr[30] = {0};
	explicit_bzero(valueStr, SIZEOF(valueStr));
	str_formatInt64(value, valueStr, SIZEOF(valueStr));

	ui_displayPaginatedText(
	        screenHeader,
	        valueStr,
	        callback
	);
}

void ui_displayValidityBoundaryScreen(
        const char* firstLine,
        uint64_t boundary,
        uint8_t networkId, uint32_t protocolMagic,
        ui_callback_fn_t callback
)
{
	char boundaryStr[30] = {0};
	explicit_bzero(boundaryStr, SIZEOF(boundaryStr));

	if ((networkId == MAINNET_NETWORK_ID) && (protocolMagic == MAINNET_PROTOCOL_MAGIC)) {
		// nicer formatting could only be used for mainnet
		// since it depends on network params that could differ for testnets
		str_formatValidityBoundary(boundary, boundaryStr, SIZEOF(boundaryStr));
		ui_displayPaginatedText(
		        firstLine,
		        boundaryStr,
		        callback
		);
	} else {
		ui_displayUint64Screen(
		        firstLine,
		        boundary,
		        callback
		);
	}
}

void ui_displayNetworkParamsScreen(
        const char* firstLine,
        uint8_t networkId,
        uint32_t protocolMagic,
        ui_callback_fn_t callback
)
{
	ASSERT(strlen(firstLine) > 0);
	ASSERT(strlen(firstLine) < BUFFER_SIZE_PARANOIA);
	ASSERT(isValidNetworkId(networkId));

	char networkParams[100] = {0};
	explicit_bzero(networkParams, SIZEOF(networkParams));

	STATIC_ASSERT(sizeof(networkId) <= sizeof(unsigned), "oversized type for %u");
	STATIC_ASSERT(!IS_SIGNED(networkId), "signed type for %u");
	STATIC_ASSERT(sizeof(protocolMagic) <= sizeof(unsigned), "oversized type for %u");
	STATIC_ASSERT(!IS_SIGNED(protocolMagic), "signed type for %u");
	snprintf(
	        networkParams, SIZEOF(networkParams),
	        "network id %u / protocol magic %u",
	        networkId, protocolMagic
	);
	ASSERT(strlen(networkParams) + 1 < SIZEOF(networkParams));

	ui_displayPaginatedText(
	        firstLine,
	        networkParams,
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

	char marginStr[20] = {0};
	explicit_bzero(marginStr, SIZEOF(marginStr));

	{
		// marginPercentage is a multiple of 1/100th of 1%, i.e. the fractional part of the percentage has two digits
		// adding marginDenominator / 2 to have a rounded result
		uint64_t marginPercentage = (10000 * marginNumerator + (marginDenominator / 2)) / marginDenominator;
		ASSERT(marginPercentage <= 10000);

		const unsigned int percentage = (unsigned int) marginPercentage;

		STATIC_ASSERT(sizeof(percentage) <= sizeof(unsigned), "oversized type for %u");
		STATIC_ASSERT(!IS_SIGNED(percentage), "signed type for %u");
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
		ASSERT(isValidNetworkId(networkId));
		ASSERT(ownerIndex < POOL_MAX_OWNERS);
	}
	{
		uint8_t rewardAddress[REWARD_ACCOUNT_SIZE] = {0};

		switch (owner->keyReferenceType) {
		case KEY_REFERENCE_PATH: {
			ASSERT(bip44_isOrdinaryStakingKeyPath(&owner->path));

			constructRewardAddressFromKeyPath(
			        &owner->path, networkId, rewardAddress, SIZEOF(rewardAddress)
			);
			break;
		}
		case KEY_REFERENCE_HASH: {
			STATIC_ASSERT(SIZEOF(owner->keyHash) == ADDRESS_KEY_HASH_LENGTH, "wrong owner.keyHash size");

			constructRewardAddressFromHash(
			        networkId, REWARD_HASH_SOURCE_KEY,
			        owner->keyHash, SIZEOF(owner->keyHash),
			        rewardAddress, SIZEOF(rewardAddress)
			);
			break;
		}
		default:
			ASSERT(false);
		}

		char firstLine[20] = {0};
		explicit_bzero(firstLine, SIZEOF(firstLine));
		STATIC_ASSERT(sizeof(ownerIndex + 1) <= sizeof(unsigned), "oversized type for %u");
		STATIC_ASSERT(!IS_SIGNED(ownerIndex + 1), "signed type for %u");
		// indexed from 0 as discuss with IOHK on Slack
		snprintf(firstLine, SIZEOF(firstLine), "Owner #%u", ownerIndex);
		// make sure all the information is displayed to the user
		ASSERT(strlen(firstLine) + 1 < SIZEOF(firstLine));

		_displayRewardAccountWithDescriptionScreen(
		        owner->keyReferenceType,
		        &owner->path,
		        rewardAddress,
		        firstLine,
		        callback
		);
	}
}

// displays pool relay index
void ui_displayPoolRelayScreen(
        const pool_relay_t* relay MARK_UNUSED,
        size_t relayIndex,
        ui_callback_fn_t callback
)
{
	char firstLine[20] = {0};
	explicit_bzero(firstLine, SIZEOF(firstLine));
	{
		STATIC_ASSERT(sizeof(relayIndex + 1) <= sizeof(unsigned), "oversized type for %u");
		STATIC_ASSERT(!IS_SIGNED(relayIndex + 1), "signed type for %u");
		// indexed from 0 as discussed with IOHK on Slack
		snprintf(firstLine, SIZEOF(firstLine), "Relay #%u", relayIndex);
		// make sure all the information is displayed to the user
		ASSERT(strlen(firstLine) + 1 < SIZEOF(firstLine));
	}

	ui_displayPaginatedText(
	        firstLine,
	        "",
	        callback
	);
}

void ui_displayIpv4Screen(
        const ipv4_t* ipv4,
        ui_callback_fn_t callback
)
{
	char ipStr[IPV4_STR_SIZE_MAX + 1] = {0};
	explicit_bzero(ipStr, SIZEOF(ipStr));

	if (ipv4->isNull) {
		snprintf(ipStr, SIZEOF(ipStr), "(none)");
	} else {
		inet_ntop4(ipv4->ip, ipStr, SIZEOF(ipStr));
	}

	// make sure all the information is displayed to the user
	ASSERT(strlen(ipStr) + 1 < SIZEOF(ipStr));

	ui_displayPaginatedText(
	        "IPv4 address",
	        ipStr,
	        callback
	);
}

void ui_displayIpv6Screen(
        const ipv6_t* ipv6,
        ui_callback_fn_t callback
)
{
	char ipStr[IPV6_STR_SIZE_MAX + 1] = {0};
	explicit_bzero(ipStr, SIZEOF(ipStr));

	if (ipv6->isNull) {
		snprintf(ipStr, SIZEOF(ipStr), "(none)");
	} else {
		inet_ntop6(ipv6->ip, ipStr, SIZEOF(ipStr));
	}

	// make sure all the information is displayed to the user
	ASSERT(strlen(ipStr) + 1 < SIZEOF(ipStr));

	ui_displayPaginatedText(
	        "IPv6 address",
	        ipStr,
	        callback
	);
}

void ui_displayIpPortScreen(
        const ipport_t* port,
        ui_callback_fn_t callback
)
{
	char portStr[1 + (sizeof "65536")] = {0};
	explicit_bzero(portStr, SIZEOF(portStr));

	if (port->isNull) {
		snprintf(portStr, SIZEOF(portStr), "(none)");
	} else {
		STATIC_ASSERT(sizeof(port->number) <= sizeof(unsigned), "oversized variable for %u");
		STATIC_ASSERT(!IS_SIGNED(port->number), "signed type for %u");
		snprintf(portStr, SIZEOF(portStr), "%u", port->number);
	}

	// make sure all the information is displayed to the user
	ASSERT(strlen(portStr) + 1 < SIZEOF(portStr));

	ui_displayPaginatedText(
	        "Port",
	        portStr,
	        callback
	);
}

void ui_displayInputScreen(
        const sign_tx_transaction_input_t* input,
        ui_callback_fn_t callback)
{
	const tx_input_t* inputData = &input->input_data;
	ASSERT(SIZEOF(inputData->txHashBuffer) == TX_HASH_LENGTH);
	char txHex[2 * TX_HASH_LENGTH + 1] = {0};
	explicit_bzero(txHex, SIZEOF(txHex));

	size_t length = encode_hex(
	                        inputData->txHashBuffer, TX_HASH_LENGTH,
	                        txHex, SIZEOF(txHex)
	                );
	ASSERT(length == strlen(txHex));
	ASSERT(length == 2 * TX_HASH_LENGTH);

	// index 32 bit (10) + separator (" / ") + utxo hash hex format + \0
	// + 1 byte to detect if everything has been written
	char inputStr[10 + 3 + TX_HASH_LENGTH * 2 + 1 + 1] = {0};
	explicit_bzero(inputStr, SIZEOF(inputStr));

	snprintf(inputStr, SIZEOF(inputStr), "%u / %s", inputData->index, txHex);
	// make sure all the information is displayed to the user
	ASSERT(strlen(inputStr) + 1 < SIZEOF(inputStr));

	ui_displayPaginatedText(
	        input->label,
	        inputStr,
	        callback
	);
}
