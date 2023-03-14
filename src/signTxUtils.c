#include "io.h"
#include "errors.h"
#include "uiHelpers.h"
#include "utils.h"
#include "signTxUtils.h"
#include "securityPolicy.h"
#include "state.h"

#ifdef HAVE_BAGL
#include "uiScreens_bagl.h"
#elif defined(HAVE_NBGL)
#include "nbgl_use_case.h"
#include "uiScreens_nbgl.h"
#endif

void respondSuccessEmptyMsg()
{
	TRACE();
	io_send_buf(SUCCESS, NULL, 0);
#ifdef HAVE_BAGL
	ui_displayBusy(); // displays dots, called only after I/O to avoid freezing
#endif
}

bool violatesSingleAccountOrStoreIt(const bip44_path_t* path)
{
	PRINTF("Considering path ");
	BIP44_PRINTF(path);
	PRINTF(" for single account security model\n");

	single_account_data_t* singleAccountData = &(instructionState.signTxContext.commonTxData.singleAccountData);

	if (!bip44_hasOrdinaryWalletKeyPrefix(path) || !bip44_containsAccount(path)) {
		TRACE("Invalid path in single account check");
		ASSERT(false);
	}

	const bool isByron = bip44_hasByronPrefix(path);
	const uint32_t account = bip44_getAccount(path);
	if (singleAccountData->isStored) {
		const uint32_t storedAccount = singleAccountData->accountNumber;
		if (account != storedAccount) {
			return true;
		}
		const bool combinesByronAndShelley = singleAccountData->isByron != isByron;
		const bool combinationAllowed = (storedAccount == harden(0));
		if (combinesByronAndShelley && !combinationAllowed) {
			return true;
		}
	} else {
		singleAccountData->isStored = true;
		singleAccountData->isByron = isByron;
		singleAccountData->accountNumber = account;
	}
	return false;
}

void view_parseDestination(read_view_t* view, tx_output_destination_storage_t* destination)
{
	destination->type = parse_u1be(view);
	TRACE("Destination type %d", (int) destination->type);

	switch (destination->type) { // serves as validation of the type too

	case DESTINATION_THIRD_PARTY: {
		STATIC_ASSERT(sizeof(destination->address.size) >= 4, "wrong address size type");
		destination->address.size = parse_u4be(view);
		TRACE("Address length %u", destination->address.size);
		VALIDATE(destination->address.size <= MAX_ADDRESS_SIZE, ERR_INVALID_DATA);

		STATIC_ASSERT(SIZEOF(destination->address.buffer) >= MAX_ADDRESS_SIZE, "wrong address buffer size");
		view_parseBuffer(destination->address.buffer, view, destination->address.size);
		TRACE_BUFFER(destination->address.buffer, destination->address.size);
		break;
	}

	case DESTINATION_DEVICE_OWNED: {
		view_parseAddressParams(view, &destination->params);
		break;
	}

	default:
		THROW(ERR_INVALID_DATA);
	};
}
