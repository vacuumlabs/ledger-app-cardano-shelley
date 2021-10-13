#include "io.h"
#include "errors.h"
#include "uiHelpers.h"
#include "utils.h"
#include "signTxUtils.h"
#include "securityPolicy.h"
#include "state.h"

void respondSuccessEmptyMsg()
{
	TRACE();
	io_send_buf(SUCCESS, NULL, 0);
	ui_displayBusy(); // needs to happen after I/O
}

bool violatesSingleAccountOrStoreIt(const bip44_path_t* path)
{
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
		const bool combinationAllowed = (storedAccount == 0);
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
