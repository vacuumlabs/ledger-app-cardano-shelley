#include "cardano.h"
#include "addressUtilsShelley.h"


void rewardAccountToBuffer(
        const reward_account_t* rewardAccount,
        uint8_t networkId,
        uint8_t* rewardAccountBuffer
)
{
	switch (rewardAccount->keyReferenceType) {

	case KEY_REFERENCE_HASH: {
		ASSERT(SIZEOF(rewardAccount->hashBuffer) == REWARD_ACCOUNT_SIZE);
		memmove(rewardAccountBuffer, rewardAccount->hashBuffer, REWARD_ACCOUNT_SIZE);
		break;
	}
	case KEY_REFERENCE_PATH: {
		constructRewardAddressFromKeyPath(
		        &rewardAccount->path, networkId,
		        rewardAccountBuffer, REWARD_ACCOUNT_SIZE
		);
		break;
	}
	default:
		ASSERT(false);
	}
}
