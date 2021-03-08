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
		STATIC_ASSERT(SIZEOF(rewardAccount->buffer) == REWARD_ACCOUNT_SIZE, "wrong reward account size");
		os_memmove(rewardAccountBuffer, rewardAccount->buffer, REWARD_ACCOUNT_SIZE);
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
