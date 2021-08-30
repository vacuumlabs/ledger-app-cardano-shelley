#ifndef H_CARDANO_APP_SIGN_TX_UTILS
#define H_CARDANO_APP_SIGN_TX_UTILS

#include "cardano.h"
#include "bufView.h"

void respondSuccessEmptyMsg();

void parsePathSpec(read_view_t* view, bip44_path_t* pathSpec);
void parseStakeCredential(read_view_t* view, stake_credential_t* stakeCredential);

#endif  // H_CARDANO_APP_SIGN_TX_UTILS
