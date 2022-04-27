#ifndef H_CARDANO_APP_SIGN_TX_UTILS
#define H_CARDANO_APP_SIGN_TX_UTILS

#include "bip44.h"

void respondSuccessEmptyMsg();

/**
 * Checks if the path has the same account as the already stored one
 * with regard to Byron and Shelley equivalency at account number 0
 *
 * If it is the first path and it fits the criteria, it stores it instead
 *
 * Criteria: path has an ordinary Shelley or Byron prefix and has at least account
 */
bool violatesSingleAccountOrStoreIt(const bip44_path_t* path);

#endif  // H_CARDANO_APP_SIGN_TX_UTILS
