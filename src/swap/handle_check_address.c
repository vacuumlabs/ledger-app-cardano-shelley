#include "swap.h"
#include "bip44.h"
#include "addressUtilsByron.h"
#include "handle_sign_transaction.h"
#include "cardano.h"
#include "hexUtils.h"

#ifdef HAVE_SWAP

/* Set params.result to 0 on error, 1 otherwise */
void swap_handle_check_address(check_address_parameters_t *params) {
    uint8_t rawAddressBuffer[MAX_ADDRESS_SIZE] = {0};
    char devAddressHuman[MAX_HUMAN_ADDRESS_SIZE] = {0};
    addressParams_t addressParams = {0};
    bip44_path_t pathSpec = {0};
    size_t nbBytes = 0;

    PRINTF("Inside handle_check_address\n");
    params->result = 0;

    if (params->address_parameters == NULL) {
        PRINTF("ERROR: derivation path expected\n");
        return;
    }

    if (params->address_to_check == NULL) {
        PRINTF("ERROR: Address to check expected\n");
        return;
    }

    bip44_parseFromWire(&pathSpec, params->address_parameters, params->address_parameters_length);
    switch (pathSpec.path[BIP44_I_PURPOSE] & (~HARDENED_BIP32)) {
        case PURPOSE_BYRON:
            // Compute default device address from received path
            nbBytes = deriveAddress_byron(&pathSpec,
                                          MAINNET_PROTOCOL_MAGIC,
                                          rawAddressBuffer,
                                          SIZEOF(rawAddressBuffer));
            humanReadableAddress(rawAddressBuffer,
                                 nbBytes,
                                 devAddressHuman,
                                 sizeof(devAddressHuman));
            if (strcmp(params->address_to_check, (const char *) devAddressHuman) != 0) {
                PRINTF("Address %s != %s\n", params->address_to_check, devAddressHuman);
                return;
            }
            break;
        case PURPOSE_SHELLEY:
            // Compute default device address from received path
            addressParams.type = BASE_PAYMENT_KEY_STAKE_KEY;
            addressParams.networkId = MAINNET_NETWORK_ID;
            addressParams.stakingDataSource = STAKING_KEY_PATH;
            memcpy(&addressParams.paymentKeyPath, &pathSpec, sizeof(bip44_path_t));
            memcpy(&addressParams.stakingKeyPath, &pathSpec, sizeof(bip44_path_t));
            // The default staking key path is the same as the payment key path, except for the
            // chain element
            addressParams.stakingKeyPath.path[BIP44_I_CHAIN] = 2;
            addressParams.stakingKeyPath.path[BIP44_I_ADDRESS] = 0;
            nbBytes = deriveAddress(&addressParams, rawAddressBuffer, SIZEOF(rawAddressBuffer));
            humanReadableAddress(rawAddressBuffer,
                                 nbBytes,
                                 devAddressHuman,
                                 sizeof(devAddressHuman));
            if (strcmp((const char *) params->address_to_check, (const char *) devAddressHuman) !=
                0) {
                PRINTF("Address %s != %s\n", params->address_to_check, devAddressHuman);
                return;
            }
            break;
        default:
            PRINTF("ERROR: not yet supported!\n");
            return;
    }

    PRINTF("Addresses match\n");
    params->result = 1;
    return;
}

#endif  // HAVE_SWAP
