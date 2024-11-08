#include "swap.h"
#include "txHashBuilder.h"
#include "handle_sign_transaction.h"
#include "hexUtils.h"

#ifdef HAVE_SWAP

typedef struct swap_validated_s {
    bool initialized;
    uint64_t amount;
    uint64_t fee;
    char destination[MAX_ADDRESS_SIZE];
} swap_validated_t;

static swap_validated_t G_swap_validated;

// Save the BSS address where we will write the return value when finished
static uint8_t* G_swap_sign_return_value_address;

// Save the data validated during the Exchange app flow
bool swap_copy_transaction_parameters(create_transaction_parameters_t* params) {
    PRINTF("Inside swap_copy_transaction_parameters\n");

    // Ensure no extraid
    if (params->destination_address_extra_id == NULL) {
        PRINTF("destination_address_extra_id expected\n");
        return false;
    }
    if (params->destination_address_extra_id[0] != '\0') {
        PRINTF("destination_address_extra_id expected empty, not '%s'\n",
               params->destination_address_extra_id);
        return false;
    }

    // first copy parameters to stack, and then to global data.
    // We need this "trick" as the input data position can overlap with app globals
    // and also because we want to memset the whole bss segment as it is not done
    // when an app is called as a lib.
    // This is necessary as many part of the code expect bss variables to
    // initialized at 0.
    swap_validated_t swap_validated;
    memset(&swap_validated, 0, sizeof(swap_validated));

    // Save destination
    ASSERT(strlen(params->destination_address) < sizeof(swap_validated.destination));
    strlcpy(swap_validated.destination,
            params->destination_address,
            sizeof(swap_validated.destination));
    if (swap_validated.destination[sizeof(swap_validated.destination) - 1] != '\0') {
        PRINTF("Address copy error\n");
        return false;
    }

    PRINTF("Destination received %s\n", params->destination_address);

    // Save amount and fees
    if (!swap_str_to_u64(params->amount, params->amount_length, &swap_validated.amount)) {
        PRINTF("Amount copy error\n");
        return false;
    }
    if (!swap_str_to_u64(params->fee_amount, params->fee_amount_length, &swap_validated.fee)) {
        PRINTF("Fee copy error\n");
        return false;
    }

    swap_validated.initialized = true;

    // Full reset the global variables
    os_explicit_zero_BSS_segment();

    // Keep the address at which we'll reply the signing status
    G_swap_sign_return_value_address = &params->result;

    // Commit from stack to global data, params becomes tainted but we won't access it anymore
    memcpy(&G_swap_validated, &swap_validated, sizeof(swap_validated));
    return true;
}

bool swap_check_destination_validity(tx_output_destination_t* destination) {
    char rawAddressHuman[MAX_HUMAN_ADDRESS_SIZE] = {0};
    // char rawAddressBuffer[MAX_ADDRESS_SIZE] = {0};
    // size_t nbBytes = 0;
    size_t addrLen = 0;

    PRINTF("Inside swap_check_destination_validity\n");
    if (!G_swap_validated.initialized) {
        PRINTF("Not initialized!\n");
        return false;
    }

    switch (destination->type) {
        case DESTINATION_THIRD_PARTY:
            addrLen = humanReadableAddress(destination->address.buffer,
                                           destination->address.size,
                                           rawAddressHuman,
                                           sizeof(rawAddressHuman));
            if (strlen(G_swap_validated.destination) != addrLen) {
                PRINTF("Invalid size. %d/%d\n", strlen(G_swap_validated.destination), addrLen);
                return false;
            }
            if (strncmp(G_swap_validated.destination, rawAddressHuman, addrLen) != 0) {
                PRINTF("Destination requested in this transaction = %s\n", rawAddressHuman);
                PRINTF("Destination validated in swap = %s\n", G_swap_validated.destination);
                return false;
            }
            break;
#if 0
// Case not used today, so currently removed
// If needed one day to support more address types, this code can be re-enabled
        case DESTINATION_DEVICE_OWNED:
            rawAddressBuffer[nbBytes++] =
                ((destination->params->type & 0x0F) << 4) | (destination->params->networkId & 0x0F);
            rawAddressBuffer[nbBytes++] = destination->params->paymentKeyPath.length;
            for (size_t i = 0; i < destination->params->paymentKeyPath.length; i++) {
                U4BE_ENCODE((uint8_t*) rawAddressBuffer,
                            nbBytes,
                            destination->params->paymentKeyPath.path[i]);
                nbBytes += 4;
            }
            rawAddressBuffer[nbBytes++] = destination->params->stakingDataSource;
            rawAddressBuffer[nbBytes++] = destination->params->stakingKeyPath.length;
            for (size_t i = 0; i < destination->params->stakingKeyPath.length; i++) {
                U4BE_ENCODE((uint8_t*) rawAddressBuffer,
                            nbBytes,
                            destination->params->stakingKeyPath.path[i]);
                nbBytes += 4;
            }
            addrLen = humanReadableAddress((const uint8_t*) rawAddressBuffer,
                                 nbBytes,
                                 rawAddressHuman,
                                 sizeof(rawAddressHuman));

            switch (destination->params->type) {
                case BASE_PAYMENT_KEY_STAKE_KEY:
                    if (strncmp(G_swap_validated.destination, rawAddressHuman, addrLen) != 0) {
                        PRINTF("Destination requested in this transaction = %s\n", rawAddressHuman);
                        PRINTF("Destination validated in swap = %s\n",
                               G_swap_validated.destination);
                        return false;
                    }
                    break;
                default:
                    PRINTF("Invalid destination type!\n");
                    return false;
            }
            break;
#endif
        default:
            PRINTF("Invalid destination type!\n");
            return false;
    }
    PRINTF("VALID!\n");
    return true;
}

bool swap_check_amount_validity(uint64_t amount) {
    PRINTF("Inside swap_check_amount_validity\n");
    if (!G_swap_validated.initialized) {
        PRINTF("Not initialized!\n");
        return false;
    }
    if (amount != G_swap_validated.amount) {
        PRINTF("Invalid swap amount!\n");
        return false;
    }
    PRINTF("VALID!\n");
    return true;
}

bool swap_check_fee_validity(uint64_t fee) {
    PRINTF("Inside swap_check_fee_validity\n");
    if (!G_swap_validated.initialized) {
        PRINTF("Not initialized!\n");
        return false;
    }
    if (fee != G_swap_validated.fee) {
        PRINTF("Invalid swap fee!\n");
        return false;
    }
    PRINTF("VALID!\n");
    return true;
}

void __attribute__((noreturn)) swap_finalize_exchange_sign_transaction(bool is_success) {
    PRINTF("is_success: %d\n", is_success);
    *G_swap_sign_return_value_address = is_success;
    os_lib_end();
}

#endif  // HAVE_SWAP
