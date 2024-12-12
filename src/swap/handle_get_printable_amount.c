#include "swap.h"
#include "textUtils.h"

#ifdef HAVE_SWAP

#define MAX_TICKER_LEN   10
#define DEFAULT_DECIMALS 6

/* Set empty printable_amount on error, printable amount otherwise */
void swap_handle_get_printable_amount(get_printable_amount_parameters_t* params) {
    uint8_t decimals = 0;
    char ticker[MAX_TICKER_LEN];
    uint64_t amount;

    PRINTF("Inside swap_handle_get_printable_amount\n");
    explicit_bzero(params->printable_amount, sizeof(params->printable_amount));

    // If the amount is a fee, its value is nominated in ADA
    // If there is no coin_configuration, consider that we are doing a ADA swap
    if (params->is_fee || params->coin_configuration == NULL) {
        if (params->is_fee) {
            PRINTF("Amount is a fee\n");
        }
        memcpy(ticker, "ADA", sizeof("ADA"));
        decimals = DEFAULT_DECIMALS;
    } else {
        if (!swap_parse_config(params->coin_configuration,
                               params->coin_configuration_length,
                               ticker,
                               sizeof(ticker),
                               &decimals)) {
            PRINTF("Error while parsing config\n");
            return;
        }
        PRINTF("Found ticker: %s, and decimals %d\n", ticker, decimals);
    }

    if (!swap_str_to_u64(params->amount, params->amount_length, &amount)) {
        PRINTF("Amount copy error\n");
        return;
    }
    str_formatAdaAmount(amount, params->printable_amount, sizeof(params->printable_amount));
    PRINTF("Amount=%s\n", params->printable_amount);
}

#endif  // HAVE_SWAP
