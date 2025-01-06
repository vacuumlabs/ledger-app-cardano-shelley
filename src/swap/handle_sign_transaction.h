#pragma once

#include "txHashBuilder.h"

bool swap_check_destination_validity(tx_output_destination_t* destination);
bool swap_check_amount_validity(uint64_t amount);
bool swap_check_fee_validity(uint64_t fee);
