#ifndef H_CARDANO_APP_HANDLERS
#define H_CARDANO_APP_HANDLERS

#include "common.h"
#include "parser.h"

uint16_t handleApdu(command_t *cmd, bool isNewCall);

#endif  // H_CARDANO_APP_HANDLERS
