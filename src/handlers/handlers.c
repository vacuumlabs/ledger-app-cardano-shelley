#ifndef H_HANDLERS

#include <stdlib.h>
#include "os_io_seproxyhal.h"
#include "handlers.h"
#include "getVersion.h"
#include "getSerial.h"
#include "getPublicKeys.h"
#include "runTests.h"
#include "common.h"
#include "deriveAddress.h"
#include "deriveNativeScriptHash.h"
#include "signTx.h"
#include "signMsg.h"
#include "signOpCert.h"
#include "signCVote.h"
#include "parser.h"
#include "swap.h"

uint16_t handleApdu(command_t *cmd, bool isNewCall) {
    uint16_t sw = ERR_NOT_IMPLEMENTED;

    if (cmd->cla != CLA) {
        return ERR_BAD_CLA;
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if ((cmd->ins != INS_GET_PUBLIC_KEY) && (cmd->ins != INS_DERIVE_ADDRESS) &&
            (cmd->ins != INS_GET_VERSION) && (cmd->ins != INS_SIGN_TX)) {
            PRINTF("Refused INS when in SWAP mode\n");
            return ERR_UNKNOWN_INS;
        }
        if ((cmd->ins == INS_DERIVE_ADDRESS) && (cmd->p1 != 0x01)) {
            PRINTF("Refused 'derive_address' with other than 'return' when in SWAP mode\n");
            return ERR_UNKNOWN_INS;
        }
    }
#endif  // HAVE_SWAP

    switch (cmd->ins) {
        case INS_GET_VERSION:
            sw = getVersion_handleAPDU(cmd->p1, cmd->p2, cmd->lc);
            break;
        case INS_GET_SERIAL:
            sw = getSerial_handleAPDU(cmd->p1, cmd->p2, cmd->lc);
            break;
        case INS_GET_PUBLIC_KEY:
            sw = getPublicKeys_handleAPDU(cmd->p1, cmd->p2, cmd->data, cmd->lc, isNewCall);
            break;
        case INS_DERIVE_ADDRESS:
            sw = deriveAddress_handleAPDU(cmd->p1, cmd->p2, cmd->data, cmd->lc, isNewCall);
            break;
#ifdef APP_FEATURE_NATIVE_SCRIPT_HASH
        case INS_DERIVE_NATIVE_SCRIPT_HASH:
            sw = deriveNativeScriptHash_handleAPDU(cmd->p1, cmd->p2, cmd->data, cmd->lc, isNewCall);
            break;
#endif  // APP_FEATURE_NATIVE_SCRIPT_HASH
        case INS_SIGN_TX:
            sw = signTx_handleAPDU(cmd->p1, cmd->p2, cmd->data, cmd->lc, isNewCall);
            break;
#ifdef APP_FEATURE_OPCERT
        case INS_SIGN_OP_CERT:
            sw = signOpCert_handleAPDU(cmd->p1, cmd->p2, cmd->data, cmd->lc, isNewCall);
            break;
#endif  // APP_FEATURE_OPCERT
        case INS_SIGN_CVOTE:
            sw = signCVote_handleAPDU(cmd->p1, cmd->p2, cmd->data, cmd->lc, isNewCall);
            break;
        case INS_SIGN_MSG:
            sw = signMsg_handleAPDU(cmd->p1, cmd->p2, cmd->data, cmd->lc, isNewCall);
            break;
#ifdef DEVEL
        case INS_RUN_TESTS:
            sw = handleRunTests();
            break;
#endif  // DEVEL
        default:
            sw = ERR_UNKNOWN_INS;
            break;
    }
    return sw;
}

#endif
