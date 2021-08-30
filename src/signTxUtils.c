#include "io.h"
#include "errors.h"
#include "uiHelpers.h"
#include "utils.h"
#include "signTxUtils.h"

void respondSuccessEmptyMsg()
{
	TRACE();
	io_send_buf(SUCCESS, NULL, 0);
	ui_displayBusy(); // needs to happen after I/O
}

void parsePathSpec(read_view_t* view, bip44_path_t* pathSpec)
{
	view_skipBytes(view, bip44_parseFromWire(pathSpec, VIEW_REMAINING_TO_TUPLE_BUF_SIZE(view)));
	TRACE();
	BIP44_PRINTF(pathSpec);
}

void parseStakeCredential(read_view_t* view, stake_credential_t* stakeCredential)
{
	stakeCredential->type = parse_u1be(view);
	switch (stakeCredential->type) {
	case STAKE_CREDENTIAL_KEY_PATH:
		parsePathSpec(view, &stakeCredential->keyPath);
		break;
	case STAKE_CREDENTIAL_SCRIPT_HASH: {
		STATIC_ASSERT(SIZEOF(stakeCredential->scriptHash) == SCRIPT_HASH_LENGTH, "bad script hash container size");
		view_copyWireToBuffer(stakeCredential->scriptHash, view, SIZEOF(stakeCredential->scriptHash));
		break;
	}

	default:
		ASSERT(false);
	}
}
