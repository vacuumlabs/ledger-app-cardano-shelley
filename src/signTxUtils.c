#include "io.h"
#include "errors.h"
#include "uiHelpers.h"
#include "signTxUtils.h"

void respondSuccessEmptyMsg()
{
	TRACE();
	io_send_buf(SUCCESS, NULL, 0);
	ui_displayBusy(); // needs to happen after I/O
}
