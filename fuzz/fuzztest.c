#include <stdint.h>
#include <string.h>
#include "cx.h"

#include "signTx.h"
#include "getPublicKeys.h"

ux_state_t G_ux;
uint8_t G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#ifdef DEVEL
#include "utils.h"
unsigned int app_stack_canary = APP_STACK_CANARY_MAGIC;
#endif

void signTx_handleAPDU_no_throw(uint8_t p1, uint8_t p2, const uint8_t *wireBuffer, size_t wireSize, bool isNewCall) {
      BEGIN_TRY {
        TRY {
            signTx_handleAPDU(p1, p2, wireBuffer, wireSize, isNewCall);
            }
        CATCH_ALL {
        } 
        FINALLY {
        }
    } END_TRY;
}

void signOpCert_handleAPDU_no_throw(uint8_t p1, uint8_t p2, const uint8_t *wireBuffer, size_t wireSize, bool isNewCall) {
      BEGIN_TRY {
        TRY {
            signOpCert_handleAPDU(p1, p2, wireBuffer, wireSize, isNewCall);
            }
        CATCH_ALL {
        } 
        FINALLY {
        }
    } END_TRY;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  UX_INIT();

  bool is_first = true;
  uint8_t * input = Data;
  size_t size = Size;
  while ((size > 5) && (input[3] < size-4)) {
    io_state = IO_EXPECT_NONE;
    uint8_t ins = input[0];
    uint8_t p1 = input[1];
    uint8_t p2 = input[2];
    uint8_t lc = input[3];

    switch (ins) {
      case 0x22:
          signOpCert_handleAPDU_no_throw(p1, p2, &input[4], lc, is_first);
          break;
      case 0x21:
          signTx_handleAPDU_no_throw(p1, p2, &input[4], lc, is_first);
          break;
      default:
        return 0;
    }
    is_first = false;
    size -= lc + 4;
    input += lc + 4;
  }
  return 0;
}