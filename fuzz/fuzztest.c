// cmake -Bbuild -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
// .\fuzzer.exe ../corpus/
// .\fuzzer_coverage.exe $(ls ../corpus/* | % {$_.FullName})
// llvm-profdata merge -sparse *.profraw -o default.profdata 
// llvm-cov report fuzzer_coverage.exe -instr-profile="default.profdata"
// llvm-cov show fuzzer_coverage.exe -instr-profile="default.profdata" --format=html > report.html

#include <stdint.h>
#include <string.h>
#include "lcx_hash.h"
#include "lcx_blake2.h"
#include "lcx_sha3.h"
#include "signTx.h"

io_seph_app_t G_io_app;
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
unsigned char G_io_apdu_buffer[260];

void os_longjmp(unsigned int exception) {
    longjmp(try_context_get()->jmp_buf, exception);
}
try_context_t *current_context = NULL;
try_context_t *try_context_get(void) {
    return current_context;
}
try_context_t *try_context_set(try_context_t *ctx) {
    try_context_t *previous_ctx = current_context;
    current_context = ctx;
    return previous_ctx;
}

bolos_task_status_t os_sched_last_status(unsigned int task_idx) {return 0;};
unsigned short io_exchange(unsigned char chan, unsigned short tx_len) {return 0;};
void * pic(void * linked_addr) {return linked_addr;}

void io_seproxyhal_display_default(const bagl_element_t * bagl) {
  char buf[256];
  sprintf(buf, "%s", bagl->text);
}

void ui_idle() {};
// void respondSuccessEmptyMsg() {};
// bool device_is_unlocked() { return true; };

unsigned int os_ux(bolos_ux_params_t * params) {return 0;};
void io_seproxyhal_init_ux(void) {};
void io_seproxyhal_init_button(void) {};
unsigned int io_seph_is_status_sent (void) {return 1;};
bolos_bool_t os_perso_isonboarded(void) {return 1;};
void io_seproxyhal_general_status(void) {};
void io_seph_send(const unsigned char * buffer, unsigned short length) {};
unsigned short io_seph_recv ( unsigned char * buffer, unsigned short maxlength, unsigned int flags ) {return 0;};
void halt() { for(;;); };
bolos_bool_t os_global_pin_is_validated(void) {return 1;};
cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode, const uint8_t *in, size_t len, uint8_t *out, size_t out_len) { return 0;};
size_t cx_hash_get_size(const cx_hash_t *ctx) { return 32;};
cx_err_t cx_blake2b_init_no_throw(cx_blake2b_t *hash, size_t size) {return 0;};
cx_err_t cx_sha3_init_no_throw(cx_sha3_t *hash, size_t size) {return 0;};

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  uint8_t * data_ptr = Data;
  size_t total_size = Size;

  uint8_t commands[11] = {0x01, 0x08, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0a, 0x0f};
  bool is_first = true;
  if (Size > 2) {
    BEGIN_TRY {
        TRY {
          for (size_t i = 0; i<sizeof(commands); i++) {
            size_t cur_size = MIN(256, total_size);
            signTx_handleAPDU(commands[i], data_ptr[0], (uint8_t *)&data_ptr[1], cur_size-1, is_first);
            is_first = false;
            total_size -= cur_size; 
            data_ptr += cur_size; 
          }
        }
        CATCH_ALL {
        } 
        FINALLY {
        }
    } END_TRY;
  }
  return 0;
}