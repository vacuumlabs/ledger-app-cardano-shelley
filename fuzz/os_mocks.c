#include "os.h"
#include "cx.h"
#include "ux.h"

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

bolos_task_status_t os_sched_last_status(unsigned int task_idx) {return 1;};
unsigned short io_exchange(unsigned char chan, unsigned short tx_len) {return 0;};
void * pic(void * linked_addr) {return linked_addr;}

void io_seproxyhal_display_default(const bagl_element_t * bagl) {
  if (bagl->text) {
        printf("[-] %s\n", bagl->text);
  }
}

void ui_idle() {};

unsigned int os_ux(bolos_ux_params_t * params) {return 0;};
void io_seproxyhal_init_ux(void) {};
unsigned int io_seph_is_status_sent (void) {return 0;};
bolos_bool_t os_perso_isonboarded(void) {return (bolos_bool_t)BOLOS_UX_OK;};
void io_seproxyhal_general_status(void) {};
void io_seph_send(const unsigned char * buffer, unsigned short length) {};
unsigned short io_seph_recv ( unsigned char * buffer, unsigned short maxlength, unsigned int flags ) {return 0;};
void halt() { for(;;); };
bolos_bool_t os_global_pin_is_validated(void) {return (bolos_bool_t)BOLOS_UX_OK;};
cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode, const uint8_t *in, size_t len, uint8_t *out, size_t out_len) { return 0;};
size_t cx_hash_get_size(const cx_hash_t *ctx) { return 32;};
cx_err_t cx_blake2b_init_no_throw(cx_blake2b_t *hash, size_t size) {return 0;};
cx_err_t cx_sha3_init_no_throw(cx_sha3_t *hash, size_t size) {return 0;};
