#include <cx.h>
#include <os.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ux.h>

bool G_called_from_swap;
bool G_swap_response_ready;
bool G_swap_signing_return_value_address;

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    memcpy(dst_adr, src_adr, src_len);
}

typedef char tx_output_destination_t;

bool swap_check_validity(uint64_t amount, tx_output_destination_t *destination) {
    return true;
}

bool swap_check_fee_validity(uint64_t fee) {
    return true;
}

unsigned int os_serial(unsigned char *serial, unsigned int maxlength) {
    memset(serial, 'A', maxlength);
    return maxlength;
}

void __attribute__((noreturn)) os_sched_exit(bolos_task_status_t exit_code) {
    exit(exit_code);
}

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

void *pic(void *linked_addr) {
    return linked_addr;
}
// void ui_idle(){};
void halt() {
    for (;;)
        ;
};

void io_send_buf(unsigned short code, unsigned char *buffer, size_t tx){};
unsigned short io_exchange(unsigned char chan, unsigned short tx_len) {
    return 0;
};
unsigned short io_seph_recv(unsigned char *buffer, unsigned short maxlength, unsigned int flags) {
    return 0;
};
cx_err_t cx_blake2b_init_no_throw(cx_blake2b_t *hash, size_t size) {
    return CX_OK;
};
cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t len,
                          uint8_t *out,
                          size_t out_len) {
    return CX_OK;
};
size_t cx_hash_get_size(const cx_hash_t *ctx) {
    return 32;
};
void io_seph_send(const unsigned char *buffer, unsigned short length){};
cx_err_t cx_sha3_init_no_throw(cx_sha3_t *hash, size_t size) {
    return CX_OK;
};
unsigned int io_seph_is_status_sent(void) {
    return 0;
};
bolos_bool_t os_perso_isonboarded(void) {
    return (bolos_bool_t) BOLOS_UX_OK;
};

void io_seproxyhal_init_ux(void){};
bolos_task_status_t os_sched_last_status(unsigned int task_idx) {
    return 1;
};
bolos_bool_t os_global_pin_is_validated(void) {
    return (bolos_bool_t) BOLOS_UX_OK;
}

cx_err_t cx_eddsa_get_public_key_no_throw(const cx_ecfp_private_key_t *pv_key,
                                          cx_md_t hashID,
                                          cx_ecfp_public_key_t *pu_key,
                                          uint8_t *a,
                                          size_t a_len,
                                          uint8_t *h,
                                          size_t h_len) {
    pu_key->W_len = 65;
    memset(pu_key, 'A', pu_key->W_len);
    return CX_OK;
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t sig_len) {
    return CX_OK;
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length) {
    // cardano uses CX_CURVE_Ed25519
    if (cv == CX_CURVE_Ed25519) {
        *length = 32;
        return CX_OK;
    }

    exit(1);
    return CX_INVALID_PARAMETER;
}

void os_perso_derive_node_with_seed_key(unsigned int mode,
                                        cx_curve_t curve,
                                        const unsigned int *path,
                                        unsigned int pathLength,
                                        unsigned char *privateKey,
                                        unsigned char *chain,
                                        unsigned char *seed_key,
                                        unsigned int seed_key_length) {
}
