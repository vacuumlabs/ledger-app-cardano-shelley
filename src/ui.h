#ifndef H_CARDANO_APP_UI_H
#define H_CARDANO_APP_UI_H

#include "io.h"
#include "uiHelpers.h"

#ifdef HAVE_NBGL
typedef void (*callback_t)(void);

void set_light_confirmation(bool needed);
void display_address(callback_t user_accept_cb, callback_t user_reject_cb);
void fill_address_data(char* text, char* content, callback_t callback);
void fill_and_display_if_required(const char* line1, const char* line2, callback_t user_accept_cb, callback_t user_reject_cb);
void fill_and_display_new_page(const char* line1, const char* line2, callback_t user_accept_cb, callback_t user_reject_cb);
void force_display(callback_t user_accept_cb, callback_t user_reject_cb);
void display_confirmation(const char* text1, const char* text2, const char* confirmText, const char* rejectText, callback_t user_accept_cb, callback_t user_reject_cb);
void display_page(callback_t user_accept_cb, callback_t user_reject_cb);
void display_prompt(const char* text1, const char* text2, callback_t user_accept_cb, callback_t user_reject_cb);
void display_warning(const char* text, callback_t user_accept_cb, callback_t user_reject_cb);
void ui_idle(void);
void ui_idle_flow(void);
void display_cancel_message(void);
void display_error(void);
void nbgl_reset_transaction_full_context(void);
#endif

#ifdef HAVE_BAGL
void io_seproxyhal_display(const bagl_element_t* element);
#endif // HAVE_BAGL

#endif // H_CARDANO_APP_UI_H
