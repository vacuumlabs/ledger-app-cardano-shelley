#ifndef H_CARDANO_APP_UTILS
#define H_CARDANO_APP_UTILS

#include "assert.h"


// Does not compile if x is pointer of some kind
// See http://zubplot.blogspot.com/2015/01/gcc-is-wonderful-better-arraysize-macro.html
#define ARRAY_NOT_A_PTR(x) \
	(sizeof(__typeof__(int[1 - 2 * \
	                         !!__builtin_types_compatible_p(__typeof__(x), \
	                               __typeof__(&x[0]))])) * 0)


// Safe array length, does not compile if you accidentally supply a pointer
#define ARRAY_LEN(arr) \
	(sizeof(arr) / sizeof((arr)[0]) + ARRAY_NOT_A_PTR(arr))

// Does not compile if x *might* be a pointer of some kind
// Might produce false positives on small structs...
// Note: ARRAY_NOT_A_PTR does not compile if arg is a struct so this is a workaround
#define SIZEOF_NOT_A_PTR(var) \
	(sizeof(__typeof(int[0 - (sizeof(var) == sizeof((void *)0))])) * 0)

// Safe version of SIZEOF, does not compile if you accidentally supply a pointer
#define SIZEOF(var) \
	(sizeof(var) + SIZEOF_NOT_A_PTR(var))


#define ASSERT_TYPE(expr, expected_type) \
	STATIC_ASSERT( \
	               __builtin_types_compatible_p(__typeof__((expr)), expected_type), \
	               "Wrong type" \
	             )

// Helper function to check APDU request parameters
#define VALIDATE(cond, error) \
	do {\
		if (!(cond)) { \
			PRINTF("Validation Error in %s: %d\n", __FILE__, __LINE__); \
			THROW(error); \
		} \
	} while(0)

// Helper functions for ranges
// TODO(ppershing): make more type safe?
#define BEGIN(buf) buf
// Note: SIZEOF would not work if buf is not uin8_t*
#define END(buf) (buf + ARRAY_LEN(buf))

// Any buffer claiming to be longer than this is a bug
// (we anyway have only 4KB of memory)
#define BUFFER_SIZE_PARANOIA 1024

#define PTR_PIC(ptr) ((__typeof__(ptr)) PIC(ptr))

#define ITERATE(it, arr) for (__typeof__(&(arr[0])) it = BEGIN(arr); it < END(arr); it++)


// *INDENT-OFF*

// Warning: Following macros are *NOT* brace-balanced by design!
// The macros simplify writing resumable logic that needs to happen over
// multiple calls.

// Example usage:
// UI_STEP_BEGIN(ctx->ui_step);
// UI_STEP(1) {do something & setup callback}
// UI_STEP(2) {do something & setup callback}
// UI_STEP_END(-1); // invalid state

#define UI_STEP_BEGIN(VAR) \
	{ \
		int* __ui_step_ptr = &(VAR); \
		switch(*__ui_step_ptr) { \
			default: { \
				ASSERT(false);

#define UI_STEP(NEXT_STEP) \
				*__ui_step_ptr = NEXT_STEP; \
				break; \
			} \
			case NEXT_STEP: {

#define UI_STEP_END(INVALID_STEP) \
				*__ui_step_ptr = INVALID_STEP; \
				break; \
			} \
		} \
	}

// Early exit to another state, unused for now
// #define UI_STEP_JUMP(NEXT_STEP) \
// 				*__ui_step_ptr = NEXT_STEP; \
// 				break;

// *INDENT-ON*


// Note: unused removes unused warning but does not warn if you suddenly
// start using such variable. deprecated deals with that.
#define MARK_UNUSED __attribute__ ((unused, deprecated))

// Note: inlining can increase stack memory usage
// where we really do not want it
#define __noinline_due_to_stack__ __attribute__((noinline))

#ifdef DEVEL
#define TRACE(...) \
	do { \
		PRINTF("[%s:%d] ", __func__, __LINE__); \
		PRINTF("" __VA_ARGS__); \
		PRINTF("\n"); \
	} while(0)
#else
#define TRACE(...)
#endif // DEVEL


#ifdef DEVEL
#define TRACE_BUFFER(BUF, SIZE) \
	TRACE("%.*h", SIZE, BUF);
#else
#define TRACE_BUFFER(BUF, SIZE)
#endif // DEVEL


#ifdef DEVEL
// Note: this is an unreliable (potentially very misleading) way of checking
// stack memory consumption because the compiler might allocate the space
// for all the local variables at the beginning of a function call.
// but even then it can give you at least a rough idea.
// The output of 'arm-none-eabi-objdump -d -S bin/app.elf'
// gives more accurate info on the stack frames of individual function calls.

// The variable app_stack_canary is provided in the linker script 'script.ld'
// in nanos-secure-sdk.
// There is also the flag HAVE_BOLOS_APP_STACK_CANARY in our Makefile
// which turns on automatic checking of the stack canary in io_exchange()
// (see os_io_seproxyhal.c in nanos-secure-sdk).
#define TRACE_STACK_USAGE() \
	do { \
		volatile uint32_t x = 0; \
		TRACE("stack position = %d", (int)((void*)&x - (void*)&app_stack_canary)); \
		if (app_stack_canary != APP_STACK_CANARY_MAGIC) { \
			TRACE("===================== stack overflow ====================="); \
		} \
		\
	} while(0)
#define APP_STACK_CANARY_MAGIC 0xDEAD0031
extern unsigned int app_stack_canary;
#else
#define TRACE_STACK_USAGE()
#endif // DEVEL

#endif // H_CARDANO_APP_UTILS
