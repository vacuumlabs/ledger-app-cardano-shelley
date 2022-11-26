#ifndef H_CARDANO_APP_UTILS
#define H_CARDANO_APP_UTILS

#include <os.h>

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
// (Watch for lines like 'sub sp, #508' close to function headers.)

// Another thing to check is the output of 'objdump -x app.elf'.
// There are two important lines, looking like
// 2 .bss          000009f8  20001800  20001800  00001800  2**3
// 20002800 g       .text  00000000 END_STACK
// In this particular example, stack starts at 0x2800,
// data start at 0x1800 and have size 0x9f8.
// Thus the space available for data + stack is 0x1000 (4096 B),
// and data (.bss) take 0x9f8 (2552 B). This includes some Ledger
// internal stuff for handling APDUs etc.
// Unless some changes have been made, our global data usage is mostly
// determined by sizeof(instructionState_t), see state.h.

// The variable app_stack_canary is provided in the linker script 'script.ld'
// in nanos-secure-sdk.
// There is also the flag HAVE_BOLOS_APP_STACK_CANARY in our Makefile
// which turns on automatic checking of the stack canary in io_exchange()
// (see os_io_seproxyhal.c in nanos-secure-sdk).
#define APP_STACK_CANARY_MAGIC 0xDEAD0031
extern unsigned int app_stack_canary;

#define TRACE_STACK_USAGE() \
	do { \
		volatile uint32_t x = 0; \
		TRACE("stack position = %d", (int)((void*)&x - (void*)&app_stack_canary)); \
		if (app_stack_canary != APP_STACK_CANARY_MAGIC) { \
			TRACE("===================== stack overflow ====================="); \
		} \
		\
	} while(0)
#else
#define TRACE_STACK_USAGE()
#endif // DEVEL

#define IS_SIGNED_TYPE(type) (((type)(-1)) < 0)
#define IS_SIGNED(var) (((typeof(var))(-1)) < 0)


#endif // H_CARDANO_APP_UTILS
