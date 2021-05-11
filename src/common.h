#pragma once
// General libraries
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

// BOLOS
#include <os.h>
#include <os_io_seproxyhal.h>
#include <cx.h>

#ifdef FUZZING
#define os_memcpy memcpy
#define os_memmove memmove
#define os_memcmp memcmp
#define os_memset memset 
#define explicit_bzero(addr, size) memset((addr), 0, (size))
#endif

// ours
#include "utils.h"
#include "assert.h"
#include "io.h"
#include "errors.h"
