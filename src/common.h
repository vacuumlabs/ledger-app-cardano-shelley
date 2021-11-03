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
#define explicit_bzero(addr, size) memset((addr), 0, (size))
#endif

// ours
#include "utils.h"
#include "assert.h"
#include "io.h"
#include "errors.h"
