#pragma once
// General libraries
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef FUZZING
#define explicit_bzero(addr, size) memset((addr), 0, (size))
#endif

// ours
#include "assert.h"
#include "errors.h"
#include "io.h"
#include "utils.h"
