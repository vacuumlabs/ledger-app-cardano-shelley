#ifndef H_CARDANO_APP_ASSERT
#define H_CARDANO_APP_ASSERT

#include "common.h"

// from https://stackoverflow.com/questions/19343205/c-concatenating-file-and-line-macros
#define _TO_STR1_(x) #x
#define _TO_STR2_(x) _TO_STR1_(x)

#define STATIC_ASSERT _Static_assert

extern void assert(int cond, const char* msgStr);

// Note(ppershing): I like macro-like uppercase version better
// because it captures reader's attention.
#define ASSERT_WITH_MSG(cond, msg) assert(cond, msg)

#define _FILE_LINE_ __FILE__ ":" _TO_STR2_(__LINE__)

#define ASSERT(cond)                           \
    do {                                       \
        if (!(cond)) {                         \
            PRINTF(                            \
                "ASSERT failed at "_FILE_LINE_ \
                "\n");                         \
        }                                      \
        assert((cond), NULL);                  \
    } while (0)

#endif  // H_CARDANO_APP_ASSERT
