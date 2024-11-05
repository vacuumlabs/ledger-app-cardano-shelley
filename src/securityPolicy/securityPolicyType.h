#ifndef H_CARDANO_APP_SECURITY_POLICY_TYPE
#define H_CARDANO_APP_SECURITY_POLICY_TYPE

#include "os.h"

#include "errors.h"

typedef enum {
    POLICY_DENY = 1,
    POLICY_ALLOW_WITHOUT_PROMPT = 2,
    POLICY_PROMPT_BEFORE_RESPONSE = 3,
    POLICY_PROMPT_WARN_UNUSUAL = 4,
    POLICY_SHOW_BEFORE_RESPONSE = 5,  // Show on display but do not ask for explicit confirmation
} security_policy_t;

static inline void ENSURE_NOT_DENIED(security_policy_t policy) {
    if (policy == POLICY_DENY) {
        THROW(ERR_REJECTED_BY_POLICY);
    }
}

#endif  // H_CARDANO_APP_SECURITY_POLICY_TYPE
