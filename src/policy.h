#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>

typedef struct {
    uint32_t badge_id;
    uint32_t employee_id;
    uint32_t department_id;
} PolicyContext;

typedef struct {
    uint8_t resolved;
    uint8_t match_count;
    uint16_t mask;
    uint32_t value;
} PolicyResult;

_Static_assert(sizeof(PolicyResult) == 8, "PolicyResult doit rester compacte");

PolicyResult resolve_policy(int category, const PolicyContext *context);

#endif
