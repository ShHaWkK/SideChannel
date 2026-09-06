#ifndef ENROLLMENT_H
#define ENROLLMENT_H

#include <stdint.h>
#include "badge.h"
#include "policy.h"

typedef struct {
    badge_id_t badge_id;
    uint8_t authorized;
    PolicyResult policies[NB_CATEGORIES];
} InternalResult;

InternalResult process_enrollment(badge_id_t badge_id, const uint8_t *candidate_vector);
InternalResult process_enrollment_hardened(badge_id_t badge_id, const uint8_t *candidate_vector);

#endif
