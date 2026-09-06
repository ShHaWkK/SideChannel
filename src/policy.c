#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "badge.h"
#include "policy.h"

static uint32_t scope_applies(uint32_t scope, uint32_t department_id) {
    return scope == 0 || scope == department_id;
}

static uint32_t count_bits16(uint16_t v) {
    uint32_t count = 0;
    while (v) {
        count += v & 1;
        v >>= 1;
    }
    return count;
}

typedef struct {
    uint16_t bit_type;
    uint32_t department_scope;
} SiteConstraint;

static const int32_t site_timezone[] = { 60, 120 };

static const SiteConstraint site_constraints[] = {
    { 0x1, 0 },
    { 0x2, 0 },
    { 0x4, 1 },
    { 0x8, 2 },
};

static PolicyResult resolve_site(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(site_constraints) / sizeof(site_constraints[0]);
    for (size_t i = 0; i < n; i++) {
        if (scope_applies(site_constraints[i].department_scope, context->department_id)) {
            r.match_count++;
            r.mask |= site_constraints[i].bit_type;
        }
    }
    size_t timezone_count = sizeof(site_timezone) / sizeof(site_timezone[0]);
    r.value = (uint32_t)site_timezone[context->department_id % timezone_count];
    return r;
}

typedef struct {
    uint8_t escort_required;
    uint8_t emergency_capacity;
} EntryPoint;

static const EntryPoint zone_entry_points[][4] = {
    { { 0, 0 }, { 0, 1 }, { 1, 0 }, { 1, 1 } },
    { { 0, 1 }, { 1, 0 }, { 1, 1 }, { 0, 0 } },
};

static PolicyResult resolve_zone(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(zone_entry_points) / sizeof(zone_entry_points[0]);
    const EntryPoint *entries = zone_entry_points[context->department_id % n];
    for (int i = 0; i < 4; i++) {
        if (!entries[i].escort_required) {
            r.match_count++;
        }
        if (entries[i].emergency_capacity) {
            r.mask |= (uint16_t)(1u << i);
        }
    }
    return r;
}

typedef struct {
    uint16_t start_minute;
    uint16_t end_minute;
    uint8_t priority;
} ScheduleRule;

static const ScheduleRule schedule_rules[][3] = {
    { { 8 * 60, 18 * 60, 1 }, { 10 * 60, 14 * 60, 2 }, { 0, 24 * 60, 3 } },
    { { 6 * 60, 22 * 60, 1 }, { 9 * 60, 17 * 60, 2 }, { 0, 12 * 60, 3 } },
    { { 0, 24 * 60, 1 }, { 8 * 60, 20 * 60, 2 }, { 12 * 60, 18 * 60, 3 } },
};

static PolicyResult resolve_schedule(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(schedule_rules) / sizeof(schedule_rules[0]);
    const ScheduleRule *rules = schedule_rules[context->employee_id % n];

    int selected = 0;
    for (int i = 0; i < 3; i++) {
        r.match_count++;
        if (rules[i].priority > rules[selected].priority) {
            selected = i;
        }
    }
    r.mask = (uint16_t)(1u << selected);
    r.value = (uint32_t)(rules[selected].end_minute - rules[selected].start_minute);
    return r;
}

typedef struct {
    uint32_t department_scope;
    uint16_t door_class_bit;
} DoorRule;

static const DoorRule door_rules[] = {
    { 0, 0x01 },
    { 0, 0x02 },
    { 1, 0x04 },
    { 2, 0x08 },
    { 1, 0x10 },
};

static PolicyResult resolve_door_class(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(door_rules) / sizeof(door_rules[0]);
    for (size_t i = 0; i < n; i++) {
        if (scope_applies(door_rules[i].department_scope, context->department_id)) {
            r.match_count++;
            r.mask |= door_rules[i].door_class_bit;
        }
    }
    return r;
}

typedef struct {
    uint32_t department_scope;
    uint16_t grant_mask;
    uint16_t revoke_mask;
} PrivilegeRule;

static const PrivilegeRule privilege_rules[] = {
    { 0, 0x03, 0x00 },
    { 1, 0x04, 0x00 },
    { 2, 0x00, 0x01 },
};

static PolicyResult resolve_privilege(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(privilege_rules) / sizeof(privilege_rules[0]);
    for (size_t i = 0; i < n; i++) {
        if (scope_applies(privilege_rules[i].department_scope, context->department_id)) {
            r.match_count++;
            r.mask = (uint16_t)((r.mask | privilege_rules[i].grant_mask) & ~privilege_rules[i].revoke_mask);
        }
    }
    r.value = count_bits16(r.mask);
    return r;
}

typedef struct {
    uint32_t department_scope;
    uint8_t required;
} EscortRule;

static const EscortRule escort_rules[] = {
    { 0, 0 },
    { 1, 1 },
    { 2, 0 },
};

static PolicyResult resolve_escort(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(escort_rules) / sizeof(escort_rules[0]);
    uint32_t required = 0;
    for (size_t i = 0; i < n; i++) {
        if (scope_applies(escort_rules[i].department_scope, context->department_id)) {
            r.match_count++;
            r.mask |= (uint16_t)(1u << i);
            if (escort_rules[i].required) {
                required = 1;
            }
        }
    }
    r.value = required;
    return r;
}

typedef struct {
    uint32_t department_scope;
    uint16_t capacity_bit;
} EmergencyRule;

static const EmergencyRule emergency_rules[] = {
    { 0, 0x01 },
    { 0, 0x02 },
    { 1, 0x04 },
    { 1, 0x08 },
};

static PolicyResult resolve_emergency(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(emergency_rules) / sizeof(emergency_rules[0]);
    for (size_t i = 0; i < n; i++) {
        if (scope_applies(emergency_rules[i].department_scope, context->department_id)) {
            r.match_count++;
            r.mask |= emergency_rules[i].capacity_bit;
        }
    }
    r.value = count_bits16(r.mask);
    return r;
}

typedef struct {
    uint32_t department_scope;
    uint16_t terminal_class_bit;
} TerminalRule;

static const TerminalRule terminal_rules[] = {
    { 0, 0x01 },
    { 1, 0x02 },
    { 2, 0x04 },
};

static PolicyResult resolve_terminal(const PolicyContext *context) {
    PolicyResult r = { .resolved = 1, .match_count = 0, .mask = 0, .value = 0 };
    size_t n = sizeof(terminal_rules) / sizeof(terminal_rules[0]);
    for (size_t i = 0; i < n; i++) {
        if (scope_applies(terminal_rules[i].department_scope, context->department_id)) {
            r.match_count++;
            r.mask |= terminal_rules[i].terminal_class_bit;
        }
    }
    return r;
}

PolicyResult resolve_policy(int category, const PolicyContext *context) {
    switch (category) {
        case CAT_SITE: return resolve_site(context);
        case CAT_ZONE: return resolve_zone(context);
        case CAT_SCHEDULE: return resolve_schedule(context);
        case CAT_DOOR_CLASS: return resolve_door_class(context);
        case CAT_PRIVILEGE: return resolve_privilege(context);
        case CAT_ESCORT: return resolve_escort(context);
        case CAT_EMERGENCY: return resolve_emergency(context);
        case CAT_TERMINAL: return resolve_terminal(context);
        default: {
            PolicyResult none_result = { .resolved = 0, .match_count = 0, .mask = 0, .value = 0 };
            return none_result;
        }
    }
}

#ifndef TAPTRACE_POLICY_NO_MAIN
static int verifier(const char *label, int ok) {
    printf("[%s] %s\n", ok ? "+" : "-", label);
    return !ok;
}

int main(void) {
    PolicyContext context = { .badge_id = 1, .employee_id = 2, .department_id = 1 };
    int failure = 0;

    PolicyResult site = resolve_policy(CAT_SITE, &context);
    failure |= verifier("site resolu", site.resolved == 1);
    failure |= verifier("site nombre_correspondances", site.match_count == 3);
    failure |= verifier("site masque", site.mask == 0x7);
    failure |= verifier("site valeur", site.value == 120);

    PolicyResult zone = resolve_policy(CAT_ZONE, &context);
    failure |= verifier("zone resolu", zone.resolved == 1);
    failure |= verifier("zone nombre_correspondances", zone.match_count == 2);
    failure |= verifier("zone masque", zone.mask == 0x5);

    PolicyResult schedule = resolve_policy(CAT_SCHEDULE, &context);
    failure |= verifier("horaire resolu", schedule.resolved == 1);
    failure |= verifier("horaire nombre_correspondances", schedule.match_count == 3);
    failure |= verifier("horaire masque", schedule.mask == 0x4);
    failure |= verifier("horaire valeur", schedule.value == 360);

    PolicyResult door_class = resolve_policy(CAT_DOOR_CLASS, &context);
    failure |= verifier("classe_porte resolu", door_class.resolved == 1);
    failure |= verifier("classe_porte nombre_correspondances", door_class.match_count == 4);
    failure |= verifier("classe_porte masque", door_class.mask == 0x17);

    PolicyResult privilege = resolve_policy(CAT_PRIVILEGE, &context);
    failure |= verifier("privilege resolu", privilege.resolved == 1);
    failure |= verifier("privilege nombre_correspondances", privilege.match_count == 2);
    failure |= verifier("privilege masque", privilege.mask == 0x7);
    failure |= verifier("privilege valeur", privilege.value == 3);

    PolicyResult escort = resolve_policy(CAT_ESCORT, &context);
    failure |= verifier("escorte resolu", escort.resolved == 1);
    failure |= verifier("escorte nombre_correspondances", escort.match_count == 2);
    failure |= verifier("escorte masque", escort.mask == 0x3);
    failure |= verifier("escorte valeur", escort.value == 1);

    PolicyResult emergency = resolve_policy(CAT_EMERGENCY, &context);
    failure |= verifier("urgence resolu", emergency.resolved == 1);
    failure |= verifier("urgence nombre_correspondances", emergency.match_count == 4);
    failure |= verifier("urgence masque", emergency.mask == 0xF);
    failure |= verifier("urgence valeur", emergency.value == 4);

    PolicyResult terminal = resolve_policy(CAT_TERMINAL, &context);
    failure |= verifier("terminal resolu", terminal.resolved == 1);
    failure |= verifier("terminal nombre_correspondances", terminal.match_count == 2);
    failure |= verifier("terminal masque", terminal.mask == 0x3);

    PolicyResult invalid = resolve_policy(99, &context);
    failure |= verifier("categorie invalide non resolue", invalid.resolved == 0);

    return failure;
}
#endif
