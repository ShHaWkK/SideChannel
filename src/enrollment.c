#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "badge.h"
#include "policy.h"
#include "enrollment.h"

static void clear_policies(PolicyResult *policies) {
    for (int i = 0; i < NB_CATEGORIES; i++) {
        policies[i].resolved = 0;
        policies[i].value = 0;
    }
}

InternalResult process_enrollment(badge_id_t badge_id, const uint8_t *candidate_vector) {
    InternalResult result;
    result.badge_id = badge_id;
    result.authorized = 0;
    clear_policies(result.policies);

    const Badge *badge = find_badge(badge_id);
    if (badge == NULL) {
        return result;
    }
    const Employee *employee = find_employee(badge->employee_id);
    if (employee == NULL) {
        return result;
    }
    const Department *department = find_department(employee->department_id);
    if (department == NULL) {
        return result;
    }
    if (badge->status != BADGE_ACTIVE) {
        return result;
    }

    PolicyContext context;
    context.badge_id = badge->badge_id;
    context.employee_id = badge->employee_id;
    context.department_id = employee->department_id;

    int valid_count = 0;
    for (int i = 0; i < ACCESS_VECTOR_LENGTH; i++) {
        if (candidate_vector[i] != badge->access_vector[i]) {
            break;
        }
        result.policies[i] = resolve_policy(i, &context);
        valid_count++;
    }
    result.authorized = (valid_count == ACCESS_VECTOR_LENGTH) ? 1 : 0;
    return result;
}

InternalResult process_enrollment_hardened(badge_id_t badge_id, const uint8_t *candidate_vector) {
    InternalResult result;
    result.badge_id = badge_id;
    result.authorized = 0;
    clear_policies(result.policies);

    const Badge *badge = find_badge(badge_id);
    if (badge == NULL) {
        return result;
    }
    const Employee *employee = find_employee(badge->employee_id);
    if (employee == NULL) {
        return result;
    }
    const Department *department = find_department(employee->department_id);
    if (department == NULL) {
        return result;
    }
    if (badge->status != BADGE_ACTIVE) {
        return result;
    }

    PolicyContext context;
    context.badge_id = badge->badge_id;
    context.employee_id = badge->employee_id;
    context.department_id = employee->department_id;

    uint8_t difference = 0;
    for (int i = 0; i < ACCESS_VECTOR_LENGTH; i++) {
        difference |= candidate_vector[i] ^ badge->access_vector[i];
        result.policies[i] = resolve_policy(i, &context);
    }
    result.authorized = (difference == 0) ? 1 : 0;
    return result;
}

#ifndef TAPTRACE_ENROLLMENT_NO_MAIN
int main(void) {
    badge_id_t id = provision_badge(1);
    if (id == 0) {
        printf("[-] provisioning echoue\n");
        return 1;
    }
    const Badge *badge = find_badge(id);

    uint8_t v_wrong0[ACCESS_VECTOR_LENGTH];
    memcpy(v_wrong0, badge->access_vector, ACCESS_VECTOR_LENGTH);
    v_wrong0[0] ^= 0xFF;

    uint8_t v_wrong1[ACCESS_VECTOR_LENGTH];
    memcpy(v_wrong1, badge->access_vector, ACCESS_VECTOR_LENGTH);
    v_wrong1[1] ^= 0xFF;

    uint8_t v_wrong4[ACCESS_VECTOR_LENGTH];
    memcpy(v_wrong4, badge->access_vector, ACCESS_VECTOR_LENGTH);
    v_wrong4[4] ^= 0xFF;

    uint8_t v_wrong7[ACCESS_VECTOR_LENGTH];
    memcpy(v_wrong7, badge->access_vector, ACCESS_VECTOR_LENGTH);
    v_wrong7[7] ^= 0xFF;

    int failure = 0;
    const uint8_t *cases[5] = { v_wrong0, v_wrong1, v_wrong4, v_wrong7, badge->access_vector };
    const char *labels[5] = {
        "faux byte 0",
        "byte 0 ok, faux byte 1",
        "bytes 0-3 ok, faux byte 4",
        "bytes 0-6 ok, faux byte 7",
        "vecteur complet correct",
    };
    int expected_resolved[5] = { 0, 1, 4, 7, 8 };
    uint8_t expected_authorized[5] = { 0, 0, 0, 0, 1 };

    for (int c = 0; c < 5; c++) {
        InternalResult result = process_enrollment(id, cases[c]);
        int resolved_count = 0;
        for (int i = 0; i < NB_CATEGORIES; i++) {
            if (result.policies[i].resolved) {
                resolved_count++;
            }
        }
        printf("[+] %s : autorise=%u, politiques resolues=%d\n", labels[c], result.authorized, resolved_count);
        if (result.authorized != expected_authorized[c] || resolved_count != expected_resolved[c]) {
            failure = 1;
        }
    }

    for (int c = 0; c < 5; c++) {
        InternalResult result = process_enrollment_hardened(id, cases[c]);
        int resolved_count = 0;
        for (int i = 0; i < NB_CATEGORIES; i++) {
            if (result.policies[i].resolved) {
                resolved_count++;
            }
        }
        printf("[+] durcie %s : autorise=%u, politiques resolues=%d\n", labels[c], result.authorized, resolved_count);
        if (result.authorized != expected_authorized[c] || resolved_count != NB_CATEGORIES) {
            failure = 1;
        }
    }
    return failure;
}
#endif
