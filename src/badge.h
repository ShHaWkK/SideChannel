#ifndef BADGE_H
#define BADGE_H

#include <stdint.h>
#include <stddef.h>

#define ACCESS_VECTOR_LENGTH 8
#define NB_CATEGORIES 8
#define MAX_BADGES 16

typedef uint32_t badge_id_t;

// Structure représentant un employé
typedef struct {
    uint32_t employee_id;
    uint32_t department_id;
} Employee;


// Structure représentant un département
typedef struct {
    uint32_t department_id;
} Department;

// Structure représentant un badge
typedef enum {
    BADGE_ACTIVE,
    BADGE_REVOKED,
    BADGE_EXPIRED
} badge_status_t;


// Définition des catégories d'accès
enum {
    CAT_SITE = 0,
    CAT_ZONE,
    CAT_SCHEDULE,
    CAT_DOOR_CLASS,
    CAT_PRIVILEGE,
    CAT_ESCORT,
    CAT_EMERGENCY,
    CAT_TERMINAL
};

typedef uint8_t access_vector_t[ACCESS_VECTOR_LENGTH];

// Structure représentant un badge
typedef struct {
    badge_id_t badge_id;
    uint32_t employee_id;
    badge_status_t status;
    access_vector_t access_vector;
} Badge;


// Déclarations des fonctions
const Employee *find_employee(uint32_t employee_id);
const Department *find_department(uint32_t department_id);
const Badge *find_badge(badge_id_t badge_id);
int generate_access_vector(access_vector_t output);
badge_id_t provision_badge(uint32_t employee_id);
void set_badge_status(badge_id_t badge_id, badge_status_t status);

#endif
