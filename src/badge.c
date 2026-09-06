#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>
#include "badge.h"

// Tableau des employés
static const Employee employees[] = {
    { .employee_id = 1, .department_id = 1 },
    { .employee_id = 2, .department_id = 1 },
    { .employee_id = 3, .department_id = 2 },
};

// Nombre d'employés dans le tableau
static const size_t employee_count = sizeof(employees) / sizeof(employees[0]);


// Tableau des départements
static const Department departments[] = {
    { .department_id = 1 },
    { .department_id = 2 },
};

// Nombre de départements dans le tableau
static const size_t department_count = sizeof(departments) / sizeof(departments[0]);

// Tableau des badges provisionnés
static Badge badges[MAX_BADGES];
static size_t badge_count = 0;
static badge_id_t next_badge_id = 1;

// Trouve un employé par son ID
const Employee *find_employee(uint32_t employee_id) {
    for (size_t i = 0; i < employee_count; i++) {
        if (employees[i].employee_id == employee_id) {
            return &employees[i];
        }
    }
    return NULL;
}

// Trouve un département par son ID
const Department *find_department(uint32_t department_id) {
    for (size_t i = 0; i < department_count; i++) {
        if (departments[i].department_id == department_id) {
            return &departments[i];
        }
    }
    return NULL;
}

// Trouve un badge par son ID
const Badge *find_badge(badge_id_t badge_id) {
    for (size_t i = 0; i < badge_count; i++) {
        if (badges[i].badge_id == badge_id) {
            return &badges[i];
        }
    }
    return NULL;
}

// Définit le statut d'un badge
void set_badge_status(badge_id_t badge_id, badge_status_t status) {
    for (size_t i = 0; i < badge_count; i++) {
        if (badges[i].badge_id == badge_id) {
            badges[i].status = status;
            return;
        }
    }
}

// Génère un vecteur d'accès aléatoire
int generate_access_vector(access_vector_t output) {
    size_t filled = 0;
    while (filled < ACCESS_VECTOR_LENGTH) {
        ssize_t n = getrandom(output + filled, ACCESS_VECTOR_LENGTH - filled, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        filled += (size_t)n;
    }
    return 0;
}

// Provisionne un badge pour un employé donné

badge_id_t provision_badge(uint32_t employee_id) {
    const Employee *employee = find_employee(employee_id);
    if (employee == NULL) {
        return 0;
    }
    if (find_department(employee->department_id) == NULL) {
        return 0;
    }
    if (badge_count >= MAX_BADGES) {
        return 0;
    }
    if (next_badge_id == 0) {
        return 0;
    }

    Badge candidate;
    candidate.badge_id = next_badge_id;
    candidate.employee_id = employee_id;
    candidate.status = BADGE_ACTIVE;
    if (generate_access_vector(candidate.access_vector) != 0) {
        return 0;
    }

    badges[badge_count] = candidate;
    badge_count++;
    if (next_badge_id == UINT32_MAX) {
        next_badge_id = 0;
    } else {
        next_badge_id++;
    }
    return candidate.badge_id;
}

#ifndef TAPTRACE_BADGE_NO_MAIN

// Fonction principale pour les tests
int main(void) {
    int failure = 0;

    badge_id_t id1 = provision_badge(1);
    badge_id_t id2 = provision_badge(2);
    if (id1 != 0 && id2 != 0) {
        printf("[+] provisioning valide : ok\n");
    } else {
        printf("[-] provisioning valide : echec\n");
        failure = 1;
    }

    if (id1 != 0 && id2 == id1 + 1) {
        printf("[+] ids sequentiels : ok\n");
    } else {
        printf("[-] ids sequentiels : echec\n");
        failure = 1;
    }

    int is_different = memcmp(badges[0].access_vector, badges[1].access_vector, ACCESS_VECTOR_LENGTH) != 0;
    printf("[+] vecteurs differents : %s\n", is_different ? "oui" : "non");
    if (!is_different) {
        failure = 1;
    }

    if (provision_badge(999) == 0) {
        printf("[+] employe inconnu rejete : ok\n");
    } else {
        printf("[-] employe inconnu rejete : echec\n");
        failure = 1;
    }

    if (find_employee(999) == NULL) {
        printf("[+] employe inconnu non trouve : ok\n");
    } else {
        printf("[-] employe inconnu non trouve : echec\n");
        failure = 1;
    }

    if (find_department(1) != NULL && find_department(2) != NULL) {
        printf("[+] departement connu trouve : ok\n");
    } else {
        printf("[-] departement connu trouve : echec\n");
        failure = 1;
    }

    while (badge_count < MAX_BADGES) {
        uint32_t emp = employees[badge_count % employee_count].employee_id;
        if (provision_badge(emp) == 0) {
            printf("[-] remplissage limite badges : echec\n");
            failure = 1;
            break;
        }
    }
    printf("[+] nombre de badges a la limite : %s\n", badge_count == MAX_BADGES ? "ok" : "echec");
    if (badge_count != MAX_BADGES) {
        failure = 1;
    }

    if (provision_badge(1) == 0) {
        printf("[+] limite de badges : ok\n");
    } else {
        printf("[-] limite de badges : echec\n");
        failure = 1;
    }

    return failure;
}
#endif
