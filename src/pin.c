#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>
#include "pin.h"

// une table de calibration par position (comme un profil par touche), une
// entree par chiffre + la case de remplissage. evite qu'un chiffre partage
// entre deux positions ne rechauffe la mauvaise case.
static CalibrationEntry calibration_table[PIN_LENGTH][CALIBRATION_TABLE_SIZE];
static pin_code_t secret_pin;
static uint32_t last_checksum;

int generate_secret_pin(void) {
    uint8_t raw[PIN_LENGTH];
    size_t filled = 0;
    while (filled < sizeof(raw)) {
        ssize_t n = getrandom(raw + filled, sizeof(raw) - filled, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        filled += (size_t)n;
    }

    for (int i = 0; i < PIN_LENGTH; i++) {
        secret_pin[i] = raw[i] % PIN_DIGIT_COUNT;
    }

    for (int p = 0; p < PIN_LENGTH; p++) {
        for (int i = 0; i < CALIBRATION_TABLE_SIZE; i++) {
            memset(calibration_table[p][i].data, (uint8_t)(p * 13 + i * 7 + 1), CALIBRATION_ENTRY_SIZE);
        }
    }

    return 0;
}

// reserve au canal admin, jamais appele depuis le traitement d'une requete publique
void get_secret_pin(pin_code_t out) {
    memcpy(out, secret_pin, sizeof(secret_pin));
}

// le cout reel depend du cache CPU : chaud si l'entree vient d'etre touchee,
// froid sinon. c'est ce comportement materiel qui fuit, pas un delai ajoute
static uint32_t touch_entry(int position, int digit) {
    int index = digit % CALIBRATION_TABLE_SIZE; // borne l'octet recu du reseau
    uint32_t acc = 0;
    const CalibrationEntry *entry = &calibration_table[position][index];
    for (size_t i = 0; i < CALIBRATION_ENTRY_SIZE; i += 64) {
        acc += entry->data[i];
    }
    return acc;
}

// relit le profil du secret PUIS celui du candidat : si les deux chiffres
// sont identiques, la 2e lecture retombe sur la meme entree (cache chaud).
// pas de branchement ni de sortie anticipee, la fuite vient juste de quelle
// entree est relue
int validate_pin_vulnerable(const pin_code_t candidate) {
    uint32_t checksum = 0;
    uint8_t diff = 0;
    for (int i = 0; i < PIN_LENGTH; i++) {
        checksum += touch_entry(i, secret_pin[i]);
        checksum += touch_entry(i, candidate[i]);
        diff |= (uint8_t)(candidate[i] ^ secret_pin[i]);
    }
    last_checksum = checksum;
    return diff == 0;
}

// relit systematiquement toute la table, meme ordre, quel que soit le
// candidat -> motif d'acces memoire constant
int validate_pin_hardened(const pin_code_t candidate) {
    uint32_t checksum = 0;
    uint8_t diff = 0;
    for (int i = 0; i < PIN_LENGTH; i++) {
        diff |= (uint8_t)(candidate[i] ^ secret_pin[i]);
    }
    for (int p = 0; p < PIN_LENGTH; p++) {
        for (int i = 0; i < CALIBRATION_TABLE_SIZE; i++) {
            checksum += touch_entry(p, i);
        }
    }
    last_checksum = checksum;
    return diff == 0;
}

#ifndef DIGICODE_PIN_NO_MAIN
#include <stdio.h>

int main(void) {
    int failure = 0;

    if (generate_secret_pin() != 0) {
        printf("[-] generation du pin : echec\n");
        return 1;
    }
    printf("[+] generation du pin : ok\n");

    pin_code_t secret;
    get_secret_pin(secret);

    pin_code_t wrong0;
    memcpy(wrong0, secret, sizeof(wrong0));
    wrong0[0] = (uint8_t)((wrong0[0] + 1) % PIN_DIGIT_COUNT);

    pin_code_t wrong3;
    memcpy(wrong3, secret, sizeof(wrong3));
    wrong3[3] = (uint8_t)((wrong3[3] + 1) % PIN_DIGIT_COUNT);

    if (validate_pin_vulnerable(secret) == 1) {
        printf("[+] vulnerable, code correct : ok\n");
    } else {
        printf("[-] vulnerable, code correct : echec\n");
        failure = 1;
    }
    if (validate_pin_vulnerable(wrong0) == 0 && validate_pin_vulnerable(wrong3) == 0) {
        printf("[+] vulnerable, code incorrect rejete : ok\n");
    } else {
        printf("[-] vulnerable, code incorrect rejete : echec\n");
        failure = 1;
    }

    if (validate_pin_hardened(secret) == 1) {
        printf("[+] durcie, code correct : ok\n");
    } else {
        printf("[-] durcie, code correct : echec\n");
        failure = 1;
    }
    if (validate_pin_hardened(wrong0) == 0 && validate_pin_hardened(wrong3) == 0) {
        printf("[+] durcie, code incorrect rejete : ok\n");
    } else {
        printf("[-] durcie, code incorrect rejete : echec\n");
        failure = 1;
    }

    return failure;
}
#endif
