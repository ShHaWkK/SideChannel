#ifndef PIN_H
#define PIN_H

#include <stdint.h>
#include <stddef.h>

#define PIN_LENGTH 4
#define PIN_DIGIT_COUNT 10

// case hors alphabet 0-9, juste pour remplir les positions pas encore
// testees sans fausser la mesure sur un vrai chiffre
#define PIN_PADDING_DIGIT PIN_DIGIT_COUNT
#define CALIBRATION_TABLE_SIZE (PIN_DIGIT_COUNT + 1)

// taille choisie pour que l'ecart chaud/froid reste mesurable a travers un
// aller-retour reseau (mesure sur cette machine, voir writeup/RAPPORT.md)
#define CALIBRATION_ENTRY_SIZE (1024 * 1024)

typedef uint8_t pin_code_t[PIN_LENGTH];

typedef struct {
    uint8_t data[CALIBRATION_ENTRY_SIZE];
} CalibrationEntry;

int generate_secret_pin(void);
void get_secret_pin(pin_code_t out);

int validate_pin_vulnerable(const pin_code_t candidate);
int validate_pin_hardened(const pin_code_t candidate);

#endif
