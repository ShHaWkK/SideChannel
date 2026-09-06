import argparse

HINTS = {
    1: (
        "Regarde pas la reponse, elle bouge jamais de toute facon. "
        "C'est pas la que ca se passe."
    ),
    2: (
        "Le serveur fait pas le meme boulot selon ce que tu lui donnes : "
        "un octet bon declenche un traitement en plus, un octet faux se fait "
        "jeter tout de suite. Ca se voit quelque part niveau timing, meme si "
        "le message renvoye ne change jamais."
    ),
    3: (
        "Fixe tous les octets sauf un, teste les 256 valeurs de celui-la, et "
        "chronometre. Une mesure toute seule c'est du bruit, faut repeter "
        "plusieurs fois pour qu'un octet se detache vraiment des 255 autres. "
        "Une fois que t'es sur, tu le gardes et tu passes au suivant."
    ),
}


def main():
    parser = argparse.ArgumentParser(description="TAPTRACE - indices progressifs")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=1,
                         help="niveau d'indice a afficher (1 = leger, 3 = oriente solution)")
    args = parser.parse_args()

    print(f"Indice {args.level}/3")
    print()
    print(HINTS[args.level])


if __name__ == "__main__":
    main()
