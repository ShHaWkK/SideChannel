#!/bin/bash
# Script de demo pour la soutenance TAPTRACE.
# Lance le serveur (vulnerable ou hardened), attend qu'il soit ready,
# affiche son PID et son log, puis attend une commande d'arret propre.
# Usage : ./demo.sh vulnerable | ./demo.sh hardened

set -u
cd "$(dirname "$0")"

VARIANT="${1:-}"
if [ "$VARIANT" = "vulnerable" ]; then
    BINARY=./taptrace_server
elif [ "$VARIANT" = "hardened" ]; then
    BINARY=./taptrace_server_hardened
else
    echo "Usage : $0 vulnerable|hardened"
    exit 1
fi

if [ ! -x "$BINARY" ]; then
    echo "$BINARY n'existe pas, lance 'make' d'abord."
    exit 1
fi

if ss -tln 2>/dev/null | grep -q ":9000 "; then
    echo "Le port 9000 est deja occupe. Arrete l'instance existante avant de relancer la demo"
    exit 1
fi

echo "=== Demarrage de $BINARY sur 127.0.0.1:9000 ==="
TAPTRACE_QUIET=1 "$BINARY" &
PID=$!
echo "PID serveur : $PID"

trap 'echo; echo "=== Arret du serveur (PID $PID) ==="; kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; exit 0' INT TERM

echo "Serveur ready (mode silencieux : pas de log par request, juste le demarrage)"
echo "Ctrl+C ici arrete proprement le serveur"
echo "Dans un autre terminal, lancer :"
echo "  python3 taptrace_attack.py --badge-id 1 --demo"
echo

wait "$PID"
