#!/usr/bin/env bash
# subir.sh - Copies the code and each board's config to the ESP32
# Usage: bash subir.sh alice                       Alice: code + config_alice.py
#        bash subir.sh bob                         Bob: code + config_bob.py
#        bash subir.sh ambas                       ambas = both boards
#        bash subir.sh ambas --atacante            their packets go through the attacker PC (attacker.py)
#        bash subir.sh alice protocol.py           also runs that test on the board
# Ports: COM5 (Alice) and COM7 (Bob). On Linux, for example:
#        PUERTO_ALICE=/dev/ttyUSB0 PUERTO_BOB=/dev/ttyUSB1 bash subir.sh ambas

set -e

cd "$(dirname "$0")"

# Ports: from puertos.env (not pushed; see INSTRUCCIONES.md) or from the environment
[ -f puertos.env ] && . ./puertos.env
PUERTO_ALICE=${PUERTO_ALICE:-/dev/ttyUSB0}
PUERTO_BOB=${PUERTO_BOB:-/dev/ttyUSB1}
COMUNES="padding.py aes_cbc.py tag.py hkdf.py dh.py protocol.py medir.py"

PLACA=$1
ATACANTE=no
PRUEBA=""
for arg in "${@:2}"; do
    if [ "$arg" = "--atacante" ]; then ATACANTE=si; else PRUEBA=$arg; fi
done

subir() {
    nombre=$1
    if [ "$nombre" = "alice" ]; then puerto=$PUERTO_ALICE; else puerto=$PUERTO_BOB; fi
    cfg="esp32/config_$nombre.py"
    echo
    echo "=== $nombre ($puerto) ==="
    if [ ! -f "$cfg" ]; then
        echo "Missing $cfg (copy esp32/config_$nombre.example.py and fill it in)"
        return
    fi

    echo "Copying common/ and esp32/"
    python -m mpremote connect "$puerto" fs cp $(for f in $COMUNES; do echo "common/$f"; done) esp32/led.py esp32/main.py :

    # The config is copied with the name config.py. With --atacante, USAR_ATACANTE = True is added
    tmp=$(mktemp -d)/config.py
    cp "$cfg" "$tmp"
    if [ "$ATACANTE" = "si" ]; then printf '\nUSAR_ATACANTE = True\n' >> "$tmp"; fi
    python -m mpremote connect "$puerto" fs cp "$tmp" :config.py
    if [ "$ATACANTE" = "si" ]; then echo "Copied $cfg -> config.py (WITH attacker)"; else echo "Copied $cfg -> config.py (direct)"; fi
    rm -f "$tmp"

    if [ -n "$PRUEBA" ]; then
        # run executes the file as __main__, so its test runs
        if [ "$PRUEBA" = "led.py" ] || [ "$PRUEBA" = "main.py" ]; then
            archivo="esp32/$PRUEBA"
        else
            archivo="common/$PRUEBA"
        fi
        echo "Running $archivo on $nombre"
        python -m mpremote connect "$puerto" run "$archivo"
    fi
}

case "$PLACA" in
    alice|bob) subir "$PLACA" ;;
    ambas) subir alice; subir bob ;;
    *) echo "Usage: bash subir.sh alice|bob|ambas [--atacante] [test.py]"; exit 1 ;;
esac
