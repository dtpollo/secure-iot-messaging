#!/usr/bin/env bash
# subir.sh - Copia los modulos de common/ a la raiz de la ESP32 y corre la prueba de protocol.py
# Uso:  bash subir.sh                 (usa COM5)
#       bash subir.sh /dev/ttyUSB0    (otro puerto, ej. en Linux)

set -e

PUERTO=${1:-COM5}
MODULOS="padding.py aes_cbc.py tag.py hkdf.py dh.py protocol.py"

cd "$(dirname "$0")/common"

echo "Copiando a la ESP32 ($PUERTO): $MODULOS"
mpremote connect "$PUERTO" fs cp $MODULOS :

echo "Corriendo la prueba de protocol.py"
mpremote connect "$PUERTO" run protocol.py
