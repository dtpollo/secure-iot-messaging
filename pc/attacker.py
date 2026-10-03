# attacker.py - Atacante en medio (MITM) para las pruebas de seguridad
# Responsable: Integrante B
#
# Se pone entre los dos nodos: cada nodo le manda los paquetes al atacante
# (en config.py, PEERS apunta a la IP del atacante) y el atacante los reenvia.
#
# Uso:
#   python pc/attacker.py --mode sniff        ver los paquetes
#   python pc/attacker.py --mode tamper_c     cambiar 1 bit del ciphertext   -> Rechazado: TAG
#   python pc/attacker.py --mode tamper_tag   cambiar 1 bit del TAG          -> Rechazado: TAG
#   python pc/attacker.py --mode replay       reenviar un paquete viejo      -> Rechazado: replay
#   python pc/attacker.py --mode forge        inventar un paquete            -> Rechazado: TAG
#
# Por hacer:
#   [ ] Recibir de un nodo y reenviar al otro
#   [ ] Implementar los 5 modos (solo tocar paquetes DATA, TYPE = 0x10)
#   [ ] Imprimir que se hizo con cada paquete

# Posiciones en el paquete DATA
IDS = 1
SID = slice(2, 6)
SEQ = slice(6, 10)
IV = slice(10, 26)
C = slice(26, -16)
TAG = slice(-16, None)
