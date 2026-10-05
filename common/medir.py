# medir.py - Size and time measurements on the ESP32 (PDF §5, notes §9)
# Measures: message size, packet size, seal time (encrypt + TAG),
# open time (verify + decrypt) and handshake time.
# Network latency is measured separately with option 3 of the main.py menu.
#
# Run it on the board (it copies the modules first):
#   .\subir.ps1 alice -Prueba medir.py
#
# Every sample is saved to measure_esp32.csv on the board. Copy it to the PC with:
#   python -m mpremote connect COM5 fs cp :measure_esp32.csv results/measure_esp32.csv
#
# main.py and node.py use ahora_us(), ms_desde(), resumen() and guardar_csv() from this file.

import os
import sys
import time

MICROPYTHON = sys.implementation.name == "micropython"


def ahora_us():
    # current time in microseconds
    if MICROPYTHON:
        return time.ticks_us()
    return time.perf_counter_ns() // 1000


def ms_desde(t0):
    # milliseconds since t0 (t0 comes from ahora_us)
    if MICROPYTHON:
        return time.ticks_diff(time.ticks_us(), t0) / 1000
    return (time.perf_counter_ns() // 1000 - t0) / 1000


def resumen(tiempos):
    # mean and sample standard deviation (notes §9)
    n = len(tiempos)
    prom = sum(tiempos) / n
    if n < 2:
        return prom, 0.0
    var = sum((t - prom) ** 2 for t in tiempos) / (n - 1)
    return prom, var ** 0.5


def guardar_csv(nombre, cabecera, filas):
    # Saves a CSV in the current folder (on the ESP32: the board's file system)
    with open(nombre, "w") as f:
        f.write(cabecera + "\n")
        for fila in filas:
            f.write(",".join(str(x) for x in fila) + "\n")
    print("Saved:", nombre)


if __name__ == "__main__":
    from protocol import Initiator, Responder, Rejected

    N = 100             # samples per message size
    CALENTAR = 10       # warm-up runs that are not saved
    N_HS = 3            # each handshake takes ~7 s on the ESP32
    TAMANOS = [8, 32, 128, 512]
    ID_A = 0x01
    ID_B = 0x02
    psk = os.urandom(32)

    print("Measuring on:", "ESP32" if MICROPYTHON else "PC")
    filas = []      # (test, L, packet, ms) for the CSV

    # 1) Handshake: A and B on the same board, no network (4 exponentiations of 2048 bits)
    tiempos = []
    for _ in range(N_HS):
        t0 = ahora_us()
        a = Initiator(ID_A, {ID_B: psk})
        b = Responder(ID_B, {ID_A: psk})
        confirm, ses_a = a.on_response(b.on_hello(a.hello(ID_B)))
        ses_b = b.on_confirm(confirm)
        tiempos.append(ms_desde(t0))
    for t in tiempos:
        filas.append(("handshake", 0, 614, t))
    prom, desv = resumen(tiempos)
    print()
    print("1) Full handshake, both sides here (n=%d): %.1f +- %.1f ms" % (N_HS, prom, desv))
    print("   With two boards each side does half of the work, plus the network time")
    print("   Bytes: HELLO 274 + RESPONSE 306 + CONFIRM 34 = 614 B (once per session)")

    # 2) DATA packets: table ready for the report
    print()
    print("2) DATA packets (n=%d per size, times in ms)" % N)
    print()
    print("| Message L (B) | Packet (B) | Overhead (B) | seal (ms) | open (ms) |")
    print("|---|---|---|---|---|")
    for L in TAMANOS:
        msg = b"x" * L
        t_seal = []
        t_open = []
        bien = True
        for _ in range(CALENTAR):
            ses_b.open(ses_a.seal(msg))
        for _ in range(N):
            t0 = ahora_us()
            p = ses_a.seal(msg)
            t_seal.append(ms_desde(t0))
            t0 = ahora_us()
            m = ses_b.open(p)
            t_open.append(ms_desde(t0))
            bien = bien and m == msg
        for t in t_seal:
            filas.append(("seal", L, len(p), t))
        for t in t_open:
            filas.append(("open", L, len(p), t))
        s_prom, s_desv = resumen(t_seal)
        o_prom, o_desv = resumen(t_open)
        print("| %d | %d | %d | %.3f +- %.3f | %.3f +- %.3f |%s" % (
            L, len(p), len(p) - L, s_prom, s_desv, o_prom, o_desv, "" if bien else " FAIL"))

    # 3) Rejecting a modified packet only costs the HMAC: it is not decrypted
    p = bytearray(ses_a.seal(b"x" * 32))
    p[-1] ^= 0x01
    p = bytes(p)
    tiempos = []
    for i in range(CALENTAR + N):
        t0 = ahora_us()
        try:
            ses_b.open(p)
        except Rejected:
            pass
        if i >= CALENTAR:
            tiempos.append(ms_desde(t0))
    for t in tiempos:
        filas.append(("reject", 32, len(p), t))
    prom, desv = resumen(tiempos)
    print()
    print("3) Reject by TAG (L=32, n=%d): %.3f +- %.3f ms" % (N, prom, desv))

    print()
    guardar_csv("measure_esp32.csv", "test,L,packet,ms", filas)
