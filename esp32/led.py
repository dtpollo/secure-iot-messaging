# led.py - Board LED
# Owner: Member B
#
# To do:
#   [x] handshake_ok(): turn on for 1 s
#   [x] aceptado(): 1 blink
#   [x] rechazado(): 3 fast blinks

import time
from machine import Pin
import config

pin_led = Pin(config.LED_PIN, Pin.OUT)
pin_led.value(0)


def handshake_ok():
    pin_led.value(1)
    time.sleep_ms(1000)
    pin_led.value(0)


def aceptado():
    pin_led.value(1)
    time.sleep_ms(200)
    pin_led.value(0)


def rechazado():
    for _ in range(3):
        pin_led.value(1)
        time.sleep_ms(100)
        pin_led.value(0)
        time.sleep_ms(100)


if __name__ == "__main__":
    # LED test: run with  python -m mpremote connect COM5 run esp32/led.py
    # (or  .\subir.ps1 alice -Prueba led.py ; uses LED_PIN from config.py)
    print("handshake_ok: on for 1 s")
    handshake_ok()
    time.sleep_ms(1000)
    print("aceptado: 1 blink")
    aceptado()
    time.sleep_ms(1000)
    print("rechazado: 3 fast blinks")
    rechazado()
