# led.py - LED de la placa
# Responsable: Integrante B
#
# Por hacer:
#   [x] handshake_ok(): prender 1 s
#   [x] aceptado(): 1 parpadeo
#   [x] rechazado(): 3 parpadeos rapidos

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