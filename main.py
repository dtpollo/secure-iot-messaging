import time
p=(1<<2048)-1942289
t=time.ticks_ms()
pow(2,(1<<255)+12345,p)
print(time.ticks_diff(time.ticks_ms(),t),'ms')