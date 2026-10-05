# padding.py - PKCS#7 padding (notes §3.9)
# AES works on 16-byte blocks, so the message is padded up to a multiple of 16.
# n = 16 - (L mod 16) bytes are appended, each with the value n (1 <= n <= 16).

BLOCK = 16


def pkcs7_pad(data):
    # data must be a bytes object
    n = BLOCK - len(data) % BLOCK
    return data + bytes([n]) * n


def pkcs7_unpad(data):
    if len(data) == 0 or len(data) % BLOCK != 0:
        raise ValueError("Invalid padding: inconsistent length")
    n = data[-1]
    if n < 1 or n > BLOCK:
        raise ValueError("Invalid padding: value out of range")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid padding: bytes do not match")
    return data[:-n]


# Test the padding
if __name__ == "__main__":

    sms = "post-quantum crypto in TLS".encode()
    p = pkcs7_pad(sms)
    print(f"I.len: {len(sms)}, F.len: {len(p)}")
    print(f"SMS: {sms}")
    print(f"PDD: {p}")

    d = pkcs7_unpad(p)
    print(f"U.len: {len(d)}")
    print(f"SMS: {d.decode()}")
    # A message that is already a multiple of 16 gets a full extra block
    p16 = pkcs7_pad(b"A" * 16)
    print(f"16 B -> {len(p16)} B, last byte: {p16[-1]}")

    # Bad padding must raise ValueError (the receiver never sees this: the TAG fails first)
    bad = [
        ("length not multiple of 16", p[:-1]),
        ("last byte = 0", p[:-1] + b"\x00"),
        ("last byte = 17", p[:-1] + b"\x11"),
        ("bytes do not match", b"A" * 14 + b"\x01\x02"),
    ]
    for name, data in bad:
        try:
            pkcs7_unpad(data)
            print(f"{name}: ACCEPTED (wrong)")
        except ValueError as e:
            print(f"{name}: rejected ({e})")
