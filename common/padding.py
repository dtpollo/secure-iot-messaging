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

    sms = "criptografia poscuantica en TLS".encode()
    p = pkcs7_pad(sms)
    print(f"I.len: {len(sms)}, F.len: {len(p)}")
    print(f"SMS: {sms}")
    print(f"PDD: {p}")

    d = pkcs7_unpad(p)
    print(f"U.len: {len(d)}")
    print(f"SMS: {d.decode()}")