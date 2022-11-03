import random
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import ciphers


def aes_encrypt(plaintext: bytes, key: bytes = None):
    if not key:
        key = random.SystemRandom().randbytes(32)

    padder = PKCS7(ciphers.algorithms.AES.block_size).padder()
    pdata = padder.update(plaintext) + padder.finalize()

    iv = random.SystemRandom().randbytes(16)
    encryptor = ciphers.Cipher(
        ciphers.algorithms.AES(key),
        ciphers.modes.CBC(iv),
    ).encryptor()

    ciphertext = encryptor.update(pdata) + encryptor.finalize()

    return key, iv + ciphertext
