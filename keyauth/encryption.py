import binascii

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

from .errors import InvalidApplicationInformation

def encrypt_hex(content: str) -> str:
    return binascii.hexlify(content)

def decrypt_hex(hex_content: str) -> str:
    return binascii.unhexlify(hex_content)

def encrypt_string(plain_text, key, iv):
    plain_text = pad(plain_text, 16)
    aes_instance = AES.new(key, AES.MODE_CBC, iv)
    raw_out = aes_instance.encrypt(plain_text)

    return encrypt_hex(raw_out)

def decrypt_string(cipher_text, key, iv):
    cipher_text = decrypt_hex(cipher_text)
    aes_instance = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = aes_instance.decrypt(cipher_text)

    return unpad(cipher_text, 16)

def encrypt(message, enc_key, iv):
    try:
        _key = SHA256.new(enc_key.encode()).hexdigest()[:32]
        _iv = SHA256.new(iv.encode()).hexdigest()[:16]

        data = encrypt_string(message.encode(), _key.encode(), _iv.encode())

        return data
    except Exception:
        raise InvalidApplicationInformation("Long text is secret short text is ownerid. Name is supposed to be app name not username")

def decrypt(message, enc_key, iv):
    try:
        _key = SHA256.new(enc_key.encode()).hexdigest()[:32]
        _iv = SHA256.new(iv.encode()).hexdigest()[:16]

        return decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
    except Exception:
        raise InvalidApplicationInformation("Long text is secret short text is ownerid. Name is supposed to be app name not username")