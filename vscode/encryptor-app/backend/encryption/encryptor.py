from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
import base64

class Encryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode()
        }

    def decrypt(self, nonce, ciphertext, tag):
        nonce = base64.b64decode(nonce)
        ciphertext = base64.b64decode(ciphertext)
        tag = base64.b64decode(tag)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()