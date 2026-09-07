from pathlib import Path


class Aes256GcmRsaOaep:
    def __init__(self):
        pass

    def decrypt_data_aes(self):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            file = AESGCM.decrypt()

        except ImportError:
            pass

    def decrypt_aes_key(self):
        pass