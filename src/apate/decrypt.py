from pathlib import Path
from apate import format


class RsaOaep:
    def load_rsa_keys(self, data):
        try:
            from cryptography.hazmat.primitives import serialization

            public_key = serialization.load_pem_public_key(data=data, backend=None)
            private_key = serialization.load_pem_private_key(
                data=data, password=public_key, backend=None
            )
            return private_key

        except:
            return

    def decrypt_rsa_key(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes

        except ImportError:
            return


class Aes256GcmRsaOaep(RsaOaep):
    def __init__(self):
        pass

    @format.veilcontainer.unpack()
    def decrypt_data_aes(self, nonce, ciphertext, rsa_protected_key):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            key = self.load_rsa_keys(rsa_protected_key)
            file = AESGCM(key).decrypt(
                nonce=nonce, data=ciphertext, associated_data=None
            )
            return file

        except ImportError:
            pass

    def load_rsa_keys(self, private_key):
        return super().load_rsa_keys(private_key)

    def decrypt_rsa_key(self, key):
        return super().decrypt_rsa_key(key)


class Chacha20Poly1305RsaOaep(RsaOaep):
    def __init__(self):
        super().__init__()

    def load_rsa_keys(self, data):
        return super().load_rsa_keys(data)

    def decrypt_rsa_key(self):
        return super().decrypt_rsa_key()
