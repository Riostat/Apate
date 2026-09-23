import logging
from pathlib import Path
from apate import format

logger = logging.getLogger('apate')
class RsaOaep:
    def __init__(self):
        pass

    def load_rsa_key(self,original_filename):
        try:
            from cryptography.hazmat.primitives import serialization
            P = Path(f'~/.apate/{original_filename}/private_key.pem').expanduser()
            data = P.read_bytes()
            logger.info("loading the .pem key")
            key = serialization.load_pem_private_key(
                data = data,
                password = None,
                backend = None
                )
            logger.info(".pem key loaded!")
            return key

        except:
            logger.warning(".pem key could not be loaded")

    def decrypt_rsa_key(self,original_filename, key):
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            pem_file = self.load_rsa_key(original_filename)
            new_key = pem_file.decrypt(
                ciphertext = key,
                padding = padding.OAEP(
                    mgf = padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm = hashes.SHA256(),
                    label = None
                ))
            return new_key
        except:
            logger.critical("rsa protected key could not be decrypted")


class Aes256GcmRsaOaep(RsaOaep):
    def __init__(self):
        pass

    def decrypt_data_aes(self, nonce, ciphertext, rsa_protected_key, original_filename):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = self.decrypt_rsa_key(original_filename, rsa_protected_key)
            file = AESGCM(key).decrypt(
                nonce = nonce,
                data = ciphertext,
                associated_data = None
            )
            return file

        except ImportError:
            logger.warning("cryptography module not found. Please install it using 'pip install cryptography")

    def decrypt_rsa_key(self, original_filename, key):
        return super().decrypt_rsa_key(original_filename, key)


class Chacha20Poly1305RsaOaep(RsaOaep):
    def __init__(self):
        super().__init__()

    def Chacha20Poly1305(self):
        pass

    def decrypt_rsa_key(self, original_filename, key):
        return super().decrypt_rsa_key(original_filename, key)