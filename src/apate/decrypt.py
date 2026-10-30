import logging
from pathlib import Path
from apate import format

logger = logging.getLogger('apate')


class RsaOaep:
    def __init__(self):
        pass

    def load_rsa_key(self, original_filename: str):
        try:
            from cryptography.hazmat.primitives import serialization
            stem = Path(original_filename).stem
            p = Path(f'~/.apate/{stem}/private_key.pem').expanduser()
            if not p.exists():
                raise FileNotFoundError(f"Private key not found at {p}")
            data = p.read_bytes()
            logger.info("loading the .pem key")
            key = serialization.load_pem_private_key(
                data=data,
                password=None,
                backend=None,
            )
            logger.info(".pem key loaded!")
            return key

        except Exception as e:
            logger.warning(".pem key could not be loaded: %s", e)
            raise

    def decrypt_rsa_key(self, original_filename: str, key: bytes):
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import hashes
            pem_file = self.load_rsa_key(original_filename)
            new_key = pem_file.decrypt(
                ciphertext=key,
                padding=padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return new_key
        except Exception as e:
            logger.critical("rsa protected key could not be decrypted: %s", e)
            raise


class Aes256GcmRsaOaep(RsaOaep):
    algorithm_id = 1

    def __init__(self):
        super().__init__()

    def decrypt_data_aes(self, nonce: bytes, ciphertext: bytes, rsa_protected_key: bytes, original_filename: str) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = self.decrypt_rsa_key(original_filename, rsa_protected_key)
            file = AESGCM(key).decrypt(
                nonce=nonce,
                data=ciphertext,
                associated_data=None,
            )
            return file

        except (ImportError, ModuleNotFoundError):
            logger.warning("cryptography module not found. Please install it using 'pip install cryptography'")
            raise

    def decrypt_rsa_key(self, original_filename, key):
        return super().decrypt_rsa_key(original_filename, key)


class ChaCha20Poly1305RsaOaep(RsaOaep):
    algorithm_id = 2

    def __init__(self):
        super().__init__()

    def decrypt_data_chacha(self, nonce: bytes, ciphertext: bytes, rsa_protected_key: bytes, original_filename: str) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            key = self.decrypt_rsa_key(original_filename, rsa_protected_key)
            file = ChaCha20Poly1305(key).decrypt(
                nonce=nonce,
                data=ciphertext,
                associated_data=None,
            )
            return file
        except (ImportError, ModuleNotFoundError):
            logger.warning("cryptography module not found. Please install it using 'pip install cryptography'")
            raise

    def decrypt_rsa_key(self, original_filename, key):
        return super().decrypt_rsa_key(original_filename, key)
