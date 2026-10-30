from pathlib import Path
from apate import format
import logging

logger = logging.getLogger('apate')


class RsaOaep:
    def __init__(self):
        pass

    def encrypt_key_rsa(self, key: bytes, original_filename: str) -> bytes:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            logger.info("private key generated")
            public_key = private_key.public_key()
            logger.info("public key generated")
            rsa_protected_key = public_key.encrypt(
                plaintext=key,
                padding=padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            logger.info("key protected using RSA")
            logger.info("saving the private key...")
            self.save_key_rsa(
                private_key_rsa=private_key,
                original_filename=original_filename,
            )
            return rsa_protected_key

        except ModuleNotFoundError:
            logger.warning("cryptography module not found. Please install it using 'pip install cryptography'")
            raise

    def save_key_rsa(self, private_key_rsa, original_filename) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from pathlib import Path
            stem = Path(original_filename).stem
            private_key_bytes = private_key_rsa.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_path = Path(f"~/.apate/{stem}/private_key.pem").expanduser()
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(private_key_bytes)
            logger.info("private key saved!")

        except ModuleNotFoundError:
            logger.warning("cryptography module not found. Please install it using 'pip install cryptography'")
            raise


class Aes256GcmRsaOaep(RsaOaep):
    algorithm_id = 1

    def __init__(self):
        super().__init__()

    @staticmethod
    def locate_file(
        source,
    ) -> bool:  # finding if the file exists and is a file or directory
        logger.info("locating file...")
        p = Path(source)
        if p.exists():
            return bool(p.is_file() or p.is_dir())
        return False

    @format.veilcontainer().pack
    def encrypt_data_aes(
        self,
        data: bytes,
        original_filename: str,
    ) -> tuple[bytes, bytes, bytes]:  # encrypting the data using AES-GCM and returning the ciphertext, nonce, and RSA-protected key
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = os.urandom(12)
            key = AESGCM.generate_key(bit_length=256)
            ciphertext = AESGCM(key).encrypt(
                nonce=nonce,
                data=data,
                associated_data=None,
            )
            rsa_protected_key = self.encrypt_key_rsa(
                key, original_filename
            )  # encrypting the AES key using RSA and returning the RSA-protected key
            return ciphertext, nonce, rsa_protected_key

        except (ImportError, ModuleNotFoundError):
            logger.warning("cryptography module not found. Please install it using 'pip install cryptography'")
            raise

    def encrypt_key_rsa(self, key, Original_filename):
        return super().encrypt_key_rsa(key, Original_filename)


class ChaCha20Poly1305RsaOaep(RsaOaep):
    algorithm_id = 2

    def __init__(self):
        super().__init__()

    @format.veilcontainer().pack
    def encrypt_data_chacha(
        self,
        data: bytes,
        original_filename: str,
    ) -> tuple[bytes, bytes, bytes]:
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        except (ModuleNotFoundError, ImportError):
            logger.warning("cryptography module not found. Please install it using 'pip install cryptography'")
            raise

        nonce = os.urandom(12)
        key = ChaCha20Poly1305.generate_key()
        ciphertext = ChaCha20Poly1305(key).encrypt(
            nonce=nonce,
            data=data,
            associated_data=None,
        )
        rsa_protected_key = self.encrypt_key_rsa(key, original_filename)
        return ciphertext, nonce, rsa_protected_key

    def encrypt_key_rsa(self, key, original_filename):
        return super().encrypt_key_rsa(key, original_filename)
