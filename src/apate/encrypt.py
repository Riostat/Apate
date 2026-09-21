from pathlib import Path
from apate import format
import logging

class RsaOaep:
    def __init__(self):
        pass

    def encrypt_key_rsa(self, key, original_filename):
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            logging.info("private key genarated")
            public_key = private_key.public_key()
            logging.info("public key generated")
            rsa_protected_key = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            logging.info("key protected using RSA")
            logging.info("saving the private key...")
            self.save_key_rsa(
                private_key_rsa = private_key,
                original_filename = original_filename
                )
            return rsa_protected_key

        except ModuleNotFoundError:
            logging.warning("cryptography module not found. Please install it using 'pip install cryptography")

    def save_key_rsa(self, private_key_rsa,original_filename) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from pathlib import Path
            original_filename = Path(original_filename).stem
            private_key_bytes = private_key_rsa.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.PKCS8,
                encryption_algorithm = serialization.NoEncryption()
            )
            Path(f"~/.apate/{original_filename}/private_key.pem").expanduser().write_bytes(private_key_bytes)
            logging.info("private key saved!")

        except ModuleNotFoundError:
            logging.warning("cryptography module not found. Please install it using 'pip install cryptography'")


class Aes256GcmRsaOaep(RsaOaep):
    def __init__(self):
        super().__init__(self)

    def locate_file(
        self, source
    ) -> bool:  # finding if the file exists and is a file or directory
        logging.info("locating file...")
        if Path.exists(source):
            if Path.is_file(source) or Path.is_dir(source):
                return bool(Path.is_file(source) or Path.is_dir(source))

            else:
                return False

        else:
            return False
        
    @format.veilcontainer().pack
    def encrypt_data_aes(
        self,
        data : bytes,
        original_filename
    ) -> tuple[bytes, bytes, bytes]:  # encrypting the data using AES-GCM and returning the ciphertext, nonce, and RSA-protected key
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = os.urandom(12)
            key = AESGCM.generate_key(bit_length=256)
            ciphertext = AESGCM(key).encrypt(
                nonce=nonce, 
                data=data, 
                associated_data=None
            )
            rsa_protected_key = self.encrypt_key_rsa(
                key
            )  # encrypting the AES key using RSA and returning the RSA-protected key
            self.encrypt_key_rsa(key=key, Original_filename=original_filename)
            return ciphertext, nonce, rsa_protected_key

        except ImportError:
            logging.warning("cryptography module not found. Please install it using 'pip install cryptography")

    def encrypt_key_rsa(self, key, Original_filename):
        return super().encrypt_key_rsa(key, Original_filename)


class Chacha20Poly1305RsaOaep(RsaOaep):
    def __init__(self):
        super().__init__()

    @format.veilcontainer().pack
    def encrypt_data_chacha(
        data : bytes
        ) -> tuple[bytes, bytes, bytes]:
        pass

    def encrypt_key_rsa(self, key):
        return super().encrypt_key_rsa(key)
