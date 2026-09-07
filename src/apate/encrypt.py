from pathlib import Path


class Aes256GcmRsaOaep:
    def __init__(self):
        pass

    def locate_file(self, source):      #finding if the file exists and is a file or directory
        if Path.exists(source):
            if Path.is_file(source) or Path.is_dir(source):
                return bool(Path.is_file(source) or Path.is_dir(source))

            else:
                return False

        else:
            return False

    def encrypt_data_aes(self, data):   #encrypting the data using AES-GCM and returning the ciphertext, nonce, and RSA-protected key
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = os.urandom(12)
            key = AESGCM.generate_key(bit_length=256)
            ciphertext = AESGCM(key).encrypt(nonce, data, None)
            rsa_protected_key = self.encrypt_key_rsa(key)  #encrypting the AES key using RSA and returning the RSA-protected key
            return ciphertext, nonce, rsa_protected_key

        except ImportError:
            print(
                "cryptography module not found. Please install it using 'pip install cryptography'"
            )
            return

    def encrypt_key_rsa(self, key):

        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            rsa_protected_key = rsa.generate_private_key()
            return rsa_protected_key
        
        except ModuleNotFoundError:
            return None


class Chacha20Poly1305RsaOaep:

    def __init__(self):
        pass