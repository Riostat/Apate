import struct
from apate import encrypt

class veilcontainer:
    def __init__(self):
        pass

    def pack(self, data, original_filename):
        MAGIC = b"VEIL"
        VERSION = 1
        algorithm_id = 1  # AES-256-GCM with RSA-OAEP
        ciphertext, nonce, rsa_protected_key = encrypt.Aes256GcmRsaOaep.encrypt_data_aes(data)
        filename_bytes = original_filename.encode("utf-8")
        filename_length = len(filename_bytes)
        veil_data = (
            struct.pack("<5sB", MAGIC, VERSION)
            + struct.pack("<Q", filename_length)
            + filename_bytes
            + struct.pack("I", len(ciphertext))
            + ciphertext
            + nonce
            + struct.pack("<B", algorithm_id)
            + struct.pack("<I", len(rsa_protected_key))
            + rsa_protected_key
        )
        return veil_data
    
    def unpack(self, packed_data):
        pass

