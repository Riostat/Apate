import struct
import logging

logger = logging.getLogger('apate')


class veilcontainer:
    def __init__(self):
        pass

    def pack(self, base_fn) -> callable:
        def pack_wrapper(instance, data, original_filename) -> bytes:
            MAGIC: bytes = b"VEIL"
            VERSION: int = 1
            algorithm_id: int = getattr(instance, "algorithm_id", 1)
            ciphertext, nonce, rsa_protected_key = base_fn(instance, data, original_filename)
            filename_bytes: bytes = original_filename.encode("utf-8")
            filename_length: int = len(filename_bytes)
            logger.info("starting packing data")
            veil_data: bytes = (
                struct.pack("<4sB", MAGIC, VERSION)
                + struct.pack("<Q", filename_length)
                + filename_bytes
                + struct.pack("<I", len(ciphertext))
                + ciphertext
                + nonce
                + struct.pack("<B", algorithm_id)
                + struct.pack("<I", len(rsa_protected_key))
                + rsa_protected_key
            )
            logger.info("data packed successfully!")
            return veil_data

        return pack_wrapper

    @staticmethod
    def unpack(packed_data: bytes) -> tuple:
        offset = 0
        logger.info("starting unpacking the data")

        # MAGIC + VERSION
        magic, version = struct.unpack_from("<4sB", packed_data, offset)
        offset += struct.calcsize("<4sB")

        # filename length, then the filename bytes themselves
        (filename_length,) = struct.unpack_from("<Q", packed_data, offset)
        offset += struct.calcsize("<Q")

        filename_bytes = packed_data[offset : offset + filename_length]
        offset += filename_length
        original_filename = filename_bytes.decode("utf-8")

        # ciphertext length, then the ciphertext itself
        (ciphertext_length,) = struct.unpack_from("<I", packed_data, offset)
        offset += struct.calcsize("<I")

        ciphertext = packed_data[offset : offset + ciphertext_length]
        offset += ciphertext_length

        # nonce is always 12 bytes for AES-GCM and ChaCha20-Poly1305
        nonce = packed_data[offset : offset + 12]
        offset += 12

        # algorithm id
        (algorithm_id,) = struct.unpack_from("<B", packed_data, offset)
        offset += struct.calcsize("<B")

        # rsa key length, then the rsa-protected key itself
        (rsa_key_length,) = struct.unpack_from("<I", packed_data, offset)
        offset += struct.calcsize("<I")

        rsa_protected_key = packed_data[offset : offset + rsa_key_length]
        offset += rsa_key_length
        logger.info("data unpacked successfully!")
        return magic, version, original_filename, ciphertext, nonce, algorithm_id, rsa_protected_key


# Top-level aliases for direct usage and backwards compatibility
pack = veilcontainer().pack
unpack = veilcontainer.unpack
