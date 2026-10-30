import os
import tempfile
from pathlib import Path
import pytest

from apate import encrypt, decrypt, format
from apate.tests.test import time_count


def test_aes256_gcm_encrypt_decrypt():
    original_data = b"Confidential AES-256-GCM test payload."
    filename = "test_aes_sample.txt"

    aes_enc = encrypt.Aes256GcmRsaOaep()
    packed_veil = aes_enc.encrypt_data_aes(original_data, filename)
    assert packed_veil.startswith(b"VEIL")

    # Unpack container
    magic, version, original_filename, ciphertext, nonce, algorithm_id, rsa_protected_key = format.unpack(packed_veil)

    assert magic == b"VEIL"
    assert version == 1
    assert original_filename == filename
    assert algorithm_id == 1
    assert len(nonce) == 12
    assert len(ciphertext) > 0
    assert len(rsa_protected_key) > 0

    # Decrypt
    aes_dec = decrypt.Aes256GcmRsaOaep()
    decrypted_plaintext = aes_dec.decrypt_data_aes(
        nonce=nonce,
        ciphertext=ciphertext,
        rsa_protected_key=rsa_protected_key,
        original_filename=original_filename,
    )

    assert decrypted_plaintext == original_data


def test_chacha20_poly1305_encrypt_decrypt():
    original_data = b"Confidential ChaCha20-Poly1305 test payload."
    filename = "test_chacha_sample.txt"

    chacha_enc = encrypt.ChaCha20Poly1305RsaOaep()
    packed_veil = chacha_enc.encrypt_data_chacha(original_data, filename)
    assert packed_veil.startswith(b"VEIL")

    # Unpack container
    magic, version, original_filename, ciphertext, nonce, algorithm_id, rsa_protected_key = format.unpack(packed_veil)

    assert magic == b"VEIL"
    assert version == 1
    assert original_filename == filename
    assert algorithm_id == 2  # ChaCha20-Poly1305 algorithm ID
    assert len(nonce) == 12
    assert len(ciphertext) > 0
    assert len(rsa_protected_key) > 0

    # Decrypt
    chacha_dec = decrypt.ChaCha20Poly1305RsaOaep()
    decrypted_plaintext = chacha_dec.decrypt_data_chacha(
        nonce=nonce,
        ciphertext=ciphertext,
        rsa_protected_key=rsa_protected_key,
        original_filename=original_filename,
    )

    assert decrypted_plaintext == original_data


def test_locate_file():
    aes = encrypt.Aes256GcmRsaOaep()
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"sample")
        temp_path = tf.name

    try:
        assert aes.locate_file(temp_path) is True
        assert aes.locate_file("/path/that/definitely/does/not/exist_12345") is False
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_time_count_decorator():
    @time_count
    def sample_task(x, y):
        return x + y

    result = sample_task(10, 20)
    assert result == 30


def test_file_end_to_end(tmp_path):
    test_file = tmp_path / "document.md"
    original_content = b"# Security Test\nThis is end-to-end test data."
    test_file.write_bytes(original_content)

    # 1. Encrypt with ChaCha20
    chacha_enc = encrypt.ChaCha20Poly1305RsaOaep()
    encrypted_bytes = chacha_enc.encrypt_data_chacha(test_file.read_bytes(), test_file.name)

    veil_file = tmp_path / "document.veil"
    veil_file.write_bytes(encrypted_bytes)

    # 2. Decrypt
    packed_data = veil_file.read_bytes()
    magic, version, orig_name, ciphertext, nonce, algo_id, rsa_key = format.unpack(packed_data)

    assert algo_id == 2
    chacha_dec = decrypt.ChaCha20Poly1305RsaOaep()
    restored_bytes = chacha_dec.decrypt_data_chacha(
        nonce=nonce,
        ciphertext=ciphertext,
        rsa_protected_key=rsa_key,
        original_filename=orig_name,
    )

    assert restored_bytes == original_content
