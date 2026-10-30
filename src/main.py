import os
import logging
from pathlib import Path
from apate import encrypt, decrypt, format, ui
from apate.ui import app_ui

logger = logging.getLogger('apate')


class main:
    def __init__(self):
        pass

    def user_interface(self):
        pass

    def encrypt(self, B: int):
        if B == 1:
            self.encrypt_file_Aes256GcmRsaOaep()
        elif B == 2:
            self.encrypt_file_Chacha20Poly1305RsaOaep()
        else:
            app_ui.display_error_message("Invalid choice. Please select a valid encryption algorithm.")

    def encrypt_file_Aes256GcmRsaOaep(self):
        P = app_ui.get_input_path()
        src_path = Path(P)
        aes_enc = encrypt.Aes256GcmRsaOaep()
        if not aes_enc.locate_file(src_path):
            app_ui.display_error_message(f"File or directory not found: {P}")
            return

        File = src_path.read_bytes()
        original_filename = src_path.name
        new_file = aes_enc.encrypt_data_aes(File, original_filename)

        K = Path(f"~/.apate/{src_path.stem}").expanduser()
        try:
            if not K.exists():
                K.mkdir(parents=True, exist_ok=True)
        except Exception:
            logger.warning("something went wrong in main.py")

        M = Path(K).joinpath(src_path.stem)
        out_path = M.with_suffix(".veil")
        out_path.write_bytes(new_file)
        app_ui.display_success_message(f"File encrypted to {out_path}")

    def encrypt_file_Chacha20Poly1305RsaOaep(self):
        P = app_ui.get_input_path()
        src_path = Path(P)
        if not (src_path.exists() and src_path.is_file()):
            app_ui.display_error_message(f"File not found: {P}")
            return

        File = src_path.read_bytes()
        original_filename = src_path.name
        chacha_enc = encrypt.ChaCha20Poly1305RsaOaep()
        new_file = chacha_enc.encrypt_data_chacha(File, original_filename)

        K = Path(f"~/.apate/{src_path.stem}").expanduser()
        try:
            if not K.exists():
                K.mkdir(parents=True, exist_ok=True)
        except Exception:
            logger.warning("something went wrong in main.py")

        M = Path(K).joinpath(src_path.stem)
        out_path = M.with_suffix(".veil")
        out_path.write_bytes(new_file)
        app_ui.display_success_message(f"File encrypted to {out_path}")

    def decrypt(self):
        try:
            P = app_ui.get_decrypt_input_path()
            veil_path = Path(P)
            if not (veil_path.exists() and veil_path.is_file()):
                app_ui.display_error_message(f"File not found: {P}")
                return

            packed_data = veil_path.read_bytes()
            magic, version, original_filename, ciphertext, nonce, algorithm_id, rsa_protected_key = format.veilcontainer.unpack(packed_data)

            if algorithm_id == 1:
                aes_dec = decrypt.Aes256GcmRsaOaep()
                plaintext = aes_dec.decrypt_data_aes(
                    nonce=nonce,
                    ciphertext=ciphertext,
                    rsa_protected_key=rsa_protected_key,
                    original_filename=original_filename,
                )
            elif algorithm_id == 2:
                chacha_dec = decrypt.ChaCha20Poly1305RsaOaep()
                plaintext = chacha_dec.decrypt_data_chacha(
                    nonce=nonce,
                    ciphertext=ciphertext,
                    rsa_protected_key=rsa_protected_key,
                    original_filename=original_filename,
                )
            else:
                logger.warning("wrong number entered")
                app_ui.display_error_message(f"Unsupported algorithm id: {algorithm_id}")
                return

            out_path = veil_path.parent / f"decrypted_{original_filename}"
            out_path.write_bytes(plaintext)
            app_ui.display_success_message(f"File decrypted to {out_path}")

        except OSError as e:
            app_ui.display_error_message(f"File or OS error: {e}")
        except ValueError as e:
            app_ui.display_error_message(f"Data unpacking failed or file is corrupted: {e}")
        except Exception as e:
            app_ui.display_error_message(f"Decryption failed: {e}")


Main = main


def run():
    app = main()
    app_ui.display_banner()
    choice = app_ui.get_main_menu_choice()
    if choice == 1:
        algo_choice = app_ui.get_encryption_algo_choice()
        app.encrypt(algo_choice)
    elif choice == 2:
        app.decrypt()


if __name__ == "__main__":
    run()
