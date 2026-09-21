import os
import logging
from pathlib import Path
from apate import encrypt, decrypt, ui

P = input("Enter the path of the file or directory to encrypt: ")


class main:
    def __init__(self):
        pass

    def user_interface(self):
        pass

    def encrypt_file_Aes256GcmRsaOaep(self, P):
         if os.name == 'posix':
            if os.getcwd == '~': pass
            else: os.chdir("~")
            original_filename = Path(P).name
            K = Path(f"~/.apate/{original_filename}").expanduser()
            if encrypt.Aes256GcmRsaOaep.locate_file(P) == True:
                File = Path(P).read_bytes()
                new_file = encrypt.Aes256GcmRsaOaep.encrypt_data_aes(
                    File, original_filename
                )
                try:
                    if not K.exists:
                        K.mkdir(parents=True, exist_ok=True)
                except:
                    logging.warning("something went wrong in main.py")
                M = Path(K).joinpath(Path(original_filename).stem)
                M.with_suffix(".veil").write_bytes(new_file)
            elif os.name == 'nt':
                pass

            else:
                return 

    def decrypt_file(self):
        pass
