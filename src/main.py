from pathlib import Path
from apate import encrypt, decrypt, ui

P = input("Enter the path of the file or directory to encrypt: ")


class main:
    def __init__(self):
        pass

    def user_interface(self):
        pass

    def encrypt_file_Aes256GcmRsaOaep(self, P):
        K = Path("~/.local/share/Apate")
        if encrypt.Aes256GcmRsaOaep.locate_file(P) == True:
            original_filename = Path(P).name
            File = Path(P).read_bytes()
            new_file = encrypt.Aes256GcmRsaOaep.encrypt_data_aes(
                File, original_filename
            )
            try:
                if not K.exists:
                    K.mkdir(parents=True, exist_ok=True)
            except:
                return
            finally:
                M = Path(K).joinpath(original_filename.rstrip("."))
                M.with_suffix(".veil").write_bytes(new_file)

    def decrypt_file(self):
        pass
