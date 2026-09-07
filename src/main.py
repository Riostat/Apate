from pathlib import Path
from apate import encrypt, format

P = input("Enter the path of the file or directory to encrypt: ")

class main:
    def __init__(self):
        pass

    def user_interface(self):
        pass

    def encrypt_file(self, P):
        if encrypt.enc.locate_file(P) == True:
            original_filename = Path(P).name
            File = Path(P).read_bytes()
            new_file = format.veilcontainer.pack(File, original_filename)
            Path(P).with_suffix(".veil").write_bytes(new_file)

    def decrypt_file(self):
        pass