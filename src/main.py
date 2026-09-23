import os
import logging
from pathlib import Path
from apate import encrypt, decrypt, format ,ui


logger = logging.getLogger('apate')
class main:
    def __init__(self):
        pass

    def user_interface(self):
        pass

    def encrypt(B : int):
        if B == 1:
            main.encrypt_file_Aes256GcmRsaOaep()
        elif B == 2:
            pass

    def encrypt_file_Aes256GcmRsaOaep(self):
         P = input("Enter the path of the file or directory to encrypt: ")
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
                    logger.warning("something went wrong in main.py")
                M = Path(K).joinpath(Path(original_filename).stem)
                M.with_suffix(".veil").write_bytes(new_file)
            elif os.name == 'nt':
                pass

            else:
                return 

    def encrypt_file_Chacha20Poly1305RsaOaep():
        pass

    def decrypt():
        try:
            if os.name == 'posix':
                magic, version, original_filename, ciphertext, nonce, algorithm_id, rsa_protected_key = format.veilcontainer.unpack()
                if algorithm_id == 1:
                    decrypt.Aes256GcmRsaOaep.decrypt_data_aes(
                        nonce=nonce,
                        ciphertext=ciphertext,
                        rsa_protected_key=rsa_protected_key, 
                        original_filename=original_filename)

                elif algorithm_id == 2:
                    decrypt.Chacha20Poly1305RsaOaep.Chacha20Poly1305() #empty-shell for now

                else:
                    logger.warning("wrong number entered")
                    print("pls enter a valid number")

            elif os.name == 'nt':
                pass

        except OSError:
            pass

        except ValueError:
            pass



print("For encyption enter 1")
print("For decryption enter 2")
A = int(input(">"))

if A == 1:
    print("enter 1 for Aes256GcmRsaOaep")
    print("enter 2 for Chacha20Poly1305RsaOaep")
    B = int(input(">"))
    main.encrypt(B)

elif A == 2:
    main.decrypt()