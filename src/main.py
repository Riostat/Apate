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
            main.encrypt_file_Chacha20Poly1305RsaOaep()
        else :
            app_ui.display_error_message("Invalid choice. Please select a valid encryption algorithm.")

    def encrypt_file_Aes256GcmRsaOaep(self):
         P = input("Enter the path of the file or directory to encrypt: ")
         if os.name == 'posix':
            if os.getcwd == '~': pass
            else: os.chdir("~")
            original_filename = Path(P).name
            K = Path(f"~/.apate/{original_filename}").expanduser()
            aes_enc = encrypt.Aes256GcmRsaOaep()
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

    def encrypt_file_Chacha20Poly1305RsaOaep(self):
        P = app_ui.get_input_path()
        if os.name == 'posix':
           if os.getcwd() == '~': pass
           else: os.chdir(os.path.expanduser("~"))
           original_filename = Path(P).name
           K = Path(f"~/.apate/{original_filename}").expanduser()
            
           if Path(P).exists() and Path(P).is_file():
               File = Path(P).read_bytes()
               new_file = encrypt.ChaCha20Poly1305RsaOaep().encrypt_data_chacha(
                   File, original_filename
                )
           try:
               if not K.exists():
                   K.mkdir(parents=True, exist_ok=True)
           except:
               logger.warning("something went wrong in main.py")
           M = Path(K).joinpath(Path(original_filename).stem)
           M.with_suffix(".veil").write_bytes(new_file)
           app_ui.display_success_message(f"File encrypted to {M.with_suffix('.veil')}")
        elif os.name == 'nt':
            pass
        else:
            return

    def decrypt(self):
        try:
            P = input("Enter the path of the .veil file to decrypt: ")
            packed_data = Path(P).read_bytes()
            if os.name == 'posix':
                magic, version, original_filename, ciphertext, nonce, algorithm_id, rsa_protected_key = format.veilcontainer.unpack()
                if algorithm_id == 1:
                    decrypt.Aes256GcmRsaOaep.decrypt_data_aes(
                        nonce=nonce,
                        ciphertext=ciphertext,
                        rsa_protected_key=rsa_protected_key, 
                        original_filename=original_filename)
                    out_path = Path(P).parent / f"decrypted_{original_filename}"
                    out_path.write_bytes(plaintext)
                    app_ui.display_success_message(f"File decrypted to {out_path}")


                elif algorithm_id == 2:
                    decrypt.ChaCha20Poly1305RsaOaep.decrypt_data_chacha(    
                        nonce=nonce,
                        ciphertext=ciphertext,
                        rsa_protected_key=rsa_protected_key, 
                        original_filename=original_filename)
                    out_path = Path(P).parent / f"decrypted_{original_filename}"
                    out_path.write_bytes(plaintext)
                    app_ui.display_success_message(f"File decrypted to {out_path}")


                elif algorithm_id == 2:
                    decrypt.ChaCha20Poly1305RsaOaep.decrypt_data_chacha(    
                        nonce=nonce,
                        ciphertext=ciphertext,
                        rsa_protected_key=rsa_protected_key, 
                        original_filename=original_filename)
                    out_path = Path(P).parent / f"decrypted_{original_filename}"
                    
                else:
                    logger.warning("wrong number entered")
                    print("pls enter a valid number")

            elif os.name == 'nt':
                pass

        except OSError:
            app.ui.display_error_message("file not found or os error")

        except ValueError:
            app.ui.display_error_message("data unpacking failed or file is corrupted")



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