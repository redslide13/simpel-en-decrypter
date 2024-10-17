from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def aes_decrypt(input_file, output_file, key):
    with open(input_file, 'rb') as f_input:
        iv = f_input.read(16)
        ciphertext = f_input.read()


    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


    decryptor = cipher.decryptor()
    decrypted_padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()


    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_plaintext) + unpadder.finalize()

    with open(output_file, 'wb') as f_output:
        f_output.write(plaintext)

if __name__ == "__main__":
    key = b'Your Key'
    input_file = 'YourEncryptetFile.exe'
    output_file = 'YourFileDecrypted.exe'
    aes_decrypt(input_file, output_file, key)
    print("Sucess!!!")
