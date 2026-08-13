import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def make_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password.encode())


def encrypt_file(filename, password):
    with open(filename, "rb") as f:
        data = f.read()

    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = make_key(password, salt)
    encrypted = AESGCM(key).encrypt(nonce, data, None)

    with open(filename + ".enc", "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(encrypted)

    print("Encryption successful!")
    print("Encrypted file:", filename + ".enc")


def decrypt_file(filename, password):
    try:
        with open(filename, "rb") as f:
            salt = f.read(16)
            nonce = f.read(12)
            encrypted = f.read()

        key = make_key(password, salt)
        data = AESGCM(key).decrypt(nonce, encrypted, None)

        output = filename[:-4] + ".decrypted"

        with open(output, "wb") as f:
            f.write(data)

        print("Decryption successful!")
        print("Decrypted file:", output)
        print("Integrity verification: PASSED")

    except Exception:
        print("Decryption failed!")


print("===== FILE PROTECTION UTILITY =====")
print("1. Encrypt File")
print("2. Decrypt File")

choice = input("Enter your choice: ")

if choice == "1":
    filename = input("Enter file name: ")
    password = input("Enter password: ")
    encrypt_file(filename, password)

elif choice == "2":
    filename = input("Enter encrypted file name: ")
    password = input("Enter password: ")
    decrypt_file(filename, password)

else:
    print("Invalid choice")