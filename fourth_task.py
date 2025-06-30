import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SALT_SIZE = 16
IV_SIZE = 16
KEY_LENGTH = 32  # 256 bits
ITERATIONS = 100000

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(filename, password):
    with open(filename, 'rb') as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - len(data) % 16
    data += bytes([pad_len]) * pad_len

    encrypted = encryptor.update(data) + encryptor.finalize()
    output_file = filename + ".enc"

    if os.path.exists(output_file):
        print("⚠️  Encrypted file already exists. Overwrite? (y/n): ", end='')
        if input().strip().lower() != 'y':
            print("❌ Aborted.")
            return

    with open(output_file, 'wb') as f:
        f.write(salt + iv + encrypted)

    print(f"✅ File encrypted successfully as {output_file}")

def decrypt_file(filename, password):
    if not filename.endswith('.enc'):
        print("❌ Decryption target must be a .enc file.")
        return

    with open(filename, 'rb') as f:
        content = f.read()

    salt = content[:SALT_SIZE]
    iv = content[SALT_SIZE:SALT_SIZE + IV_SIZE]
    encrypted_data = content[SALT_SIZE + IV_SIZE:]
    key = derive_key(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        pad_len = decrypted[-1]
        decrypted = decrypted[:-pad_len]
    except Exception:
        print("❌ Decryption failed. Incorrect password or corrupted file.")
        return

    output_file = filename.replace('.enc', '.dec')

    if os.path.exists(output_file):
        print("⚠️  Decrypted file already exists. Overwrite? (y/n): ", end='')
        if input().strip().lower() != 'y':
            print("❌ Aborted.")
            return

    with open(output_file, 'wb') as f:
        f.write(decrypted)

    print(f"✅ File decrypted successfully as {output_file}")

def main():
    print("="*55)
    print("🔐 AES-256 FILE ENCRYPTION TOOL")
    print("="*55)
    print("1. 🔒 Encrypt a file")
    print("2. 🔓 Decrypt a file")
    print("="*55)

    choice = input("📥 Choose an option (1/2): ").strip()
    if choice not in ['1', '2']:
        print("❌ Invalid choice.")
        return

    file_path = input("📄 Enter the file path: ").strip()
    if not os.path.exists(file_path):
        print("❌ File does not exist.")
        return

    password = getpass.getpass("🔑 Enter your password: ")

    if choice == '1':
        confirm = getpass.getpass("🔁 Confirm password: ")
        if password != confirm:
            print("❌ Passwords do not match.")
            return
        encrypt_file(file_path, password)
    else:
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()

# Credits: euphoric-habromaniac