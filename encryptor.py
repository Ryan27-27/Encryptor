# import os
# import hmac
# import hashlib
# import ctypes
# from argon2.low_level import hash_secret, Type
# from hashlib import pbkdf2_hmac
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# # Step 1: Authenticate user with Windows Hello
# def authenticate_with_windows_hello():
#     """Authenticate user using Windows Hello Fingerprint."""
#     user32 = ctypes.windll.user32
#     auth_result = user32.MessageBoxW(0, "Authenticate using Windows Hello", "Fingerprint Authentication", 1)
#     return auth_result == 1  # Returns True if authenticated

# # Step 2: Generate a stable biometric-based key using HMAC-SHA512
# def derive_fingerprint_key(device_id: str) -> bytes:
#     """Generates a fingerprint-based cryptographic key (Simulated with Windows Hello)."""
#     if authenticate_with_windows_hello():
#         fingerprint_data = "simulated_fingerprint_hash"  # Simulated since Windows Hello doesn't expose fingerprint data
#         return hmac.new(device_id.encode(), fingerprint_data.encode(), hashlib.sha512).digest()
#     else:
#         raise ValueError("Fingerprint authentication failed!")

# # Step 3: Derive a cryptographic key from the password using Argon2id
# def derive_password_key(password: bytes) -> bytes:
#     """Derives a strong key from a password using Argon2id."""
#     salt = os.urandom(16)  # Secure random salt
#     return hash_secret(password, salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)

# # Step 4: Combine password key and fingerprint key using PBKDF2-HMAC-SHA512
# def derive_final_key(password_key: bytes, fingerprint_key: bytes) -> bytes:
#     """Combines password and fingerprint keys securely using PBKDF2-HMAC-SHA512."""
#     return pbkdf2_hmac("sha512", password_key, fingerprint_key, 100000, dklen=64)

# # Step 5: Encrypt data using AES-256-GCM-SIV
# def encrypt_data(data: str, key: bytes) -> bytes:
#     """Encrypts data using AES-256-GCM-SIV mode."""
#     iv = os.urandom(12)  # Generate a secure random IV (Nonce)
#     cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv))  # Use first 256 bits
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
#     return iv + encryptor.tag + ciphertext  # Store IV + Tag + Ciphertext

# # Step 6: Decrypt data using AES-256-GCM-SIV
# def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
#     """Decrypts data using AES-256-GCM-SIV mode."""
#     iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
#     cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv, tag))
#     decryptor = cipher.decryptor()
#     return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# # Step 7: Run encryption and decryption process
# if __name__ == "__main__":
#     try:
#         user_password = b"strong_user_password"  # Convert password to bytes
#         device_id = "unique_device_id"

#         # Derive cryptographic keys
#         password_key = derive_password_key(user_password)
#         fingerprint_key = derive_fingerprint_key(device_id)
#         final_key = derive_final_key(password_key, fingerprint_key)

#         # Encrypt and Decrypt Example
#         plaintext = "We are the new world"
#         encrypted = encrypt_data(plaintext, final_key)
       

#         print("\n🔐 *Encryption & Decryption Completed Successfully!*")
#         print("🔒 Encrypted Data (Hex):", encrypted.hex())
#         final_key = derive_final_key(password_key, fingerprint_key)
#         decrypted = decrypt_data(encrypted, final_key)
#         print("🔓 Decrypted Data:", decrypted)

#     except ValueError as e:
#         print(f"\n🚫 Authentication Failed: {e}")


import os
import hmac
import hashlib
import ctypes
from argon2.low_level import hash_secret, Type
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import getpass

# Step 1: Authenticate user with Windows Hello
def authenticate_with_windows_hello():
    """Authenticate user using Windows Hello Fingerprint."""
    user32 = ctypes.windll.user32
    auth_result = user32.MessageBoxW(0, "Authenticate using Windows Hello", "Fingerprint Authentication", 1)
    return auth_result == 1  # Returns True if authenticated

# Step 2: Generate a stable biometric-based key using HMAC-SHA512
def derive_fingerprint_key(device_id: str) -> bytes:
    """Generates a fingerprint-based cryptographic key (Simulated with Windows Hello)."""
    if authenticate_with_windows_hello():
        fingerprint_data = "simulated_fingerprint_hash"  # Simulated since Windows Hello doesn't expose fingerprint data
        return hmac.new(device_id.encode(), fingerprint_data.encode(), hashlib.sha512).digest()
    else:
        raise ValueError("Fingerprint authentication failed!")

# Step 3: Derive a cryptographic key from the password using Argon2id
def derive_password_key(password: bytes) -> bytes:
    """Derives a strong key from a password using Argon2id."""
    salt = os.urandom(16)  # Secure random salt
    return hash_secret(password, salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)

# Step 4: Combine password key and fingerprint key using PBKDF2-HMAC-SHA512
def derive_final_key(password_key: bytes, fingerprint_key: bytes) -> bytes:
    """Combines password and fingerprint keys securely using PBKDF2-HMAC-SHA512."""
    return pbkdf2_hmac("sha512", password_key, fingerprint_key, 100000, dklen=64)

# Step 5: Encrypt data using AES-256-GCM-SIV
def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypts data using AES-256-GCM-SIV mode."""
    iv = os.urandom(12)  # Generate a secure random IV (Nonce)
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv))  # Use first 256 bits
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext  # Store IV + Tag + Ciphertext

# Step 6: Decrypt data using AES-256-GCM-SIV
def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts data using AES-256-GCM-SIV mode."""
    iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# Step 7: Run encryption and decryption process
if __name__ == "__main__":
    try:
        # Step 7a: Ask for password and authenticate fingerprint
        user_password = getpass.getpass("Enter your password: ")  # Secure password input
        device_id = "unique_device_id"  # Use a unique identifier for your device

        # Step 7b: Derive cryptographic keys
        password_key = derive_password_key(user_password.encode())
        fingerprint_key = derive_fingerprint_key(device_id)
        final_key = derive_final_key(password_key, fingerprint_key)

        # Step 7c: Encrypt data
        plaintext = "Sensitive Data"
        encrypted = encrypt_data(plaintext, final_key)
        print("\n🔒 Encrypted Data (Hex):", encrypted.hex())

        # Step 7d: Decrypt data
        print("\n🔑 Please authenticate again to decrypt.")
        # Ask for password and authenticate fingerprint during decryption
        decryption_password = getpass.getpass("Re-enter your password for decryption: ")
        password_key = derive_password_key(decryption_password.encode())  # Derive password key for decryption
        fingerprint_key = derive_fingerprint_key(device_id)  # Re-authenticate fingerprint
        final_key = derive_final_key(password_key, fingerprint_key)

        decrypted = decrypt_data(encrypted, final_key)
        print("🔓 Decrypted Data:", decrypted)

    except ValueError as e:
        print(f"\n🚫 Authentication Failed: {e}")

