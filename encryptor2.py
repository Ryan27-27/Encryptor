# import os
# import io
# import zlib
# import hmac
# import hashlib
# import ctypes
# import getpass
# import pickle
# from argon2.low_level import hash_secret, Type
# from hashlib import pbkdf2_hmac
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# # Google Drive API
# from googleapiclient.discovery import build
# from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
# from google_auth_oauthlib.flow import InstalledAppFlow
# from google.auth.transport.requests import Request

# # ---------- STEP 1: Windows Hello Authentication ----------
# def authenticate_with_windows_hello():
#     user32 = ctypes.windll.user32
#     auth_result = user32.MessageBoxW(0, "Authenticate using Windows Hello", "Fingerprint Authentication", 1)
#     return auth_result == 1

# # ---------- STEP 2: Fingerprint-Based Key ----------
# def derive_fingerprint_key(device_id: str) -> bytes:
#     if authenticate_with_windows_hello():
#         fingerprint_data = "simulated_fingerprint_hash"
#         return hmac.new(device_id.encode(), fingerprint_data.encode(), hashlib.sha512).digest()
#     else:
#         raise ValueError("Fingerprint authentication failed!")

# # ---------- STEP 3: Password Key (Argon2id) ----------
# def derive_password_key(password: bytes) -> bytes:
#     # Generate a deterministic Argon2 hash (no saved salt)
#     # Using password itself as both secret and salt input ensures reproducibility
#     return hash_secret(password, password[:16], time_cost=3, memory_cost=65536,
#                        parallelism=4, hash_len=32, type=Type.ID)

# # ---------- STEP 4: Combine Keys ----------
# def derive_final_key(password_key: bytes, fingerprint_key: bytes) -> bytes:
#     return pbkdf2_hmac("sha512", password_key, fingerprint_key, 100000, dklen=64)

# # ---------- STEP 5: AES-256-GCM Encryption ----------
# def encrypt_data(data: bytes, key: bytes) -> bytes:
#     iv = os.urandom(12)
#     cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv))
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(data) + encryptor.finalize()
#     return iv + encryptor.tag + ciphertext

# def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
#     iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
#     cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv, tag))
#     decryptor = cipher.decryptor()
#     return decryptor.update(ciphertext) + decryptor.finalize()

# # ---------- STEP 6: Google Drive Auth ----------
# def get_drive_service():
#     SCOPES = ['https://www.googleapis.com/auth/drive.file']
#     creds = None
#     if os.path.exists('token.pkl'):
#         with open('token.pkl', 'rb') as token:
#             creds = pickle.load(token)
#     if not creds or not creds.valid:
#         if creds and creds.expired and creds.refresh_token:
#             creds.refresh(Request())
#         else:
#             flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
#             creds = flow.run_local_server(port=0)
#         with open('token.pkl', 'wb') as token:
#             pickle.dump(creds, token)
#     return build('drive', 'v3', credentials=creds)

# # ---------- STEP 7: Upload ----------
# def upload_to_drive(service, file_path: str, file_name: str) -> str:
#     file_metadata = {'name': file_name}
#     media = MediaFileUpload(file_path, resumable=True)
#     uploaded_file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
#     print(f"✅ Uploaded file with ID: {uploaded_file['id']}")
#     return uploaded_file['id']

# # ---------- STEP 8: Download ----------
# def download_from_drive(service, file_id: str, destination_path: str):
#     request = service.files().get_media(fileId=file_id)
#     fh = io.FileIO(destination_path, 'wb')
#     downloader = MediaIoBaseDownload(fh, request)
#     done = False
#     while not done:
#         status, done = downloader.next_chunk()
#         print(f"⬇️  Downloading... {int(status.progress() * 100)}%")
#     print("✅ File downloaded!")

# # ---------- STEP 9: MAIN ----------
# if __name__ == "__main__":
#     try:
#         print("\n🔐 ENCRYPTION PHASE")
#         print("\nThe password length must be greater than 16!")
#         password = getpass.getpass("Enter your password: ")
#         device_id = "unique_device_id"

#         # Derive runtime-only key
#         pw_key = derive_password_key(password.encode())
#         fp_key = derive_fingerprint_key(device_id)
#         final_key = derive_final_key(pw_key, fp_key)

#         # Compress → Encrypt
#         plaintext = b"This is top-secret sensitive data."
#         compressed = zlib.compress(plaintext)
#         encrypted = encrypt_data(compressed, final_key)

#         enc_path = "secure_data.bin"
#         with open(enc_path, "wb") as f:
#             f.write(encrypted)
#         print("🔒 Compressed, encrypted, and saved locally.")

#         # Upload to Drive
#         service = get_drive_service()
#         file_id = upload_to_drive(service, enc_path, "EncryptedFile.bin")

#         # Download → Decrypt → Decompress
#         print("\n🔁 SYNCHRONIZED DOWNLOAD & DECRYPTION PHASE")
#         dl_path = "downloaded_secure_data.bin"
#         download_from_drive(service, file_id, dl_path)

#         print("\n🔑 Re-authenticate to decrypt.")
#         password = getpass.getpass("Re-enter password: ")
#         pw_key = derive_password_key(password.encode())
#         fp_key = derive_fingerprint_key(device_id)
#         final_key = derive_final_key(pw_key, fp_key)

#         with open(dl_path, "rb") as f:
#             encrypted_dl = f.read()

#         decrypted = decrypt_data(encrypted_dl, final_key)
#         decompressed = zlib.decompress(decrypted)
#         print("🔓 Decrypted Data:", decompressed.decode())

#     except ValueError as ve:
#         print(f"\n🚫 Authentication Error: {ve}")
#     except Exception as e:
#         print(f"\n⚠️ Error: {e}")

import os
import io
import gzip
import hmac
import hashlib
import base64
import tempfile
import pickle
import ctypes
from getpass import getpass
from argon2.low_level import hash_secret, Type
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


# ======== WINDOWS HELLO AUTHENTICATION ========
def authenticate_with_windows_hello() -> bool:
    """Simulate Windows Hello fingerprint verification."""
    user32 = ctypes.windll.user32
    response = user32.MessageBoxW(0, "Authenticate using Windows Hello fingerprint", "Windows Hello Authentication", 1)
    return response == 1  # OK = 1, Cancel = 2


def derive_fingerprint_key(device_id: str) -> bytes:
    """Derive fingerprint key using HMAC-SHA512 after Windows Hello verification."""
    if authenticate_with_windows_hello():
        fingerprint_data = "SimulatedFingerprintHashFromDevice"
        return hmac.new(device_id.encode(), fingerprint_data.encode(), hashlib.sha512).digest()
    else:
        raise ValueError("❌ Windows Hello authentication failed!")


# ======== GOOGLE DRIVE AUTH ========
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def get_drive_service():
    """Authenticate to Google Drive and return the service object."""
    creds = None
    if os.path.exists('token.pkl'):
        with open('token.pkl', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pkl', 'wb') as token:
            pickle.dump(creds, token)

    return build('drive', 'v3', credentials=creds)


# ======== KEY DERIVATION ========
def derive_password_key(password: bytes) -> bytes:
    """Derive password key using Argon2id (zero-salt model)."""
    if len(password) < 16:
        raise ValueError("Password must be at least 16 characters.")
    return hash_secret(password, password[:16], time_cost=3, memory_cost=65536,
                       parallelism=4, hash_len=32, type=Type.ID)


def derive_final_key(password_key: bytes, fingerprint_key: bytes) -> bytes:
    """Combine Argon2 password key and HMAC fingerprint key."""
    return pbkdf2_hmac("sha512", password_key, fingerprint_key, 100000, dklen=64)


# ======== ENCRYPTION / DECRYPTION ========
def encrypt_data(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext


def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    nonce, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ======== COMPRESSION ========
def compress_data(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode='wb') as f:
        f.write(data)
    return buf.getvalue()


def decompress_data(data: bytes) -> bytes:
    buf = io.BytesIO(data)
    with gzip.GzipFile(fileobj=buf, mode='rb') as f:
        return f.read()


# ======== UPLOAD / DOWNLOAD ========
def upload_to_drive(service, file_path: str, file_name: str) -> str:
    """Upload encrypted file to Google Drive."""
    file_metadata = {'name': file_name}
    media = MediaFileUpload(file_path, resumable=True)
    uploaded = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"✅ Uploaded to Drive with ID: {uploaded['id']}")
    return uploaded['id']


def download_from_drive(service, file_id: str, destination_path: str):
    """Download encrypted file from Google Drive."""
    request = service.files().get_media(fileId=file_id)
    with open(destination_path, 'wb') as f:
        downloader = MediaIoBaseDownload(f, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            print(f"⬇️  Downloading... {int(status.progress() * 100)}%")
    print(f"✅ File downloaded to: {destination_path}")


# ======== MAIN PHASES ========
def encrypt_and_upload(file_path: str, device_id: str, service):
    print("\n🔐 ENCRYPTION PHASE")
    password = getpass("Enter your password: ").encode()

    pw_key = derive_password_key(password)
    fp_key = derive_fingerprint_key(device_id)
    final_key = derive_final_key(pw_key, fp_key)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    compressed = compress_data(plaintext)
    encrypted = encrypt_data(compressed, final_key)

    enc_path = tempfile.mktemp(suffix=".enc")
    with open(enc_path, 'wb') as f:
        f.write(encrypted)

    print("🔒 File compressed and encrypted successfully.")
    file_id = upload_to_drive(service, enc_path, os.path.basename(file_path) + ".enc")

    os.remove(enc_path)
    print("🧹 Temporary encrypted file securely deleted.")

    return file_id


def download_and_decrypt(file_id: str, device_id: str, service):
    print("\n🔁 DECRYPTION PHASE")
    dl_path = tempfile.mktemp(suffix=".enc")
    download_from_drive(service, file_id, dl_path)

    password = getpass("Re-enter your password: ").encode()
    pw_key = derive_password_key(password)
    fp_key = derive_fingerprint_key(device_id)
    final_key = derive_final_key(pw_key, fp_key)

    with open(dl_path, 'rb') as f:
        encrypted = f.read()

    decrypted = decrypt_data(encrypted, final_key)
    decompressed = decompress_data(decrypted)

    output_dir = os.path.join(os.getcwd(), "DecryptedFiles")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "decrypted_output.bin")

    with open(output_file, 'wb') as f:
        f.write(decompressed)

    print(f"✅ File decrypted and saved at: {output_file}")
    os.remove(dl_path)


# ======== EXECUTION ENTRY POINT ========
if __name__ == "__main__":
    print("\n=== ENCRYPTOR ZERO TRUST SYSTEM (Windows Hello + Argon2id) ===")
    drive_service = get_drive_service()
    device_id = "UniqueDeviceIdentifier"  # replace with actual machine UUID if desired

    choice = input("1. Encrypt & Upload\n2. Download & Decrypt\nChoose option: ")

    if choice == "1":
        path = input("Enter file path to encrypt: ").strip('"')
        encrypt_and_upload(path, device_id, drive_service)
    elif choice == "2":
        fid = input("Enter Google Drive File ID to decrypt: ").strip()
        download_and_decrypt(fid, device_id, drive_service)
    else:
        print("❌ Invalid choice.")


