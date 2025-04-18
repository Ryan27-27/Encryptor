import os
import hmac
import hashlib
import ctypes
import getpass
import pickle
from argon2.low_level import hash_secret, Type
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Google Drive API
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import io

# ---------- STEP 1: Windows Hello Authentication ----------
def authenticate_with_windows_hello():
    user32 = ctypes.windll.user32
    auth_result = user32.MessageBoxW(0, "Authenticate using Windows Hello", "Fingerprint Authentication", 1)
    return auth_result == 1

# ---------- STEP 2: Biometric Key ----------
def derive_fingerprint_key(device_id: str) -> bytes:
    if authenticate_with_windows_hello():
        fingerprint_data = "simulated_fingerprint_hash"
        return hmac.new(device_id.encode(), fingerprint_data.encode(), hashlib.sha512).digest()
    else:
        raise ValueError("Fingerprint authentication failed!")

# ---------- STEP 3: Password Key with Argon2id ----------
def derive_password_key(password: bytes) -> bytes:
    salt = os.urandom(16)
    return hash_secret(password, salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)

# ---------- STEP 4: Combine Keys ----------
def derive_final_key(password_key: bytes, fingerprint_key: bytes) -> bytes:
    return pbkdf2_hmac("sha512", password_key, fingerprint_key, 100000, dklen=64)

# ---------- STEP 5: AES-256-GCM Encryption ----------
def encrypt_data(data: str, key: bytes) -> bytes:
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

# ---------- STEP 6: Google Drive Auth ----------
def get_drive_service():
    SCOPES = ['https://www.googleapis.com/auth/drive.file']
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

# ---------- STEP 7: Upload to Drive ----------
def upload_to_drive(service, file_path: str, file_name: str) -> str:
    file_metadata = {'name': file_name}
    media = MediaFileUpload(file_path, resumable=True)
    uploaded_file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"✅ Uploaded file with ID: {uploaded_file['id']}")
    return uploaded_file['id']

# ---------- STEP 8: Download from Drive ----------
def download_from_drive(service, file_id: str, destination_path: str):
    request = service.files().get_media(fileId=file_id)
    fh = io.FileIO(destination_path, 'wb')
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        status, done = downloader.next_chunk()
        print(f"⬇️  Downloading... {int(status.progress() * 100)}%")
    print("✅ File downloaded!")

# ---------- STEP 9: Main Workflow ----------
if __name__ == "__main__":
    try:
        # Encrypt & Upload
        print("\n🔐 ENCRYPTION PHASE")
        user_password = getpass.getpass("Enter your password: ")
        device_id = "unique_device_id"
        password_key = derive_password_key(user_password.encode())
        fingerprint_key = derive_fingerprint_key(device_id)
        final_key = derive_final_key(password_key, fingerprint_key)

        plaintext = "This is top-secret sensitive data."
        encrypted = encrypt_data(plaintext, final_key)

        local_enc_path = "secure_data.bin"
        with open(local_enc_path, "wb") as f:
            f.write(encrypted)
        print("🔒 Encrypted and saved locally.")

        # Upload to Google Drive
        service = get_drive_service()
        file_id = upload_to_drive(service, local_enc_path, "EncryptedFile.bin")

        # Download & Decrypt
        print("\n🔁 SYNCHRONIZED DOWNLOAD & DECRYPTION PHASE")
        download_path = "downloaded_secure_data.bin"
        download_from_drive(service, file_id, download_path)

        print("\n🔑 Please re-authenticate to decrypt the downloaded file.")
        user_password = getpass.getpass("Re-enter your password: ")
        password_key = derive_password_key(user_password.encode())
        fingerprint_key = derive_fingerprint_key(device_id)
        final_key = derive_final_key(password_key, fingerprint_key)

        with open(download_path, "rb") as f:
            encrypted_downloaded = f.read()

        decrypted = decrypt_data(encrypted_downloaded, final_key)
        print("🔓 Decrypted Data:", decrypted)

    except ValueError as ve:
        print(f"\n🚫 Authentication Error: {ve}")
    except Exception as e:
        print(f"\n⚠️ Error: {e}")
