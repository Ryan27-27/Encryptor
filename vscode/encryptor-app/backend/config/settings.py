# filepath: encryptor-app/backend/config/settings.py

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_default_secret_key'
    API_KEY_CLOUD_SERVICE = os.environ.get('API_KEY_CLOUD_SERVICE') or 'your_default_api_key'
    ENCRYPTION_ALGORITHM = 'AES-256-GCM-SIV'
    ENCRYPTION_KEY_SIZE = 32  # 32 bytes for AES-256
    SESSION_TIMEOUT = 30  # in minutes
    FILE_COMPRESSION_METHOD = 'zlib'  # or 'brotli'
    BIOMETRIC_AUTH_ENABLED = True  # Set to False to disable biometric authentication

    @staticmethod
    def init_app(app):
        pass  # Additional initialization can be done here if needed