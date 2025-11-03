# Encryptor Application

## Overview
The Encryptor application is a secure file encryption and management tool that integrates biometric authentication, file compression, and cloud storage solutions. It consists of a Flask backend for handling encryption and cloud interactions, and a React frontend for user interaction.

## Project Structure
```
encryptor-app
├── backend
│   ├── app.py
│   ├── requirements.txt
│   ├── config
│   │   └── settings.py
│   ├── encryption
│   │   ├── __init__.py
│   │   └── encryptor.py
│   ├── cloud
│   │   ├── __init__.py
│   │   └── cloud_integration.py
│   ├── biometrics
│   │   ├── __init__.py
│   │   └── biometric_auth.py
│   ├── compression
│   │   ├── __init__.py
│   │   └── file_compression.py
│   ├── session
│   │   ├── __init__.py
│   │   └── session_manager.py
│   └── tests
│       ├── __init__.py
│       └── test_app.py
├── frontend
│   ├── public
│   │   └── index.html
│   ├── src
│   │   ├── App.js
│   │   ├── index.js
│   │   ├── components
│   │   │   └── BiometricAuth.js
│   │   ├── services
│   │   │   ├── api.js
│   │   │   └── encryptionService.js
│   │   └── styles
│   │       └── App.css
│   ├── package.json
│   └── vite.config.js
├── README.md
└── .gitignore
```

## Setup Instructions

### Backend
1. Navigate to the `backend` directory.
2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```
3. Configure your settings in `config/settings.py` (API keys, encryption settings, etc.).
4. Run the Flask application:
   ```
   python app.py
   ```

### Frontend
1. Navigate to the `frontend` directory.
2. Install the required Node.js packages:
   ```
   npm install
   ```
3. Start the React application:
   ```
   npm run dev
   ```

## Features
- **File Encryption**: Securely encrypt files using AES-256-GCM-SIV.
- **Biometric Authentication**: Utilize fingerprint authentication for enhanced security.
- **Cloud Integration**: Upload encrypted files to cloud services like Google Drive and Dropbox.
- **File Compression**: Compress files before uploading to save space.
- **Session Management**: Ensure secure user sessions with single active session enforcement.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
