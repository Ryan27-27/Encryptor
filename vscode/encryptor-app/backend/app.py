from flask import Flask, request, jsonify
from encryption.encryptor import Encryptor
from biometrics.biometric_auth import BiometricAuth
from cloud.cloud_integration import CloudIntegration
from session.session_manager import SessionManager

app = Flask(__name__)

# Initialize components
encryptor = Encryptor()
biometric_auth = BiometricAuth()
cloud_integration = CloudIntegration()
session_manager = SessionManager()

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    user_id = biometric_auth.authenticate(data['fingerprint'])
    if user_id:
        session_manager.create_session(user_id)
        return jsonify({"message": "Authenticated", "user_id": user_id}), 200
    return jsonify({"message": "Authentication failed"}), 401

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['file']
    encrypted_file = encryptor.encrypt(file)
    cloud_integration.upload(encrypted_file)
    return jsonify({"message": "File uploaded successfully"}), 200

@app.route('/api/session', methods=['GET'])
def get_session():
    user_id = session_manager.get_active_session()
    if user_id:
        return jsonify({"user_id": user_id}), 200
    return jsonify({"message": "No active session"}), 401

if __name__ == '__main__':
    app.run(debug=True)