from flask import Blueprint, request, jsonify
import hashlib
import hmac
import os

biometric_auth_bp = Blueprint('biometric_auth', __name__)

@biometric_auth_bp.route('/biometric/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    fingerprint_data = data.get('fingerprint')

    if not fingerprint_data:
        return jsonify({'error': 'Fingerprint data is required'}), 400

    # Simulate retrieving the stored fingerprint hash for the user
    user_id = data.get('user_id')
    stored_fingerprint_hash = get_stored_fingerprint_hash(user_id)

    if not stored_fingerprint_hash:
        return jsonify({'error': 'User not found'}), 404

    # Hash the provided fingerprint data
    hashed_fingerprint = hash_fingerprint(fingerprint_data)

    # Verify the fingerprint
    if hmac.compare_digest(hashed_fingerprint, stored_fingerprint_hash):
        # Generate a secure encryption key
        encryption_key = os.urandom(32)  # 256-bit key
        return jsonify({'message': 'Authentication successful', 'encryption_key': encryption_key.hex()}), 200
    else:
        return jsonify({'error': 'Authentication failed'}), 401

def hash_fingerprint(fingerprint):
    return hashlib.sha512(fingerprint.encode()).hexdigest()

def get_stored_fingerprint_hash(user_id):
    # This function should retrieve the stored fingerprint hash from the database
    # For demonstration, we return a dummy hash
    return "dummy_stored_hash_for_user"  # Replace with actual database retrieval logic