import React, { useState } from 'react';

const BiometricAuth = ({ onAuthenticate }) => {
    const [error, setError] = useState(null);

    const handleBiometricAuth = async () => {
        try {
            // Assuming a function `authenticateWithBiometrics` is defined to handle the biometric authentication
            const result = await authenticateWithBiometrics();
            if (result.success) {
                onAuthenticate(result.data);
            } else {
                setError('Authentication failed. Please try again.');
            }
        } catch (err) {
            setError('An error occurred during authentication.');
        }
    };

    return (
        <div className="biometric-auth">
            <h2>Biometric Authentication</h2>
            <button onClick={handleBiometricAuth}>Authenticate</button>
            {error && <p className="error">{error}</p>}
        </div>
    );
};

export default BiometricAuth;