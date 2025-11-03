import React, { useState } from 'react';
import './styles/App.css';
import BiometricAuth from './components/BiometricAuth';
import api from './services/api';

function App() {
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState('');

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleUpload = async () => {
        if (!file) {
            setMessage('Please select a file to upload.');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await api.uploadFile(formData);
            setMessage(response.data.message);
        } catch (error) {
            setMessage('Error uploading file: ' + error.message);
        }
    };

    return (
        <div className="App">
            <h1>Encryptor Application</h1>
            <BiometricAuth />
            <input type="file" onChange={handleFileChange} />
            <button onClick={handleUpload}>Upload File</button>
            {message && <p>{message}</p>}
        </div>
    );
}

export default App;