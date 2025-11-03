import axios from 'axios';

const API_URL = 'http://localhost:5000/api'; // Adjust the URL as needed

export const encryptFile = async (file, encryptionKey) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('encryptionKey', encryptionKey);

    try {
        const response = await axios.post(`${API_URL}/encrypt`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
            },
        });
        return response.data;
    } catch (error) {
        throw new Error('Error encrypting file: ' + error.message);
    }
};

export const decryptFile = async (file, decryptionKey) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('decryptionKey', decryptionKey);

    try {
        const response = await axios.post(`${API_URL}/decrypt`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
            },
        });
        return response.data;
    } catch (error) {
        throw new Error('Error decrypting file: ' + error.message);
    }
};