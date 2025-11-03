import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api'; // Adjust the base URL as needed

const api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// User authentication
export const login = async (credentials) => {
    return await api.post('/auth/login', credentials);
};

export const logout = async () => {
    return await api.post('/auth/logout');
};

// File upload
export const uploadFile = async (fileData) => {
    return await api.post('/files/upload', fileData, {
        headers: {
            'Content-Type': 'multipart/form-data',
        },
    });
};

// Encryption
export const encryptFile = async (fileData) => {
    return await api.post('/encrypt', fileData);
};

// Other API calls can be added here

export default api;