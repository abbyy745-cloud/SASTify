import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
    baseURL: API_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

export const fetchAnalytics = async (userId = 'anonymous') => {
    try {
        const response = await api.get(`/api/analytics?user_id=${userId}`);
        return response.data;
    } catch (error) {
        console.error('Error fetching analytics:', error);
        throw error;
    }
};

export const fetchScanResults = async (scanId) => {
    try {
        const response = await api.get(`/api/scan-results/${scanId}`);
        return response.data;
    } catch (error) {
        console.error('Error fetching scan results:', error);
        throw error;
    }
};

export const performScan = async (code, language, userId = 'anonymous') => {
    try {
        const response = await api.post('/api/scan', {
            code,
            language,
            user_id: userId,
        });
        return response.data;
    } catch (error) {
        console.error('Error performing scan:', error);
        throw error;
    }
};

export default api;
