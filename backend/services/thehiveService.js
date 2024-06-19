// backend/services/thehiveService.js
const axios = require('axios');

const THEHIVE_API_URL = process.env.THEHIVE_API_URL;
const THEHIVE_API_KEY = process.env.THEHIVE_API_KEY;

const thehiveApi = axios.create({
  baseURL: THEHIVE_API_URL,
  headers: {
    'Authorization': `Bearer ${THEHIVE_API_KEY}`,
    'Content-Type': 'application/json',
  },
});

const getCases = async () => {
  try {
    const response = await thehiveApi.post('/case/_search', { query: [] });  // Ensure this matches TheHive API specification
    return response.data;
  } catch (error) {
    console.error('Error fetching cases from TheHive:', error.response ? error.response.data : error.message);
    throw error;
  }
};

module.exports = { getCases };
