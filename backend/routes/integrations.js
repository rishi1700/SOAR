const express = require('express');
const axios = require('axios');
const router = express.Router();

// Configuration - replace with your actual credentials and URLs
const THEHIVE_URL = 'http://192.168.18.34:9000/api';
const THEHIVE_API_KEY = 'cpynfPzwsGkIZEOPYjlnV2jyiU+acSfC';
const CORTEX_URL = 'http://192.168.18.34:9000/api';
const CORTEX_API_KEY = 'Z2q2oZRz29s/VXT9JvWA3WV5cLJ0eXer';
const MISP_URL = 'https://192.168.18.34';
const MISP_API_KEY = 'RrTmLH0RPj1hIlKyZd9UXn9uCY5bTpMSRtZju3XW';
const VIRUSTOTAL_API_KEY = '87a00ae3791172d9d34902b2e2eba48d7829959099ef0251642ba9e4819e303a';

// Helper function to set headers
const setHeaders = (apiKey) => ({
  headers: {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  },
});

// Fetch alerts from TheHive
router.get('/thehive/alerts', async (req, res) => {
  try {
    const response = await axios.get(`${THEHIVE_URL}/alert`, setHeaders(THEHIVE_API_KEY));
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching alerts from TheHive:', error);
    res.status(500).json({ message: 'Error fetching alerts from TheHive' });
  }
});

// Fetch cases from TheHive
router.get('/thehive/cases', async (req, res) => {
  try {
    const response = await axios.get(`${THEHIVE_URL}/case`, setHeaders(THEHIVE_API_KEY));
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching cases from TheHive:', error);
    res.status(500).json({ message: 'Error fetching cases from TheHive' });
  }
});

// Analyze an IoC using Cortex
router.post('/cortex/analyze', async (req, res) => {
  const { data, analyzer } = req.body;
  try {
    const response = await axios.post(`${CORTEX_URL}/job`, { data, analyzer }, setHeaders(CORTEX_API_KEY));
    res.json(response.data);
  } catch (error) {
    console.error('Error analyzing IoC with Cortex:', error);
    res.status(500).json({ message: 'Error analyzing IoC with Cortex' });
  }
});

// Fetch analysis from MISP
router.get('/misp/events', async (req, res) => {
  try {
    const response = await axios.get(`${MISP_URL}/events`, setHeaders(MISP_API_KEY));
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching events from MISP:', error);
    res.status(500).json({ message: 'Error fetching events from MISP' });
  }
});

// Fetch analysis from VirusTotal
router.post('/virustotal/analyze', async (req, res) => {
  const { url } = req.body;
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${url}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
      },
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error analyzing URL with VirusTotal:', error);
    res.status(500).json({ message: 'Error analyzing URL with VirusTotal' });
  }
});

module.exports = router;
