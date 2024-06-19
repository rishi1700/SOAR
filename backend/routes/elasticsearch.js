const express = require('express');
const axios = require('axios');
const router = express.Router();
const { io } = require('../server'); // Import the socket instance

// Elasticsearch credentials and URL
const ES_URL = process.env.ELASTICSEARCH_HOST;
const ES_USERNAME = process.env.ELASTICSEARCH_USERNAME;
const ES_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;

// Fetch Elasticsearch data and emit events
router.get('/', async (req, res) => {
  try {
    const response = await axios.get(`${ES_URL}/snort-logs-*/_search`, {
      auth: {
        username: ES_USERNAME,
        password: ES_PASSWORD,
      },
    });

    const data = response.data.hits.hits.map(hit => hit._source);
    io.emit('dataUpdated', data); // Emit the data update event

    res.json(data);
  } catch (error) {
    console.error('Error fetching data from Elasticsearch:', error);
    res.status(500).json({ message: 'Error fetching data from Elasticsearch' });
  }
});

module.exports = router;
