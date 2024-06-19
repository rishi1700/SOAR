const express = require('express');
const axios = require('axios');
const router = express.Router();
const https = require('https'); 

router.post('/events', async (req, res) => {
  try {
    const response = await axios.post(
      `${process.env.MISP_URL}/attributes/restSearch`,
      {},
      {
        headers: {
          Authorization: process.env.MISP_API_KEY,
          'Content-Type': 'application/json',
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      }
    );
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching data from MISP:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
