// routes/virustotal.js
const express = require('express');
const axios = require('axios');
const router = express.Router();

router.get('/scan/:hash', async (req, res) => {
  const hash = req.params.hash;
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY,
      },
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching data from VirusTotal:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
