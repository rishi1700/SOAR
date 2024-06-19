const express = require('express');
const axios = require('axios');
const router = express.Router();

router.get('/cases', async (req, res) => {
  try {
    const response = await axios.post(
      `${process.env.THEHIVE_URL}/api/v1/query`,
      { query: [{ _name: 'listCase' }] },
      {
        headers: {
          Authorization: `Bearer ${process.env.THEHIVE_API_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching cases from TheHive:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
