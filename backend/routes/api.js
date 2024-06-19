// backend/routes/api.js
const express = require('express');
const router = express.Router();
const { getCases } = require('../services/thehiveService');

router.get('/thehive/cases', async (req, res) => {
  try {
    const cases = await getCases();
    res.json(cases);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching cases from TheHive' });
  }
});

module.exports = router;
