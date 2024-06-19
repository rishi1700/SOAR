// routes/incident.js
const express = require('express');
const router = express.Router();
const Incident = require('../models/Incident');

// Fetch incident timeline
router.get('/timeline', async (req, res) => {
  try {
    const incidents = await Incident.find().sort({ timestamp: -1 });
    res.json(incidents);
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;
