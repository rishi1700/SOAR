const express = require('express');
const router = express.Router();
const axios = require('axios');
const { sendEmail } = require('./actions');

router.post('/analyze', async (req, res) => {
  const { observable, analyzerId } = req.body;

  try {
    // Trigger Cortex analysis
    const analysisResponse = await axios.post(`${process.env.CORTEX_API_URL}/analyze`, {
      observable,
      analyzerId,
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.CORTEX_API_KEY}`
      }
    });

    const jobId = analysisResponse.data.id;

    // Poll for the result
    const pollForResult = async (jobId) => {
      let attempts = 0;
      const maxAttempts = 10;
      const pollInterval = 5000;

      while (attempts < maxAttempts) {
        attempts++;
        try {
          const reportResponse = await axios.get(`${process.env.CORTEX_API_URL}/job/${jobId}/report`, {
            headers: {
              'Authorization': `Bearer ${process.env.CORTEX_API_KEY}`
            }
          });

          if (reportResponse.data.status !== 'InProgress') {
            return reportResponse.data;
          }
        } catch (error) {
          console.error('Error fetching report:', error.response ? error.response.data : error.message);
        }

        await new Promise(resolve => setTimeout(resolve, pollInterval));
      }

      throw new Error('Max polling attempts reached');
    };

    const report = await pollForResult(jobId);

    // Check if malicious engines are detected
    if (report.report.summary.taxonomies.length > 0) {
      // Send email notification
      const subject = `Malicious Engine Detected for IP: ${observable}`;
      const text = `The analysis detected a malicious engine for the observable IP: ${observable}. Please review the details in the dashboard.`;
      sendEmail(process.env.ALERT_EMAIL, subject, text);
    }

    res.json({ jobId, report });
  } catch (error) {
    console.error('Error during analysis:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Error during analysis' });
  }
});

module.exports = router;
