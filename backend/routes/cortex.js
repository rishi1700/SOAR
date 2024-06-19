const express = require('express');
const axios = require('axios');
const nodemailer = require('nodemailer');
const router = express.Router();

const CORTEX_URL = process.env.CORTEX_URL;
const CORTEX_API_KEY = process.env.CORTEX_API_KEY;

const smtpTransport = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendAlertEmail = (ip, analyzerName, details) => {
  const emailBody = `
    A malicious activity has been detected on IP ${ip} using analyzer ${analyzerName}.

    Analysis Details:
    ${details.map(detail => {
      const typeTag = detail.tags ? detail.tags.find(tag => tag.startsWith('type:')) : 'N/A';
      const tlpTag = detail.tags ? detail.tags.find(tag => tag.startsWith('tlp:')) : 'N/A';
      return `
        Date: ${detail.date}
        Info: ${detail.info}
        Type: ${typeTag || 'N/A'}
        TLP: ${tlpTag || 'N/A'}
      `;
    }).join('\n')}

    Recommended Actions:
    1. Verify the reported malicious activity.
    2. Check the IP ${ip} in your network logs for any suspicious activities.
    3. Follow your organization's incident response procedures to mitigate the threat.
    4. Consider blocking the IP ${ip} if confirmed malicious.

    For more information, please refer to the detailed report in the Cortex dashboard.

    Regards,
    Your Security Team
  `;
  
  const emailOptions = {
    from: process.env.EMAIL_USER,
    to: 'prasadrishi170@gmail.com',  // replace with the actual email of the analyst
    subject: `Malicious Activity Detected on IP ${ip}`,
    text: emailBody.trim(),
  };

  smtpTransport.sendMail(emailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

// Cache to keep track of processed results
const processedIPs = new Set();

// List Analyzers
router.get('/analyzers', async (req, res) => {
  try {
    const response = await axios.get(`${CORTEX_URL}/api/analyzer`, {
      headers: {
        'Authorization': `Bearer ${CORTEX_API_KEY}`
      }
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching analyzers:', error);
    res.status(500).json({ error: error.message });
  }
});

// Run Analyzer
router.post('/analyze', async (req, res) => {
  const { observable, analyzerId } = req.body;
  try {
    const response = await axios.post(
      `${CORTEX_URL}/api/analyzer/${analyzerId}/run`,
      {
        data: observable,
        dataType: 'ip',
        tlp: 0,
        message: 'Running analysis',
        parameters: {}
      },
      {
        headers: {
          'Authorization': `Bearer ${CORTEX_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const jobId = response.data.id;
    const report = await pollForResult(jobId);

    // Check if malicious engines are greater than or equal to 1
    if (report.report.summary.taxonomies.length >= 1) {
      // Fetch the analyzer name
      const analyzerResponse = await axios.get(`${CORTEX_URL}/api/analyzer/${analyzerId}`, {
        headers: {
          'Authorization': `Bearer ${CORTEX_API_KEY}`
        }
      });
      const analyzerName = analyzerResponse.data.name;

      // Only send email if the IP is not already processed
      if (!processedIPs.has(observable)) {
        sendAlertEmail(observable, analyzerName, report.report.full.results[0].result);
        processedIPs.add(observable);
      }
    }

    res.json(report);  // Ensure response is sent once
  } catch (error) {
    console.error(`Error running analyzer ${analyzerId} on ${observable}:`, error);
    if (!res.headersSent) {
      res.status(500).json({ error: error.message });
    }
  }
});

// Poll Job Report
router.get('/job/:jobId/report', async (req, res) => {
  const { jobId } = req.params;
  try {
    const response = await axios.get(`${CORTEX_URL}/api/job/${jobId}/waitreport?atMost=1minute`, {
      headers: {
        'Authorization': `Bearer ${CORTEX_API_KEY}`
      }
    });
    res.json(response.data);
  } catch (error) {
    console.error(`Error fetching report for job ${jobId}:`, error);
    res.status(500).json({ error: error.message });
  }
});

const pollForResult = async (jobId) => {
  const maxRetries = 10;
  let attempts = 0;
  while (attempts < maxRetries) {
    try {
      const response = await axios.get(`${CORTEX_URL}/api/job/${jobId}/waitreport?atMost=1minute`, {
        headers: {
          'Authorization': `Bearer ${CORTEX_API_KEY}`
        }
      });
      if (response.data.status !== 'InProgress') {
        return response.data;
      }
      await new Promise(resolve => setTimeout(resolve, 5000));
      attempts++;
    } catch (error) {
      console.error('Error polling for result:', error);
      throw error;
    }
  }
  throw new Error('Max polling attempts reached');
};

module.exports = router;
