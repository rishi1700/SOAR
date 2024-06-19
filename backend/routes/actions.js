const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');

const smtpTransport = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  }
});

const sendEmail = (to, subject, text) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text,
  };

  smtpTransport.sendMail(mailOptions, (error, response) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', response);
    }
  });
};

router.post('/alert', (req, res) => {
  const { to, subject, text } = req.body;
  sendEmail(to, subject, text);
  res.send('Alert email sent');
});

module.exports = router;
