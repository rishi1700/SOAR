// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const { Server } = require('socket.io');
const https = require('https');
const nodemailer = require('nodemailer');
const axios = require('axios');

dotenv.config();

const authRoutes = require('./routes/auth');
const elasticRoutes = require('./routes/elasticsearch');
const thehiveRoutes = require('./routes/thehive');
const mispRoutes = require('./routes/misp');
const cortexRoutes = require('./routes/cortex');
const actionsRoutes = require('./routes/actions');
const rulesRoutes = require('./routes/rules'); // Import rules route

const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

app.use('/auth', authRoutes);
app.use('/api', elasticRoutes);
app.use('/api/thehive', thehiveRoutes);
app.use('/api/misp', mispRoutes);
app.use('/api/cortex', cortexRoutes);
app.use('/api/actions', actionsRoutes);
app.use('/api/rules', rulesRoutes); // Use rules route

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

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

app.post('/api/testEmail', (req, res) => {
  const { to, subject, text } = req.body;
  sendEmail(to, subject, text);
  res.send('Test email sent');
});

io.on('connection', (socket) => {
  console.log('New WebSocket connection');

  setInterval(async () => {
    try {
      const elasticResponse = await axios.get(`${process.env.ELASTICSEARCH_HOST}/snort-logs-*/_search`, {
        auth: {
          username: process.env.ELASTICSEARCH_USERNAME,
          password: process.env.ELASTICSEARCH_PASSWORD,
        },
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
        params: {
          size: 1000,
        },
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const hits = elasticResponse.data.hits.hits.sort((a, b) => new Date(b._source['@timestamp']) - new Date(a._source['@timestamp']));

      socket.emit('dataUpdate', hits.slice(0, 5));
    } catch (error) {
      console.error('Error fetching data from Elasticsearch:', error.response ? error.response.data : error.message);
    }
  }, 5000);
});
