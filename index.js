const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());
const API_KEY = process.env.PROSPEO_API_KEY;

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'LeadHunt API running' });
});

// Account info
app.get('/api/account', async (req, res) => {
  try {
    const response = await fetch('https://api.prospeo.io/account-information', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-KEY': API_KEY }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Search
app.post('/api/search', async (req, res) => {
  try {
    const response = await fetch('https://api.prospeo.io/search-person', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-KEY': API_KEY },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Email finder
app.post('/api/email-finder', async (req, res) => {
  try {
    const response = await fetch('https://api.prospeo.io/email-finder', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-KEY': API_KEY },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Enrich person (reveal email + phone)
app.post('/api/enrich', async (req, res) => {
  try {
    const response = await fetch('https://api.prospeo.io/enrich-person', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-KEY': API_KEY },
      body: JSON.stringify({ data: req.body })
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
