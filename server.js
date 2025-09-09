const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Deze regel hier!

// In-memory storage (tijdelijk)
let cards = [];

// Create disposable card
app.post('/api/cards', (req, res) => {
  const { name, email, phone, company, title } = req.body;
  
  if (!name) {
    return res.status(400).json({ error: 'Name is required' });
  }
  
  const card = {
    id: Date.now().toString(),
    name,
    email: email || '',
    phone: phone || '',
    company: company || '',
    title: title || '',
    created_at: new Date(),
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    access_count: 0
  };
  
  cards.push(card);
  
  res.json({
    id: card.id,
    share_url: `https://special-dollop-974r54q6p7wgh7qv-3001.app.github.dev/card/${card.id}?id=${card.id}`,
  });
});

// Get card by ID
app.get('/api/cards/:id', (req, res) => {
  const { id } = req.params;
  const card = cards.find(c => c.id === id);
  
  if (!card) {
    return res.status(404).json({ error: 'Card not found' });
  }
  
  // Check if expired
  if (new Date() > card.expires_at) {
    return res.status(410).json({ error: 'Card expired' });
  }
  
  // Increment access count
  card.access_count++;
  
  res.json({
    name: card.name,
    email: card.email,
    phone: card.phone,
    company: card.company,
    title: card.title,
    access_count: card.access_count,
    expires_at: card.expires_at
  });
});

// List all cards (for testing)
app.get('/api/cards', (req, res) => {
  res.json(cards.map(card => ({
    id: card.id,
    name: card.name,
    created_at: card.created_at,
    expires_at: card.expires_at,
    access_count: card.access_count
  })));
});

// Redirect card URLs to pretty view
app.get('/card/:id', (req, res) => {
  res.sendFile(__dirname + '/public/card.html');
});

app.listen(PORT, () => {
  console.log(`Whispr Cards API running on port ${PORT}`);
});