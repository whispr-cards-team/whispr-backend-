const express = require('express');
const cors = require('cors');
const QRCode = require('qrcode');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Initialize SQLite database
const db = new sqlite3.Database(':memory:'); // In-memory for now

// Create cards table
db.serialize(() => {
  db.run(`CREATE TABLE cards (
    id TEXT PRIMARY KEY,
    firstName TEXT,
    lastName TEXT,
    fullName TEXT,
    title TEXT,
    function TEXT,
    company TEXT,
    address TEXT,
    email TEXT,
    phone TEXT,
    created_at DATETIME,
    expires_at DATETIME,
    access_count INTEGER DEFAULT 0
  )`);
});

// Create disposable card
app.post('/api/cards', (req, res) => {
  const { firstName, lastName, email, phone, company, title, function: jobFunction, address, expires_in_hours = 24 } = req.body;
  
  if (!firstName || !lastName) {
    return res.status(400).json({ error: 'First name and last name are required' });
  }
  
  const card = {
    id: Date.now().toString(),
    firstName,
    lastName,
    fullName: `${firstName} ${lastName}`,
    title: title || '',
    function: jobFunction || '',
    company: company || '',
    address: address || '',
    email: email || '',
    phone: phone || '',
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + expires_in_hours * 60 * 60 * 1000).toISOString(),
    access_count: 0
  };
  
  db.run(`INSERT INTO cards (id, firstName, lastName, fullName, title, function, company, address, email, phone, created_at, expires_at, access_count) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [card.id, card.firstName, card.lastName, card.fullName, card.title, card.function, card.company, card.address, card.email, card.phone, card.created_at, card.expires_at, card.access_count],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to create card' });
      }
      
      res.json({
        id: card.id,
        share_url: `https://special-dollop-974r54q6p7wgh7qv-3001.app.github.dev/card/${card.id}?id=${card.id}`,
        expires_at: card.expires_at
      });
    });
});

// Get card by ID
app.get('/api/cards/:id', (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM cards WHERE id = ?', [id], (err, card) => {
    if (err || !card) {
      return res.status(404).json({ error: 'Card not found' });
    }
    
    // Check if expired
    if (new Date() > new Date(card.expires_at)) {
      return res.status(410).json({ error: 'Card expired' });
    }
    
    // Increment access count
    db.run('UPDATE cards SET access_count = access_count + 1 WHERE id = ?', [id]);
    
    res.json({
      firstName: card.firstName,
      lastName: card.lastName,
      fullName: card.fullName,
      email: card.email,
      phone: card.phone,
      company: card.company,
      title: card.title,
      function: card.function,
      address: card.address,
      access_count: card.access_count + 1,
      expires_at: card.expires_at
    });
  });
});

// List all cards
app.get('/api/cards', (req, res) => {
  db.all('SELECT id, fullName, created_at, expires_at, access_count FROM cards ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch cards' });
    }
    res.json(rows);
  });
});

// Redirect card URLs to pretty view
app.get('/card/:id', (req, res) => {
  res.sendFile(__dirname + '/public/card.html');
});

// Generate QR code for card
app.get('/qr/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const cardUrl = `https://special-dollop-974r54q6p7wgh7qv-3001.app.github.dev/card/${id}?id=${id}`;
    
    const qrCodeDataUrl = await QRCode.toDataURL(cardUrl, {
      width: 300,
      margin: 2,
      color: { dark: '#000000', light: '#FFFFFF' }
    });
    
    res.json({ qrCode: qrCodeDataUrl });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

// Generate vCard for download
app.get('/vcard/:id', async (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM cards WHERE id = ?', [id], (err, card) => {
    if (err || !card) {
      return res.status(404).json({ error: 'Card not found' });
    }
    
    if (new Date() > new Date(card.expires_at)) {
      return res.status(410).json({ error: 'Card expired' });
    }
    
    let vcard = 'BEGIN:VCARD\r\n';
    vcard += 'VERSION:3.0\r\n';
    vcard += `FN:${card.fullName}\r\n`;
    vcard += `N:${card.lastName};${card.firstName};;;\r\n`;
    
    if (card.title) vcard += `TITLE:${card.title}\r\n`;
    if (card.function) vcard += `ROLE:${card.function}\r\n`;
    if (card.company) vcard += `ORG:${card.company}\r\n`;
    if (card.email) vcard += `EMAIL:${card.email}\r\n`;
    if (card.phone) vcard += `TEL:${card.phone}\r\n`;
    if (card.address) vcard += `ADR:;;${card.address};;;;\r\n`;
    
    vcard += 'END:VCARD\r\n';
    
    res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${card.firstName}_${card.lastName}.vcf"`);
    res.send(vcard);
  });
});

// Analytics endpoint
app.get('/api/analytics', (req, res) => {
  db.all('SELECT * FROM cards', (err, cards) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to generate analytics' });
    }
    
    const totalCards = cards.length;
    const activeCards = cards.filter(card => new Date() < new Date(card.expires_at)).length;
    const expiredCards = totalCards - activeCards;
    
    const totalViews = cards.reduce((sum, card) => sum + card.access_count, 0);
    const averageViews = totalCards > 0 ? (totalViews / totalCards).toFixed(1) : 0;
    
    const topCards = cards
      .map(card => ({
        id: card.id.slice(-6),
        views: card.access_count,
        created: card.created_at.split('T')[0],
        expired: new Date() > new Date(card.expires_at)
      }))
      .sort((a, b) => b.views - a.views)
      .slice(0, 5);
    
    const last7Days = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      
      const cardsOnDay = cards.filter(card => 
        card.created_at.split('T')[0] === dateStr
      ).length;
      
      last7Days.push({ date: dateStr, count: cardsOnDay });
    }
    
    res.json({
      summary: { totalCards, activeCards, expiredCards, totalViews, averageViews },
      topCards,
      dailyStats: last7Days
    });
  });
});

app.listen(PORT, () => {
  console.log(`Whispr Cards API running on port ${PORT}`);
});