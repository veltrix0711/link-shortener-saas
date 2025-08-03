// Link Shortener MVP using Node.js + Express + SQLite

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { nanoid } = require('nanoid'); // Import nanoid v3.x
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public')); // Serve static files from public directory

// Home route - serve the HTML interface
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// API info route (moved to /api)
app.get('/api', (req, res) => {
  res.json({
    message: 'Link Shortener API',
    endpoints: {
      'POST /shorten': 'Create a new short URL',
      'GET /:id': 'Redirect to original URL',
      'GET /dashboard': 'View all shortened links'
    }
  });
});

// Database configuration
const DB_PATH = process.env.DB_PATH || ':memory:'; // Use :memory: for in-memory DB or a file path for persistence

// Initialize DB
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
    process.exit(1); // Exit if DB connection fails
  }
  console.log(`Connected to SQLite database at ${DB_PATH}`);
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    original_url TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    click_count INTEGER DEFAULT 0
  )`);
  console.log('Database tables initialized');
});

// Create a new shortened link
app.post('/shorten', (req, res) => {
  const { url } = req.body;
  
  // Validate URL
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  try {
    // Check if URL is valid
    new URL(url);
    
    const id = nanoid(6);
    db.run('INSERT INTO links (id, original_url) VALUES (?, ?)', [id, url], (err) => {
      if (err) return res.status(500).json({ error: 'Error saving to database' });
      
      // Use RAILWAY_STATIC_URL if available, otherwise fall back to host header
      const baseUrl = process.env.RAILWAY_STATIC_URL || `http://${req.headers.host}`;
      
      res.json({ 
        success: true,
        short_url: `${baseUrl}/${id}`, 
        original_url: url,
        id: id
      });
    });
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
});

// Redirect route
app.get('/:id', (req, res, next) => {
  // Skip if it's a dashboard request
  if (req.params.id === 'dashboard') {
    return next();
  }

  const { id } = req.params;
  
  // Validate id format (should be 6 characters for nanoid)
  if (!id || id.length !== 6) {
    return res.status(400).json({ error: 'Invalid link ID' });
  }
  
  db.get('SELECT original_url FROM links WHERE id = ?', [id], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error occurred' });
    }
    
    if (!row) {
      return res.status(404).json({ error: 'Link not found' });
    }
    
    // Update click count (don't wait for completion but log errors)
    db.run('UPDATE links SET click_count = click_count + 1 WHERE id = ?', [id], (updateErr) => {
      if (updateErr) {
        console.error('Error updating click count:', updateErr);
      }
    });
    
    // Redirect to original URL
    res.redirect(row.original_url);
  });
});

// Dashboard route
app.get('/dashboard', (req, res) => {
  // If it's an API request (has query parameters or accepts JSON), return JSON
  if (req.query.page || req.query.limit || req.headers.accept?.includes('application/json')) {
    // Add basic pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    
    // Get total count for pagination
    db.get('SELECT COUNT(*) as total FROM links', [], (countErr, countRow) => {
      if (countErr) {
        console.error('Database error:', countErr);
        return res.status(500).json({ error: 'Error loading dashboard data' });
      }
      
      // Get paginated data
      db.all('SELECT id, original_url, created_at, click_count FROM links ORDER BY created_at DESC LIMIT ? OFFSET ?', 
        [limit, offset], 
        (err, rows) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Error loading dashboard data' });
          }
          
          // Format data for response
          const baseUrl = process.env.RAILWAY_STATIC_URL || `http://${req.headers.host}`;
          const links = rows.map(row => ({
            ...row,
            short_url: `${baseUrl}/${row.id}`
          }));
          
          res.json({
            success: true,
            total: countRow.total,
            page: page,
            limit: limit,
            total_pages: Math.ceil(countRow.total / limit),
            links: links
          });
      });
    });
  } else {
    // Serve the HTML dashboard
    res.sendFile(__dirname + '/public/dashboard.html');
  }
});

const server = app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

// Proper shutdown handling
process.on('SIGINT', () => {
  console.log('Closing database connection and shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed');
    }
    server.close(() => {
      console.log('Server shut down');
      process.exit(0);
    });
  });
});
