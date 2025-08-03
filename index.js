// Link Shortener MVP using Node.js + Express + SQLite

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { nanoid } = require('nanoid'); // Import nanoid v3.x
const QRCode = require('qrcode'); // Import QR code generator
const UAParser = require('ua-parser-js'); // Import user-agent parser
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
      'GET /qr/:id': 'Generate QR code for a short URL',
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
    custom_alias TEXT UNIQUE,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    click_count INTEGER DEFAULT 0
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    referrer TEXT,
    country TEXT,
    city TEXT,
    device_type TEXT,
    browser TEXT,
    os TEXT,
    clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (link_id) REFERENCES links(id)
  )`);
  console.log('Database tables initialized');
});

// Create a new shortened link
app.post('/shorten', (req, res) => {
  const { url, customAlias, expiresIn } = req.body;
  
  // Validate URL
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  
  // Validate custom alias if provided
  if (customAlias) {
    // Check alias format: 3-20 characters, alphanumeric and hyphens only
    const aliasRegex = /^[a-zA-Z0-9-]{3,20}$/;
    if (!aliasRegex.test(customAlias)) {
      return res.status(400).json({ 
        error: 'Custom alias must be 3-20 characters long and contain only letters, numbers, and hyphens' 
      });
    }
    
    // Check for reserved words
    const reservedWords = ['api', 'dashboard', 'qr', 'admin', 'www', 'mail', 'ftp', 'localhost'];
    if (reservedWords.includes(customAlias.toLowerCase())) {
      return res.status(400).json({ error: 'This alias is reserved and cannot be used' });
    }
  }
  
  // Validate and calculate expiration date if provided
  let expiresAt = null;
  if (expiresIn) {
    const validUnits = ['seconds', 'minutes', 'hours', 'days', 'weeks', 'months'];
    const match = expiresIn.match(/^(\d+)\s*(seconds?|minutes?|hours?|days?|weeks?|months?)$/i);
    
    if (!match) {
      return res.status(400).json({ 
        error: 'Invalid expiration format. Use format like "30 seconds", "30 minutes", "2 hours", "7 days", "2 weeks", "1 month"' 
      });
    }
    
    const [, amount, unit] = match;
    const now = new Date();
    
    switch (unit.toLowerCase()) {
      case 'second':
      case 'seconds':
        expiresAt = new Date(now.getTime() + parseInt(amount) * 1000);
        break;
      case 'minute':
      case 'minutes':
        expiresAt = new Date(now.getTime() + parseInt(amount) * 60 * 1000);
        break;
      case 'hour':
      case 'hours':
        expiresAt = new Date(now.getTime() + parseInt(amount) * 60 * 60 * 1000);
        break;
      case 'day':
      case 'days':
        expiresAt = new Date(now.getTime() + parseInt(amount) * 24 * 60 * 60 * 1000);
        break;
      case 'week':
      case 'weeks':
        expiresAt = new Date(now.getTime() + parseInt(amount) * 7 * 24 * 60 * 60 * 1000);
        break;
      case 'month':
      case 'months':
        expiresAt = new Date(now.getTime() + parseInt(amount) * 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        return res.status(400).json({ error: 'Invalid time unit' });
    }
    
    // Limit maximum expiration to 1 year
    const oneYear = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
    if (expiresAt > oneYear) {
      return res.status(400).json({ error: 'Maximum expiration is 1 year' });
    }
  }
  
  try {
    // Check if URL is valid
    new URL(url);
    
    const id = customAlias || nanoid(6);
    
    // Build dynamic SQL based on what data we have
    let insertSql = 'INSERT INTO links (id, original_url';
    let insertParams = [id, url];
    
    if (customAlias) {
      insertSql += ', custom_alias';
      insertParams.push(customAlias);
    }
    
    if (expiresAt) {
      insertSql += ', expires_at';
      insertParams.push(expiresAt.toISOString());
    }
    
    insertSql += ') VALUES (' + '?,'.repeat(insertParams.length).slice(0, -1) + ')';
    
    db.run(insertSql, insertParams, function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(409).json({ error: 'This custom alias is already taken' });
        }
        return res.status(500).json({ error: 'Error saving to database' });
      }
      
      // Use RAILWAY_STATIC_URL if available, otherwise fall back to host header
      const baseUrl = process.env.RAILWAY_STATIC_URL || `http://${req.headers.host}`;
      
      res.json({ 
        success: true,
        short_url: `${baseUrl}/${id}`, 
        original_url: url,
        id: id,
        custom_alias: customAlias || null,
        expires_at: expiresAt ? expiresAt.toISOString() : null,
        expires_in_human: expiresIn || null
      });
    });
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
});

// QR Code generation endpoint
app.get('/qr/:id', async (req, res) => {
  const { id } = req.params;
  
  // Validate id format
  if (!id || id.length !== 6) {
    return res.status(400).json({ error: 'Invalid link ID' });
  }
  
  try {
    // Check if the link exists
    db.get('SELECT original_url FROM links WHERE id = ?', [id], async (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error occurred' });
      }
      
      if (!row) {
        return res.status(404).json({ error: 'Link not found' });
      }
      
      try {
        const baseUrl = process.env.RAILWAY_STATIC_URL || `http://${req.headers.host}`;
        const shortUrl = `${baseUrl}/${id}`;
        
        // Generate QR code as PNG buffer
        const qrCodeBuffer = await QRCode.toBuffer(shortUrl, {
          width: 300,
          margin: 2,
          color: {
            dark: '#000000',
            light: '#FFFFFF'
          }
        });
        
        // Set appropriate headers
        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Content-Disposition', `inline; filename="qr-${id}.png"`);
        res.send(qrCodeBuffer);
        
      } catch (qrError) {
        console.error('QR Code generation error:', qrError);
        res.status(500).json({ error: 'Failed to generate QR code' });
      }
    });
  } catch (error) {
    console.error('QR endpoint error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Redirect route
app.get('/:id', (req, res, next) => {
  // Skip if it's a dashboard request
  if (req.params.id === 'dashboard') {
    return next();
  }

  const { id } = req.params;
  
  // Look up link by ID or custom alias
  db.get('SELECT * FROM links WHERE id = ? OR custom_alias = ?', [id, id], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error occurred' });
    }
    
    if (!row) {
      return res.status(404).json({ error: 'Link not found' });
    }
    
    // Check if link has expired
    if (row.expires_at) {
      const now = new Date();
      const expiresAt = new Date(row.expires_at);
      
      if (now > expiresAt) {
        return res.status(410).json({ 
          error: 'Link has expired',
          expired_at: expiresAt.toISOString(),
          message: 'This link has expired and is no longer available'
        });
      }
    }
    
    // Capture analytics data
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const referrer = req.headers.referer || req.headers.referrer || 'Direct';
    const ipAddress = req.headers['x-forwarded-for'] || 
                     req.headers['x-real-ip'] || 
                     req.connection.remoteAddress || 
                     req.socket.remoteAddress || 
                     'Unknown';
    
    // Parse user agent for device/browser info
    const parser = new UAParser(userAgent);
    const result = parser.getResult();
    
    const deviceType = result.device.type || (result.os.name ? 'desktop' : 'unknown');
    const browser = result.browser.name || 'Unknown';
    const os = result.os.name || 'Unknown';
    
    // Update click count
    db.run('UPDATE links SET click_count = click_count + 1 WHERE id = ?', [row.id], (updateErr) => {
      if (updateErr) {
        console.error('Error updating click count:', updateErr);
      }
    });
    
    // Insert detailed analytics
    db.run(`INSERT INTO clicks (
      link_id, ip_address, user_agent, referrer, 
      device_type, browser, os
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`, [
      row.id, ipAddress, userAgent, referrer,
      deviceType, browser, os
    ], (analyticsErr) => {
      if (analyticsErr) {
        console.error('Error inserting analytics:', analyticsErr);
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

// Analytics API endpoints
// Global analytics API (must come before individual analytics)
app.get('/api/analytics/global', (req, res) => {
  // Get total stats
  db.get(`SELECT 
    COUNT(DISTINCT l.id) as total_links,
    COUNT(c.id) as total_clicks,
    COUNT(DISTINCT DATE(c.clicked_at)) as active_days
  FROM links l 
  LEFT JOIN clicks c ON l.id = c.link_id`, [], (err, stats) => {
    if (err) {
      console.error('Global stats error:', err);
      return res.status(500).json({ error: 'Error loading global stats' });
    }
    
    // Get clicks over time (last 30 days)
    db.all(`SELECT 
      DATE(clicked_at) as date,
      COUNT(*) as clicks
    FROM clicks 
    WHERE clicked_at >= datetime('now', '-30 days')
    GROUP BY DATE(clicked_at)
    ORDER BY date DESC`, [], (timeErr, timeStats) => {
      if (timeErr) {
        console.error('Time stats error:', timeErr);
        return res.status(500).json({ error: 'Error loading time stats' });
      }
      
      // Get top performing links
      db.all(`SELECT 
        l.id,
        l.original_url,
        l.custom_alias,
        l.click_count,
        COUNT(c.id) as recent_clicks
      FROM links l 
      LEFT JOIN clicks c ON l.id = c.link_id AND c.clicked_at >= datetime('now', '-7 days')
      GROUP BY l.id
      ORDER BY l.click_count DESC
      LIMIT 10`, [], (topErr, topLinks) => {
        if (topErr) {
          console.error('Top links error:', topErr);
          return res.status(500).json({ error: 'Error loading top links' });
        }
        
        const baseUrl = process.env.RAILWAY_STATIC_URL || `http://${req.headers.host}`;
        const formattedTopLinks = topLinks.map(link => ({
          ...link,
          short_url: `${baseUrl}/${link.id}`
        }));
        
        res.json({
          success: true,
          global_stats: stats,
          clicks_over_time: timeStats,
          top_links: formattedTopLinks
        });
      });
    });
  });
});

app.get('/api/analytics/:id', (req, res) => {
  const { id } = req.params;
  
  // Get link info first (by ID or custom alias)
  db.get('SELECT * FROM links WHERE id = ? OR custom_alias = ?', [id, id], (err, link) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error occurred' });
    }
    
    if (!link) {
      return res.status(404).json({ error: 'Link not found' });
    }
    
    // Get detailed analytics
    db.all(`SELECT 
      DATE(clicked_at) as date,
      COUNT(*) as clicks,
      device_type,
      browser,
      os,
      referrer
    FROM clicks 
    WHERE link_id = ? 
    GROUP BY DATE(clicked_at), device_type, browser, os, referrer
    ORDER BY clicked_at DESC`, [link.id], (analyticsErr, analytics) => {
      if (analyticsErr) {
        console.error('Analytics error:', analyticsErr);
        return res.status(500).json({ error: 'Error loading analytics' });
      }
      
      // Get summary stats
      db.all(`SELECT 
        COUNT(*) as total_clicks,
        COUNT(DISTINCT DATE(clicked_at)) as active_days,
        device_type,
        COUNT(*) as device_clicks
      FROM clicks 
      WHERE link_id = ? 
      GROUP BY device_type`, [link.id], (summaryErr, deviceStats) => {
        if (summaryErr) {
          console.error('Summary error:', summaryErr);
          return res.status(500).json({ error: 'Error loading summary' });
        }
        
        const baseUrl = process.env.RAILWAY_STATIC_URL || `http://${req.headers.host}`;
        
        res.json({
          success: true,
          link: {
            ...link,
            short_url: `${baseUrl}/${link.id}`
          },
          analytics: analytics,
          device_stats: deviceStats
        });
      });
    });
  });
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
