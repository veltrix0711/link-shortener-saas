// Link Shortener SaaS with User Authentication

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { nanoid } = require('nanoid'); // Import nanoid v3.x
const QRCode = require('qrcode'); // Import QR code generator
const UAParser = require('ua-parser-js'); // Import user-agent parser
const bcrypt = require('bcryptjs'); // For password hashing
const jwt = require('jsonwebtoken'); // For JWT tokens
const session = require('express-session'); // For session management
const cookieParser = require('cookie-parser'); // For cookie parsing
const app = express();
const PORT = process.env.PORT || 3000;

// JWT Secret (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
app.use(express.static('public')); // Serve static files from public directory

// ====== AUTHENTICATION ROUTES ======

// User Registration
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  // Validation
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }
  
  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address' });
  }
  
  try {
    // Check if user already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, existingUser) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (existingUser) {
        return res.status(400).json({ error: 'User with this email already exists' });
      }
      
      // Hash password and create user
      const passwordHash = await hashPassword(password);
      
      db.run(
        'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
        [name, email, passwordHash],
        function(insertErr) {
          if (insertErr) {
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          const userId = this.lastID;
          const token = generateToken(userId);
          
          // Set cookie
          res.cookie('auth_token', token, { 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
          });
          
          res.json({
            success: true,
            message: 'Registration successful',
            user: { id: userId, name, email },
            token
          });
        }
      );
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      
      const isValidPassword = await verifyPassword(password, user.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      
      const token = generateToken(user.id);
      
      // Set cookie
      res.cookie('auth_token', token, { 
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
      
      res.json({
        success: true,
        message: 'Login successful',
        user: { id: user.id, name: user.name, email: user.email },
        token
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// User Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true, message: 'Logged out successfully' });
});

// Get current user
app.get('/api/auth/user', requireAuth, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// Update user profile
app.put('/api/auth/profile', requireAuth, async (req, res) => {
  const { name, email } = req.body;
  const userId = req.user.id;
  
  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email are required' });
  }
  
  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address' });
  }
  
  // Check if email is taken by another user
  db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, userId], (err, existingUser) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already taken' });
    }
    
    // Update user
    db.run(
      'UPDATE users SET name = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [name, email, userId],
      function(updateErr) {
        if (updateErr) {
          return res.status(500).json({ error: 'Failed to update profile' });
        }
        
        res.json({
          success: true,
          message: 'Profile updated successfully',
          user: { id: userId, name, email }
        });
      }
    );
  });
});

// Change password
app.put('/api/auth/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long' });
  }
  
  try {
    // Get current password hash
    db.get('SELECT password_hash FROM users WHERE id = ?', [userId], async (err, user) => {
      if (err || !user) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Verify current password
      const isValidPassword = await verifyPassword(currentPassword, user.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      
      // Hash new password
      const newPasswordHash = await hashPassword(newPassword);
      
      // Update password
      db.run(
        'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [newPasswordHash, userId],
        function(updateErr) {
          if (updateErr) {
            return res.status(500).json({ error: 'Failed to update password' });
          }
          
          res.json({
            success: true,
            message: 'Password updated successfully'
          });
        }
      );
    });
  } catch (error) {
    console.error('Password update error:', error);
    res.status(500).json({ error: 'Server error during password update' });
  }
});

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
const DB_PATH = process.env.DB_PATH || './links.db'; // Use file-based database for persistence

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
  // Users table for authentication
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_verified INTEGER DEFAULT 0,
    reset_token TEXT,
    reset_token_expires TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    original_url TEXT NOT NULL,
    custom_alias TEXT UNIQUE,
    expires_at TIMESTAMP NULL,
    is_active INTEGER DEFAULT 1,
    user_id INTEGER,
    is_public INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    click_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  
  // Add new columns if they don't exist (for existing databases)
  db.run(`ALTER TABLE links ADD COLUMN is_active INTEGER DEFAULT 1`, () => {});
  db.run(`ALTER TABLE links ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`, () => {});
  db.run(`ALTER TABLE links ADD COLUMN user_id INTEGER`, () => {});
  db.run(`ALTER TABLE links ADD COLUMN is_public INTEGER DEFAULT 1`, () => {});
  
  // Sessions table for login management
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
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

// ====== AUTHENTICATION HELPER FUNCTIONS ======

// Hash password
async function hashPassword(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

// Verify password
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Generate JWT token
function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

// Verify JWT token
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Authentication middleware
function requireAuth(req, res, next) {
  const token = req.cookies.auth_token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  // Get user info and attach to request
  db.get('SELECT id, email, name FROM users WHERE id = ?', [decoded.userId], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    next();
  });
}

// Optional authentication middleware (for mixed public/private features)
function optionalAuth(req, res, next) {
  const token = req.cookies.auth_token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    req.user = null;
    return next();
  }
  
  const decoded = verifyToken(token);
  if (!decoded) {
    req.user = null;
    return next();
  }
  
  // Get user info and attach to request
  db.get('SELECT id, email, name FROM users WHERE id = ?', [decoded.userId], (err, user) => {
    req.user = user || null;
    next();
  });
}

// Helper function to format time remaining
function formatTimeRemaining(expiresAt) {
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry.getTime() - now.getTime();
  
  if (diff <= 0) return 'Expired';
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

// Create a new shortened link
app.post('/shorten', optionalAuth, (req, res) => {
  const { url, customAlias, expiresIn, isPublic = true } = req.body;
  const userId = req.user ? req.user.id : null;
  
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
    
    // Add user_id if user is logged in
    if (userId) {
      insertSql += ', user_id';
      insertParams.push(userId);
    }
    
    // Add privacy setting
    insertSql += ', is_public';
    insertParams.push(isPublic ? 1 : 0);
    
    insertSql += ') VALUES (' + '?,'.repeat(insertParams.length).slice(0, -1) + ')';
    
    db.run(insertSql, insertParams, function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(409).json({ error: 'This custom alias is already taken' });
        }
        return res.status(500).json({ error: 'Error saving to database' });
      }
      
      // Use Railway URL if available, otherwise fall back to host header
      const baseUrl = process.env.RAILWAY_STATIC_URL 
        ? `https://${process.env.RAILWAY_STATIC_URL}` 
        : `${req.protocol}://${req.headers.host}`;
      
      res.json({ 
        success: true,
        short_url: `${baseUrl}/${id}`, 
        original_url: url,
        id: id,
        custom_alias: customAlias || null,
        expires_at: expiresAt ? expiresAt.toISOString() : null,
        expires_in_human: expiresIn || null,
        owner: userId ? 'user' : 'anonymous',
        is_public: isPublic
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
        const baseUrl = process.env.RAILWAY_STATIC_URL 
          ? `https://${process.env.RAILWAY_STATIC_URL}` 
          : `${req.protocol}://${req.headers.host}`;
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
    
    // Check if link is active
    if (!row.is_active) {
      return res.status(403).json({ 
        error: 'Link is disabled',
        message: 'This link has been temporarily disabled'
      });
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
          const baseUrl = process.env.RAILWAY_STATIC_URL 
            ? `https://${process.env.RAILWAY_STATIC_URL}` 
            : `${req.protocol}://${req.headers.host}`;
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
        
        const baseUrl = process.env.RAILWAY_STATIC_URL 
          ? `https://${process.env.RAILWAY_STATIC_URL}` 
          : `${req.protocol}://${req.headers.host}`;
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
        
        const baseUrl = process.env.RAILWAY_STATIC_URL 
          ? `https://${process.env.RAILWAY_STATIC_URL}` 
          : `${req.protocol}://${req.headers.host}`;
        
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

// ====== FEATURE 4: LINK MANAGEMENT APIs ======

// Update a link (URL, alias, expiration)
app.put('/api/links/:id', (req, res) => {
  const { id } = req.params;
  const { url, customAlias, expiresIn, isActive } = req.body;
  
  // Get current link first
  db.get('SELECT * FROM links WHERE id = ? OR custom_alias = ?', [id, id], (err, currentLink) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error occurred' });
    }
    
    if (!currentLink) {
      return res.status(404).json({ error: 'Link not found' });
    }
    
    let updates = [];
    let values = [];
    
    // Update URL if provided
    if (url) {
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return res.status(400).json({ error: 'URL must start with http:// or https://' });
      }
      updates.push('original_url = ?');
      values.push(url);
    }
    
    // Update custom alias if provided
    if (customAlias !== undefined) {
      if (customAlias === '') {
        // Clear custom alias
        updates.push('custom_alias = NULL');
      } else {
        // Validate new alias
        if (!/^[a-zA-Z0-9-]{3,20}$/.test(customAlias)) {
          return res.status(400).json({ error: 'Custom alias must be 3-20 characters, alphanumeric and hyphens only' });
        }
        
        const reservedWords = ['api', 'admin', 'dashboard', 'www', 'app', 'mail', 'ftp', 'localhost', 'short', 'url'];
        if (reservedWords.includes(customAlias.toLowerCase())) {
          return res.status(400).json({ error: 'This alias is reserved and cannot be used' });
        }
        
        // Check if alias is already taken (excluding current link)
        db.get('SELECT id FROM links WHERE custom_alias = ? AND id != ?', [customAlias, currentLink.id], (aliasErr, existingAlias) => {
          if (aliasErr) {
            return res.status(500).json({ error: 'Database error checking alias' });
          }
          if (existingAlias) {
            return res.status(400).json({ error: 'This custom alias is already taken' });
          }
          
          updates.push('custom_alias = ?');
          values.push(customAlias);
          continueUpdate();
        });
        return; // Wait for alias check
      }
    }
    
    // Update expiration if provided
    if (expiresIn !== undefined) {
      if (expiresIn === '') {
        // Clear expiration
        updates.push('expires_at = NULL');
      } else {
        const timeRegex = /^(\d+)\s+(second|minute|hour|day|week|month)s?$/i;
        const match = expiresIn.match(timeRegex);
        
        if (!match) {
          return res.status(400).json({ 
            error: 'Invalid expiration format. Use format like "30 seconds", "30 minutes", "2 hours", "7 days", "2 weeks", "1 month"' 
          });
        }
        
        const amount = parseInt(match[1]);
        const unit = match[2].toLowerCase();
        
        const now = new Date();
        let expirationDate;
        
        switch (unit) {
          case 'second':
            expirationDate = new Date(now.getTime() + amount * 1000);
            break;
          case 'minute':
            expirationDate = new Date(now.getTime() + amount * 60 * 1000);
            break;
          case 'hour':
            expirationDate = new Date(now.getTime() + amount * 60 * 60 * 1000);
            break;
          case 'day':
            expirationDate = new Date(now.getTime() + amount * 24 * 60 * 60 * 1000);
            break;
          case 'week':
            expirationDate = new Date(now.getTime() + amount * 7 * 24 * 60 * 60 * 1000);
            break;
          case 'month':
            expirationDate = new Date(now.getTime() + amount * 30 * 24 * 60 * 60 * 1000);
            break;
        }
        
        updates.push('expires_at = ?');
        values.push(expirationDate.toISOString());
      }
    }
    
    // Update active status if provided
    if (isActive !== undefined) {
      updates.push('is_active = ?');
      values.push(isActive ? 1 : 0);
    }
    
    continueUpdate();
    
    function continueUpdate() {
      if (updates.length === 0) {
        return res.status(400).json({ error: 'No updates provided' });
      }
      
      values.push(currentLink.id);
      const sql = `UPDATE links SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
      
      db.run(sql, values, function(updateErr) {
        if (updateErr) {
          console.error('Update error:', updateErr);
          return res.status(500).json({ error: 'Failed to update link' });
        }
        
        // Get updated link
        db.get('SELECT * FROM links WHERE id = ?', [currentLink.id], (getErr, updatedLink) => {
          if (getErr) {
            return res.status(500).json({ error: 'Error retrieving updated link' });
          }
          
          const baseUrl = process.env.RAILWAY_STATIC_URL 
            ? `https://${process.env.RAILWAY_STATIC_URL}` 
            : `${req.protocol}://${req.headers.host}`;
          
          res.json({
            success: true,
            message: 'Link updated successfully',
            link: {
              ...updatedLink,
              short_url: `${baseUrl}/${updatedLink.custom_alias || updatedLink.id}`,
              expires_in_human: updatedLink.expires_at ? formatTimeRemaining(updatedLink.expires_at) : null
            }
          });
        });
      });
    }
  });
});

// Toggle link active/inactive status
app.patch('/api/links/:id/toggle', (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM links WHERE id = ? OR custom_alias = ?', [id, id], (err, link) => {
    if (err) {
      return res.status(500).json({ error: 'Database error occurred' });
    }
    
    if (!link) {
      return res.status(404).json({ error: 'Link not found' });
    }
    
    const newStatus = link.is_active ? 0 : 1;
    
    db.run('UPDATE links SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', 
           [newStatus, link.id], function(updateErr) {
      if (updateErr) {
        return res.status(500).json({ error: 'Failed to toggle link status' });
      }
      
      res.json({
        success: true,
        message: `Link ${newStatus ? 'activated' : 'deactivated'} successfully`,
        isActive: Boolean(newStatus)
      });
    });
  });
});

// Delete a link permanently
app.delete('/api/links/:id', (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM links WHERE id = ? OR custom_alias = ?', [id, id], (err, link) => {
    if (err) {
      return res.status(500).json({ error: 'Database error occurred' });
    }
    
    if (!link) {
      return res.status(404).json({ error: 'Link not found' });
    }
    
    // Delete analytics data first (foreign key constraint)
    db.run('DELETE FROM clicks WHERE link_id = ?', [link.id], (clicksErr) => {
      if (clicksErr) {
        return res.status(500).json({ error: 'Failed to delete analytics data' });
      }
      
      // Delete the link
      db.run('DELETE FROM links WHERE id = ?', [link.id], function(deleteErr) {
        if (deleteErr) {
          return res.status(500).json({ error: 'Failed to delete link' });
        }
        
        res.json({
          success: true,
          message: 'Link deleted successfully'
        });
      });
    });
  });
});

// Get all links for management (with pagination)
app.get('/api/links', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const search = req.query.search || '';
  const status = req.query.status; // 'active', 'inactive', 'expired', or 'all'
  const offset = (page - 1) * limit;
  
  let whereConditions = [];
  let params = [];
  
  // Search filter
  if (search) {
    whereConditions.push('(original_url LIKE ? OR custom_alias LIKE ? OR id LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  
  // Status filter
  if (status === 'active') {
    whereConditions.push('is_active = 1 AND (expires_at IS NULL OR expires_at > datetime("now"))');
  } else if (status === 'inactive') {
    whereConditions.push('is_active = 0');
  } else if (status === 'expired') {
    whereConditions.push('expires_at IS NOT NULL AND expires_at <= datetime("now")');
  }
  
  const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
  
  // Get total count
  db.get(`SELECT COUNT(*) as total FROM links ${whereClause}`, params, (countErr, countResult) => {
    if (countErr) {
      return res.status(500).json({ error: 'Error counting links' });
    }
    
    // Get links with click counts
    const sql = `
      SELECT l.*, COUNT(c.id) as click_count 
      FROM links l 
      LEFT JOIN clicks c ON l.id = c.link_id 
      ${whereClause}
      GROUP BY l.id 
      ORDER BY l.created_at DESC 
      LIMIT ? OFFSET ?
    `;
    
    db.all(sql, [...params, limit, offset], (err, links) => {
      if (err) {
        return res.status(500).json({ error: 'Error retrieving links' });
      }
      
      const baseUrl = process.env.RAILWAY_STATIC_URL || `http://${req.headers.host}`;
      
      const formattedLinks = links.map(link => ({
        ...link,
        short_url: `${baseUrl}/${link.custom_alias || link.id}`,
        is_expired: link.expires_at && new Date(link.expires_at) <= new Date(),
        expires_in_human: link.expires_at ? formatTimeRemaining(link.expires_at) : null
      }));
      
      res.json({
        success: true,
        links: formattedLinks,
        pagination: {
          page,
          limit,
          total: countResult.total,
          totalPages: Math.ceil(countResult.total / limit),
          hasNext: page * limit < countResult.total,
          hasPrev: page > 1
        }
      });
    });
  });
});

// Bulk operations on multiple links
app.post('/api/links/bulk', (req, res) => {
  const { action, linkIds } = req.body;
  
  if (!action || !linkIds || !Array.isArray(linkIds) || linkIds.length === 0) {
    return res.status(400).json({ error: 'Invalid bulk operation request' });
  }
  
  const placeholders = linkIds.map(() => '?').join(',');
  
  switch (action) {
    case 'activate':
      db.run(`UPDATE links SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id IN (${placeholders})`, 
             linkIds, function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to activate links' });
        }
        res.json({ success: true, message: `${this.changes} links activated`, affected: this.changes });
      });
      break;
      
    case 'deactivate':
      db.run(`UPDATE links SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id IN (${placeholders})`, 
             linkIds, function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to deactivate links' });
        }
        res.json({ success: true, message: `${this.changes} links deactivated`, affected: this.changes });
      });
      break;
      
    case 'delete':
      // Delete analytics first
      db.run(`DELETE FROM clicks WHERE link_id IN (${placeholders})`, linkIds, (clicksErr) => {
        if (clicksErr) {
          return res.status(500).json({ error: 'Failed to delete analytics data' });
        }
        
        // Delete links
        db.run(`DELETE FROM links WHERE id IN (${placeholders})`, linkIds, function(deleteErr) {
          if (deleteErr) {
            return res.status(500).json({ error: 'Failed to delete links' });
          }
          res.json({ success: true, message: `${this.changes} links deleted`, affected: this.changes });
        });
      });
      break;
      
    default:
      res.status(400).json({ error: 'Invalid bulk action. Use: activate, deactivate, or delete' });
  }
});

const server = app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));

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
