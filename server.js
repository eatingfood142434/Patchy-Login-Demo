// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session configuration
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: true,
      maxAge: 1000 * 60 * 60 // 1 hour
    }
  })
);

// Create a reusable connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Registration endpoint with input validation and password hashing
app.post(
  '/register',
  [
    body('username').isAlphanumeric().isLength({ min: 4, max: 20 }),
    body('password').isLength({ min: 8 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    try {
      const hashed = await bcrypt.hash(password, 12);
      const [existing] = await pool.execute(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );
      if (existing.length) {
        return res.status(409).json({ message: 'Username already exists' });
      }
      await pool.execute(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashed]
      );
      res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Login endpoint with secure password verification
app.post(
  '/login',
  [
    body('username').isAlphanumeric(),
    body('password').isString().isLength({ min: 8 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    try {
      const [rows] = await pool.execute(
        'SELECT id, password FROM users WHERE username = ?',
        [username]
      );
      if (!rows.length) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      // Regenerate session to prevent fixation
      req.session.regenerate(err => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Session error' });
        }
        req.session.userId = user.id;
        res.json({ message: 'Logged in successfully' });
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Middleware to protect routes
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  next();
}

// Example protected data endpoint
app.get('/data', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT data FROM records WHERE user_id = ?',
      [req.session.userId]
    );
    res.json({ records: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Logout failed' });
    }
    res.clearCookie('sid');
    res.json({ message: 'Logged out' });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));