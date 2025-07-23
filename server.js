// server.js (secured)
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// Security middlewares
app.use(helmet());  // Set secure HTTP headers
app.use(bodyParser.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));  // Simple rate limiting

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    }
  })
);

// Create a MySQL connection pool using environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Registration endpoint
app.post(
  '/register',
  [
    body('username')
      .isAlphanumeric().withMessage('Username must be alphanumeric')
      .isLength({ min: 3, max: 20 }).withMessage('Username must be 3-20 characters'),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[!@#$%^&*]/).withMessage('Password must include a special character')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      // Hash the password before storing
      const hashedPassword = await bcrypt.hash(password, 12);

      // Use parameterized query to prevent SQL injection
      const [result] = await pool.execute(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashedPassword]
      );

      return res.status(201).json({ message: 'User registered', userId: result.insertId });
    } catch (err) {
      console.error('Registration error:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Login endpoint
app.post(
  '/login',
  [
    body('username')
      .isAlphanumeric().withMessage('Invalid username format')
      .isLength({ min: 3, max: 20 }),
    body('password')
      .isLength({ min: 8 }).withMessage('Invalid password format')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      // Parameterized query
      const [rows] = await pool.execute(
        'SELECT id, password FROM users WHERE username = ?',
        [username]
      );

      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = rows[0];

      // Compare hashed passwords
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Store minimal info in session
      req.session.userId = user.id;
      return res.json({ message: 'Logged in successfully' });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Example protected route
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // Fetch and return user profile...
  res.json({ message: 'This is a protected profile endpoint.' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));