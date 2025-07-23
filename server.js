'use strict';

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise'); // promise-based mysql driver
const bcrypt = require('bcrypt');          // for password hashing
const jwt = require('jsonwebtoken');       // for token-based authentication
const { body, validationResult } = require('express-validator'); // input validation

const app = express();
app.use(express.json());

// Create a connection pool to the database using environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

/**
 * POST /register
 * Input validation + bcrypt password hashing + parameterized query
 */
app.post(
  '/register',
  [
    body('email').isEmail().withMessage('Invalid email address'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long')
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // Hash the password with bcrypt (12 salt rounds)
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // Use parameterized query to prevent SQL injection
      const [result] = await pool.execute(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)',
        [email, passwordHash]
      );

      return res.status(201).json({ message: 'User registered', userId: result.insertId });
    } catch (err) {
      console.error('Registration error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * POST /login
 * Verifies credentials, returns JWT on success
 */
app.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').exists().withMessage('Password is required')
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // Parameterized query to fetch user by email
      const [rows] = await pool.execute(
        'SELECT id, password_hash FROM users WHERE email = ?',
        [email]
      );

      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = rows[0];

      // Compare password hash
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Sign JWT token (expires in 1 hour)
      const token = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      return res.json({ token });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/**
 * Middleware to protect routes
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    req.user = payload;
    next();
  });
}

/**
 * GET /profile
 * Example protected endpoint
 */
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, email FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json(rows[0]);
  } catch (err) {
    console.error('Profile fetch error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
