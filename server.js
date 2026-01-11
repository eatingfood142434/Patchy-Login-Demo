// server.js
// Secure API with parameterized queries, hashed passwords, JWT authentication
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
app.use(express.json());

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

// Middleware to verify JWT tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Registration endpoint
app.post(
  '/register',
  [
    body('username')
      .isAlphanumeric().withMessage('Username must be alphanumeric')
      .isLength({ min: 3, max: 20 }).withMessage('Username length must be 3-20'),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    try {
      // Hash the password with bcrypt
      const hashed = await bcrypt.hash(password, 12);
      // Use a prepared statement to prevent SQL injection
      const [result] = await pool.execute(
        'INSERT INTO users (username, password_hash) VALUES (?, ?)',
        [username, hashed]
      );
      res.status(201).json({ message: 'User registered', userId: result.insertId });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Database error' });
    }
  }
);

// Login endpoint
app.post(
  '/login',
  [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res) => {
    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    try {
      // Parameterized query to fetch user
      const [rows] = await pool.execute(
        'SELECT id, password_hash FROM users WHERE username = ?',
        [username]
      );
      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = rows[0];
      // Compare hashed password
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({ token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Database error' });
    }
  }
);

// Example protected route
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});