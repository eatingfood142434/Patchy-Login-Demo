require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(bodyParser.json());

// Create a connection pool with environment-based configuration
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware: verify JWT token for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Missing authentication token' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// User registration endpoint
app.post(
  '/register',
  // Input validation
  body('username').isAlphanumeric().isLength({ min: 3, max: 30 }),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;
    try {
      // Prevent duplicate usernames
      const [existing] = await pool.query(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );
      if (existing.length) {
        return res.status(409).json({ message: 'Username already taken' });
      }
      // Hash password with bcrypt
      const hashed = await bcrypt.hash(password, 12);
      // Parameterized insert to avoid SQL injection
      await pool.query(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashed]
      );
      res.status(201).json({ message: 'Registration successful' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// User login endpoint
app.post(
  '/login',
  body('username').isAlphanumeric().isLength({ min: 3, max: 30 }),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;
    try {
      // Parameterized query to fetch user record
      const [rows] = await pool.query(
        'SELECT id, password, role FROM users WHERE username = ?',
        [username]
      );
      if (!rows.length) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const user = rows[0];
      // Compare hashed passwords
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      // Issue JWT (omit password)
      const payload = { userId: user.id, role: user.role, username };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Example protected route: fetch user profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, username, role FROM users WHERE id = ?',
      [req.user.userId]
    );
    if (!rows.length) return res.status(404).json({ message: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});