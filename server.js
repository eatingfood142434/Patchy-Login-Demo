// server.js - Secure Version
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(helmet());                // Set secure HTTP headers
app.use(express.json());          // Parse JSON bodies

// Create a connection pool using environment variables (no hardcoded credentials)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

// Input validation helper
function validateLoginInput(username, password) {
  if (typeof username !== 'string' || username.trim() === '') return false;
  if (typeof password !== 'string' || password.length < 8) return false;
  return true;
}

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!validateLoginInput(username, password)) {
      return res.status(400).json({ message: 'Invalid username or password format.' });
    }

    // Use parameterized query to prevent SQL injection
    const [rows] = await pool.execute(
      'SELECT id, password_hash, role FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      // Do not reveal whether username or password was incorrect
      return res.status(401).json({ message: 'Authentication failed.' });
    }

    const user = rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ message: 'Authentication failed.' });
    }

    // Issue a JWT token, signed with a strong secret
    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Middleware to protect routes
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing or invalid authorization header.' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
}

// Example protected route
app.get('/profile', authenticateJWT, async (req, res) => {
  // req.user.sub contains the user ID
  res.json({ message: `Hello user ${req.user.sub}`, role: req.user.role });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});