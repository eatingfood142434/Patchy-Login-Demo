// server.js
const express = require('express');
const mysql = require('mysql2/promise');             // Use promise-based client
const bcrypt = require('bcrypt');                      // For password hashing
const jwt = require('jsonwebtoken');                   // For token-based auth
require('dotenv').config();                            // Load credentials from .env

const app = express();
app.use(express.json());                               // Built-in body parser

// Create a connection pool using env variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware: Verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Missing token' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Middleware: Role-based authorization
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Insufficient privileges' });
    }
    next();
  };
}

// SIGNUP: create user with hashed password
app.post('/signup', async (req, res) => {
  const { username, password, role } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.execute(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hash, role || 'user']
    );
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// LOGIN: verify credentials and issue JWT
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, password, role FROM users WHERE username = ?',
      [username]
    );
    if (rows.length === 0) return res.status(401).json({ message: 'Unauthorized' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Unauthorized' });

    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET A USER BY ID: authenticated users only
app.get('/user/:id', authenticateToken, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ message: 'Invalid user ID' });
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, role FROM users WHERE id = ?',
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ message: 'Not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET ALL USERS: only admin can access
app.get('/users', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, username, role FROM users');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));