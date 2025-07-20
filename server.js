require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

// Create MySQL connection pool using environment variables
const pool = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Middleware to verify JWT and extract user role
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

// Only allow admins to access certain endpoints
function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  next();
}

// User registration (hashing password before insert)
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    const hashed = await bcrypt.hash(password, 12);
    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    const values = [username, hashed, 'user'];
    pool.query(sql, values, (err, results) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.status(201).json({ message: 'User registered' });
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// User login (compare hash and issue JWT)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const sql = 'SELECT id, password, role FROM users WHERE username = ?';
  pool.query(sql, [username], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const tokenPayload = { id: user.id, username, role: user.role };
    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Protected endpoint: only authenticated admins can view all users
app.get('/users', authenticateToken, authorizeAdmin, (req, res) => {
  const sql = 'SELECT id, username, role FROM users';
  pool.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(results);
  });
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on port ${port}`));