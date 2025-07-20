// server.js - Secured version
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
require('dotenv').config();

const app = express();
app.use(express.json());

// Configure session management with secure settings
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));

// Create a connection pool using mysql2 with built-in prepared statements
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// User signup route: hashes password before storage
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
    pool.execute(sql, [username, hashedPassword], (err) => {
      if (err) {
        console.error('DB error on signup:', err);
        return res.status(500).json({ error: 'Internal server error.' });
      }
      return res.status(201).json({ message: 'User created successfully.' });
    });
  } catch (err) {
    console.error('Hashing error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// User login route: compares hashed password
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const sql = 'SELECT id, password FROM users WHERE username = ?';
  pool.execute(sql, [username], async (err, results) => {
    if (err) {
      console.error('DB error on login:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const user = results[0];
    try {
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials.' });
      }
      // Store minimal data in session
      req.session.userId = user.id;
      return res.json({ message: 'Authenticated successfully.' });
    } catch (cmpErr) {
      console.error('Compare error:', cmpErr);
      return res.status(500).json({ error: 'Internal server error.' });
    }
  });
});

// Protected route example: retrieve user by ID, uses parameterized query and input validation
app.get('/user/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  const sql = 'SELECT id, username FROM users WHERE id = ?';
  pool.execute(sql, [id], (err, results) => {
    if (err) {
      console.error('DB error on get user:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    return res.json(results[0]);
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));