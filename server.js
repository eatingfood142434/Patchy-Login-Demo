// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(express.json());

// Configure session management
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 3600000 } // adjust secure in production
}));

// Create a connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// User login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Use parameterized query to prevent SQL injection
    const [rows] = await pool.execute(
      'SELECT id, username, password_hash FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    // Compare provided password with stored hash
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Authentication successful: establish session
    req.session.userId = user.id;
    req.session.username = user.username;
    return res.json({ message: 'Login successful' });

  } catch (err) {
    console.error('Database error during login:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// User signup route (for completeness)
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: 'Invalid username or password' });
  }

  try {
    // Hash password with bcrypt
    const passwordHash = await bcrypt.hash(password, 12);
    // Parameterized insert
    await pool.execute(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash]
    );
    return res.status(201).json({ message: 'User created' });
  } catch (err) {
    console.error('Database error during signup:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected resource example
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json({ message: `Welcome ${req.session.username}` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));