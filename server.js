// server.js (fixed version)
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');            // Use mysql2 for promise support
const bcrypt = require('bcrypt');            // For secure password hashing
const session = require('express-session');   // For session management

const app = express();
app.use(express.json());

// Secure session settings
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_me_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                  // Mitigate XSS
    secure: process.env.NODE_ENV === 'production', // Only send cookie over HTTPS in prod
    sameSite: 'lax'
  }
}));

// Create a connection pool using environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}).promise();

// Helper: Validate username and password input
function validateCredentials(username, password) {
  const usernameRe = /^[A-Za-z0-9_]{3,30}$/;
  if (!usernameRe.test(username)) return false;
  if (typeof password !== 'string' || password.length < 8) return false;
  return true;
}

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!validateCredentials(username, password)) {
    return res.status(400).json({ error: 'Invalid username or password format.' });
  }

  try {
    // Hash password before storing
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Use parameterized query to prevent SQL injection
    const [result] = await pool.execute(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash]
    );
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!validateCredentials(username, password)) {
    return res.status(400).json({ error: 'Invalid username or password format.' });
  }

  try {
    // Use parameterized query to fetch user record
    const [rows] = await pool.execute(
      'SELECT id, password_hash, role FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const user = rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Regenerate session to prevent fixation
    req.session.regenerate(err => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
      }
      // Store minimal user info in session
      req.session.userId = user.id;
      req.session.role = user.role;
      res.json({ message: 'Login successful.' });
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Example protected route
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  res.json({ message: 'Protected data for user ' + req.session.userId });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on port ${port}`));