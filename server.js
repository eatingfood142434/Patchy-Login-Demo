require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(helmet());
app.use(express.json());

// Basic rate limiter to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                 // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Create a connection pool using environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

// Registration endpoint – hashes password before storing
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation – allow only alphanumeric usernames 3-30 chars
    const usernamePattern = /^[a-zA-Z0-9_]{3,30}$/;
    if (!usernamePattern.test(username) || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Invalid username or password format.' });
    }

    // Hash the password with bcrypt
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Parameterized query to prevent SQL injection
    const [result] = await pool.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );

    return res.status(201).json({ message: 'User registered successfully.', userId: result.insertId });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// Login endpoint – compares hashed passwords securely
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    const usernamePattern = /^[a-zA-Z0-9_]{3,30}$/;
    if (!usernamePattern.test(username) || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid username or password format.' });
    }

    // Retrieve the user by username – parameterized query
    const [rows] = await pool.execute(
      'SELECT id, password FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Authentication failed.' });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Authentication failed.' });
    }

    // Issue JWT token
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({ message: 'Login successful.', token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});