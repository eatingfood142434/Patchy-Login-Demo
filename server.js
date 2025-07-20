const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const { body, param, validationResult } = require('express-validator');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
app.use(helmet());
app.use(express.json());

// Create a connection pool using environment variables for credentials
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware: handle validation errors from express-validator
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

// Registration endpoint: hashes password and uses parameterized query
app.post(
  '/register',
  body('username').isAlphanumeric().isLength({ min: 3, max: 30 }),
  body('password').isLength({ min: 8 }),
  handleValidationErrors,
  async (req, res) => {
    const { username, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 12);
      const [result] = await pool.execute(
        'INSERT INTO users (username, password) VALUES (?, ?)',
        [username, hashedPassword]
      );
      return res.status(201).json({ message: 'User registered', userId: result.insertId });
    } catch (err) {
      console.error('DB error on register:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Login endpoint: retrieves hash and compares safely
app.post(
  '/login',
  body('username').isAlphanumeric().isLength({ min: 3, max: 30 }),
  body('password').isLength({ min: 8 }),
  handleValidationErrors,
  async (req, res) => {
    const { username, password } = req.body;
    try {
      const [rows] = await pool.execute(
        'SELECT id, password FROM users WHERE username = ?',
        [username]
      );
      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      // TODO: issue JWT or establish session
      return res.json({ message: 'Login successful', userId: user.id });
    } catch (err) {
      console.error('DB error on login:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// Fetch user by ID: validates and parameterizes
app.get(
  '/user/:id',
  param('id').isInt({ min: 1 }),
  handleValidationErrors,
  async (req, res) => {
    const id = parseInt(req.params.id, 10);
    try {
      const [rows] = await pool.execute(
        'SELECT id, username FROM users WHERE id = ?',
        [id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      return res.json(rows[0]);
    } catch (err) {
      console.error('DB error on fetch user:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});