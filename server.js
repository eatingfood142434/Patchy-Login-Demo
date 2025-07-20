require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');

const app = express();
app.use(express.json());

// Create a MySQL connection pool with parameterized queries support
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware: validate incoming request parameters
function validateRequest(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

// Middleware: authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// User registration endpoint
app.post("/register",
  body('email').isEmail(),
  body('password').isLength({ min: 8 }),
  validateRequest,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      // Hash the password before storing
      const hashedPassword = await bcrypt.hash(password, 12);

      const [result] = await pool.execute(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword]
      );
      res.status(201).json({ userId: result.insertId });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// User login endpoint
app.post(
  '/login',
  body('email').isEmail(),
  body('password').isString(),
  validateRequest,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const [rows] = await pool.execute(
        'SELECT id, password FROM users WHERE email = ?',
        [email]
      );

      if (rows.length === 0) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const user = rows[0];
      // Compare hashed password
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Create JWT token
      const token = jwt.sign(
        { userId: user.id, email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({ token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Protected endpoint: fetch user data by ID
app.get(
  '/user/:id',
  authenticateToken,
  param('id').isInt({ min: 1 }),
  validateRequest,
  async (req, res) => {
    try {
      // Only allow access to own data
      if (req.user.userId !== parseInt(req.params.id, 10)) {
        return res.sendStatus(403);
      }

      const [rows] = await pool.execute(
        'SELECT id, email, created_at FROM users WHERE id = ?',
        [req.params.id]
      );

      if (rows.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json(rows[0]);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));