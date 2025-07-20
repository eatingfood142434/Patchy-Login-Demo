require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expressjwt: jwtMiddleware } = require('express-jwt');

const app = express();
app.use(express.json());

// Load DB config from environment
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
};

// Ensure JWT secret is set
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in environment');
  process.exit(1);
}

// JWT authentication middleware
const authenticate = jwtMiddleware({ secret: JWT_SECRET, algorithms: ['HS256'] });

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || typeof username !== 'string' || !password) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    // Hash password with bcrypt
    const hashedPassword = await bcrypt.hash(password, 12);
    const conn = await mysql.createConnection(dbConfig);
    // Parameterized query to prevent SQL injection
    await conn.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );
    await conn.end();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || typeof username !== 'string' || !password) {
      return res.status(400).json({ error: 'Invalid input' });
    }
    const conn = await mysql.createConnection(dbConfig);
    // Use prepared statement to fetch user by username
    const [rows] = await conn.execute(
      'SELECT id, password, role FROM users WHERE username = ?',
      [username]
    );
    await conn.end();

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Authentication failed' });
    }

    const user = rows[0];
    // Compare stored hash to provided password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Authentication failed' });
    }

    // Sign a JWT with user ID and role
    const token = jwt.sign(
      { sub: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Protected endpoint to get user info
app.get('/users/:id', authenticate, async (req, res) => {
  try {
    const requestedId = parseInt(req.params.id, 10);
    // Authorization: allow if user is self or has admin role
    if (req.auth.sub !== requestedId && req.auth.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute(
      'SELECT id, username, role FROM users WHERE id = ?',
      [requestedId]
    );
    await conn.end();

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to retrieve user' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));