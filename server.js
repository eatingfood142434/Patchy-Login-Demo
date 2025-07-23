// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();

// Security middleware
app.use(helmet());                          // Set secure HTTP headers
app.use(express.json());                  // Parse JSON bodies
app.use(express.urlencoded({extended:false}));

// Create a connection pool with credentials stored in environment variables
const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Session management with MySQL store
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    store: new MySQLStore({}, dbPool),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    }
  })
);

// Input validation chains
const registerValidation = [
  body('username').isAlphanumeric().isLength({min:3, max:30}),
  body('password').isStrongPassword({minLength:8})
];

const loginValidation = [
  body('username').exists(),
  body('password').exists()
];

// User registration route
app.post('/register', registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({errors: errors.array()});
  }

  const { username, password } = req.body;
  try {
    // Hash password before storing
    const hashed = await bcrypt.hash(password, 12);
    // Parameterized query to prevent SQL injection
    await dbPool.execute(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, hashed]
    );
    res.status(201).send('User registered successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// User login route
app.post('/login', loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({errors: errors.array()});
  }

  const { username, password } = req.body;
  try {
    // Fetch user row using parameterized query
    const [rows] = await dbPool.execute(
      'SELECT id, password_hash FROM users WHERE username = ?',
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = rows[0];
    // Compare submitted password with stored hash
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).send('Invalid credentials');
    }

    // Establish session
    req.session.userId = user.id;
    res.send('Login successful');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Middleware to protect routes
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.status(401).send('Unauthorized');
}

// Protected data endpoint
app.get('/data', isAuthenticated, async (req, res) => {
  try {
    // Use parameterized query, filter by current user
    const [rows] = await dbPool.execute(
      'SELECT * FROM data WHERE user_id = ?',
      [req.session.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Logout route
app.post('/logout', isAuthenticated, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Could not log out');
    }
    res.clearCookie('connect.sid');
    res.send('Logout successful');
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));