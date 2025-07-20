// server.js
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('Missing SESSION_SECRET in environment.');
  process.exit(1);
}

// In-memory SQLite DB
const db = new sqlite3.Database(':memory:');

// Middleware
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: true,
    maxAge: 60 * 60 * 1000 // 1 hour
  }
}));

// Initialize users table and seed a test user
const initDb = async () => {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
      )`
    );

    // Seed user with hashed password (password: Password123!)
    const testUsername = 'testuser';
    const testPassword = 'Password123!';
    bcrypt.hash(testPassword, 12, (err, hash) => {
      if (err) throw err;
      db.run(
        'INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)',
        [testUsername, hash]
      );
    });
  });
};

initDb();

// Registration endpoint
app.post(
  '/register',
  [
    body('username').isAlphanumeric().isLength({ min: 3, max: 20 }),
    body('password').isLength({ min: 8 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const passwordHash = await bcrypt.hash(password, 12);

    const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
    stmt.run(username, passwordHash, function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
    });
    stmt.finalize();
  }
);

// Login endpoint
app.post(
  '/login',
  [
    body('username').isAlphanumeric(),
    body('password').isLength({ min: 8 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Use parameterized query to prevent SQL injection
    db.get(
      'SELECT id, password_hash FROM users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        if (!row) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Compare hashed passwords
        bcrypt.compare(password, row.password_hash, (err, match) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Internal server error' });
          }
          if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
          }

          // Regenerate session ID to prevent fixation
          req.session.regenerate((err) => {
            if (err) console.error(err);
            req.session.userId = row.id;
            res.json({ message: 'Login successful' });
          });
        });
      }
    );
  }
);

// Protected endpoint example
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/profile', requireAuth, (req, res) => {
  db.get(
    'SELECT id, username FROM users WHERE id = ?',
    [req.session.userId],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json({ profile: row });
    }
  );
});

// Logout endpoint
app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('sid');
    res.json({ message: 'Logged out' });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});