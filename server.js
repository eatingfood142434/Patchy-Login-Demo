// Load environment variables from .env file (make sure .env is not checked into source control)
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Create a MySQL connection pool using environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// GET /users/:id  -> Retrieve a user by ID
app.get('/users/:id', (req, res) => {
  const id = req.params.id;

  // Input validation: allow only positive integers for user ID
  if (!/^[0-9]+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  // Parameterized query to prevent SQL injection
  const sql = 'SELECT id, name, email FROM users WHERE id = ?';
  pool.execute(sql, [id], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Return only the first matching record
    res.json(results[0]);
  });
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});