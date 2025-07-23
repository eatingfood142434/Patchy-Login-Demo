// server.js
const express = require('express');
const mysql = require('mysql2'); // mysql2 supports prepared statements
require('dotenv').config();

const app = express();
app.use(express.json());

// Connection pool using credentials from environment variables
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

/**
 * GET /user?id=<userId>
 * Retrieves a user by ID using a parameterized query to prevent SQL injection.
 */
app.get('/user', (req, res) => {
  // Input validation: ensure id is an integer
  const userId = parseInt(req.query.id, 10);
  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid or missing user ID' });
  }

  const sql = 'SELECT id, username, email, created_at FROM users WHERE id = ?';
  // Use parameterized query (prepared statement)
  db.execute(sql, [userId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    // Return only selected columns
    return res.json(results[0]);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});