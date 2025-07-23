// server.js
require('dotenv').config(); // Load environment variables
const express = require('express');
const mysql = require('mysql2'); // Use mysql2 for promise support
const app = express();
app.use(express.json());

// Create a connection pool using environment variables instead of hard-coded credentials
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

app.get('/user', async (req, res) => {
  try {
    // Input validation: ensure id is a positive integer
    const userId = parseInt(req.query.id, 10);
    if (isNaN(userId) || userId < 1) {
      return res.status(400).json({ error: 'Invalid user id provided.' });
    }

    // Parameterized query to prevent SQL injection
    const [rows] = await pool.promise().execute(
      'SELECT id, name, email FROM users WHERE id = ?',
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Database query failed:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});