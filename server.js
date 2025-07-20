// server.js
const express = require('express');
const mysql = require('mysql2'); // use mysql2 for promises and prepared statements
require('dotenv').config();

const app = express();
app.use(express.json());

// Create a pooled connection using environment variables for credentials
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}).promise();

// GET /user?id=123
app.get('/user', async (req, res) => {
  try {
    const userId = req.query.id;
    // Input validation: ensure it's a positive integer
    if (!/^[0-9]+$/.test(userId)) {
      return res.status(400).json({ error: 'Invalid user id' });
    }

    // Parameterized query to prevent SQL injection
    const sql = 'SELECT * FROM users WHERE id = ?';
    const [rows] = await pool.execute(sql, [userId]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));