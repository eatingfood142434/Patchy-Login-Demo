const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const port = 3001;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');

// Create users table and insert sample data
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )`);
    
    // Insert sample users
    db.run("INSERT INTO users (username, password) VALUES ('admin', 'secretpassword')");
    db.run("INSERT INTO users (username, password) VALUES ('user1', 'password123')");
    db.run("INSERT INTO users (username, password) VALUES ('testuser', 'mypassword')");
});

// Serve the login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// VULNERABLE LOGIN ENDPOINT - DO NOT USE IN PRODUCTION!
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABLE SQL QUERY - Directly interpolating user input!
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log('Executing query:', query); // For demonstration purposes
    
    db.get(query, (err, row) => {
        if (err) {
            console.error('Database error:', err);
            res.status(500).json({ 
                success: false, 
                message: 'Database error occurred',
                error: err.message 
            });
            return;
        }
        
        if (row) {
            res.json({ 
                success: true, 
                message: 'Login successful!', 
                user: { id: row.id, username: row.username }
            });
        } else {
            res.json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
    });
});

// Get all users (for demonstration)
app.get('/users', (req, res) => {
    db.all("SELECT id, username FROM users", (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

app.listen(port, () => {
    console.log(`Vulnerable login demo running at http://localhost:${port}`);
    console.log('');
    console.log('🚨 WARNING: This application is intentionally vulnerable!');
    console.log('For educational purposes only - DO NOT use in production!');
    console.log('');
    console.log('Try SQL injection with: \' OR 1=1--');
    console.log('Or try: admin\' OR \'1\'=\'1\' --');
});
