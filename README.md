# SQL Injection Vulnerable Login Demo

⚠️ **WARNING: This application is intentionally vulnerable for educational purposes only!**

This demo shows how SQL injection attacks work and should NEVER be used in production.

## Setup

1. Install Node.js if you haven't already
2. Install dependencies:
   ```
   npm install
   ```
3. Run the application:
   ```
   npm start
   ```
4. Open your browser to: http://localhost:3000

## How to Test SQL Injection

### Method 1: Classic `' OR 1=1--`
- **Username:** `' OR 1=1--`
- **Password:** `anything`

### Method 2: Alternative injection
- **Username:** `admin' OR '1'='1' --`
- **Password:** `anything`

### Valid Credentials (for comparison)
- admin / secretpassword
- user1 / password123  
- testuser / mypassword

## How It Works

The vulnerability exists in the server.js file where user input is directly concatenated into the SQL query:

```javascript
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

When you input `' OR 1=1--`, the query becomes:
```sql
SELECT * FROM users WHERE username = '' OR 1=1--' AND password = 'anything'
```

The `--` comments out the rest of the query, and `1=1` is always true, so it returns all users.

## What You'll Learn

- How SQL injection vulnerabilities work
- Why parameterized queries are important
- How attackers can bypass authentication
- The importance of input validation and sanitization

## Security Note

🚨 **NEVER deploy this code to production!** This is for educational purposes only.

In real applications, always use:
- Parameterized queries/prepared statements
- Input validation and sanitization
- Proper authentication mechanisms
- Security frameworks and libraries
