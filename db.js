// db.js
// Sets up a local SQLite database (users.db) and the "users" table.
// This replaces the old PHP config.php, which connected to a MySQL
// database called "users_db" using mysqli.


const path = require('path');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, 'db', 'users.db'));

// Create the users table if it doesn't exist yet (equivalent of your
// old MySQL "users" table: name, email, password, role).
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

module.exports = db;
