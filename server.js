// server.js
//
// This is the single Node.js/Express entry point that replaces:
//   - config.php          -> db.js (SQLite connection instead of MySQL)
//   - display.php         -> GET /            (renders views/display.ejs)
//   - login_register.php  -> POST /register, POST /login
//   - logout.php          -> GET /logout
//   - user_page.php       -> GET /user
//   - admin_page.php      -> GET /admin (was referenced by login_register.php but missing from the zip, added here)
//
// Run with:   npm start        (production)
//             npm run devStart (auto-restart with nodemon)

const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./db');
const Database = require('better-sqlite3');
const SqliteStore = require('better-sqlite3-session-store')(session);
const sessionDb = new Database(path.join(__dirname, 'db', 'sessions.db'));

const app = express();
const PORT = process.env.PORT || 3000;

// to get the .env file 
require('dotenv').config();

// ---- View engine (EJS replaces inline PHP templating) ----
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ---- Middleware ----
app.use(express.urlencoded({ extended: true })); // parse HTML form posts
app.use(express.static(path.join(__dirname, 'public'))); // serves style.css, script.js

app.use(session({
   store: new SqliteStore({
       client: sessionDb,
       expired: {
         clear: true,
         intervalMs: 1000 * 60 * 60 * 2 // clean up expired sessions every 2 hours
       }
     }),
  secret: process.env.SESSION_SECRET || 'cd431c6709305d2d2d17951d0800b34fe728c40a322af6b0c1984385ffc68d0f',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 2 // 2 hours 
  }
}));


function flash(req, key) {
  const val = req.session[key];
  delete req.session[key];
  return val || '';
}


app.get('/', (req, res) => {
  res.render('display', {
    loginError: flash(req, 'login_error'),
    registerError: flash(req, 'register_error'),
    activeForm: flash(req, 'active_form') || 'login'
  });
});


// ---------------------------------------------------------------------
// GET /logout 
// ---------------------------------------------------------------------
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// ---- Auth guard, same idea as the isset($_SESSION['email']) check ----
function requireLogin(role) {
  return (req, res, next) => {
    if (!req.session.userId) return res.redirect('/');
    if (role && req.session.role !== role) return res.redirect('/');
    next();
  };
}

// ---------------------------------------------------------------------
// GET /user -> replaces user_page.php
// ---------------------------------------------------------------------
app.get('/user', requireLogin('user'), (req, res) => {
  res.render('user_page', { name: req.session.name });
});

// ---------------------------------------------------------------------
// GET /admin -> replaces the missing admin_page.php that login_register.php
// used to redirect to
// ---------------------------------------------------------------------
app.get('/admin', requireLogin('admin'), (req, res) => {
  res.render('admin_page', { name: req.session.name });
});


app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    req.session.register_error = 'All fields are required.';
    req.session.active_form = 'register';
    return res.redirect('/');
  }

  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);

    if (existing) {
      req.session.register_error = 'Email is already registered!';
      req.session.active_form = 'register';
      return res.redirect('/');
    } 

    // bcrypt instead of PHP's password_hash() - same idea, salted hash.
    const hashedPassword = await bcrypt.hash(password, 10);

    db.prepare(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)'
    ).run(name, email, hashedPassword, role);

    req.session.active_form = 'login';
    return res.redirect('/');
  } catch (err) {
    console.error('Register error:', err);
    req.session.register_error = 'Something went wrong. Please try again.';
    req.session.active_form = 'register';
    return res.redirect('/');
  }
});


// ---------------------------------------------------------------------
// POST /login -> replaces the login half of login_register.php
// ---------------------------------------------------------------------
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.userId = user.id;
      req.session.name = user.name;
      req.session.email = user.email;
      req.session.role = user.role;

      return res.redirect(user.role === 'admin' ? '/admin' : '/user');
    }

    req.session.login_error = 'Incorrect email or password';
    req.session.active_form = 'login';
    return res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    req.session.login_error = 'Something went wrong. Please try again.';
    req.session.active_form = 'login';
    return res.redirect('/');
  }
});



app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
