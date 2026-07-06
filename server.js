require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*'
}
});

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Redirect to landing page on root
app.get('/', (req, res) => {
  res.redirect('/index.html');
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Force HTTPS in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure && req.get('x-forwarded-proto') !== 'https') {
    return res.redirect('https://' + req.get('host') + req.url);
  }
  next();
});

const PORT = process.env.PORT || 3000;
const ADMIN_USERNAMES = (process.env.ADMIN_USERNAMES || '').split(',').map(u => u.trim().toLowerCase()).filter(Boolean);

// Sessions with 24-hour expiration
const sessions = new Map();
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

// CSRF tokens - one per user session
const csrfTokens = new Map();

function generateCSRFToken() {
  return crypto.randomBytes(24).toString('hex');
}

// Rate limiting for login attempts
const loginAttempts = new Map();

function checkLoginAttempts(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const attempts = (loginAttempts.get(ip) || []).filter(t => now - t < windowMs);

  if (attempts.length >= 5) {
    return false;
  }

  attempts.push(now);
  loginAttempts.set(ip, attempts);
  return true;
}

// Signup throttle
const signupAttempts = new Map();
function tooManySignups(ip) {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const attempts = (signupAttempts.get(ip) || []).filter(t => now - t < windowMs);
  attempts.push(now);
  signupAttempts.set(ip, attempts);
  return attempts.length > 5;
}

// Input validation
function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;
  if (username.length < 3 || username.length > 20) return false;
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) return false;
  return true;
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;
  if (password.length < 8) return false;
  return true;
}

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

async function getUserFromToken(token) {
  const session = sessions.get(token);
  if (!session) return null;

  // Check if session expired (24 hours)
  if (Date.now() - session.createdAt > SESSION_TIMEOUT) {
    sessions.delete(token); // Remove expired session
    return null;
  }

  const result = await pool.query('SELECT * FROM users WHERE id = $1', [session.userId]);
  return result.rows[0] || null;
}

async function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  const user = token ? await getUserFromToken(token) : null;
  if (!user) return res.status(401).json({ error: 'Not logged in.' });
  if (user.suspended) return res.status(403).json({ error: 'Account suspended.' });
  req.user = user;
  req.token = token;
  next();
}

// CSRF validation middleware
function verifyCsrfToken(req, res, next) {
  const csrf = req.headers['x-csrf-token'];
  const token = req.headers['x-auth-token'];
  const expectedCsrf = csrfTokens.get(token);

  if (!csrf || !expectedCsrf || csrf !== expectedCsrf) {
    return res.status(403).json({ error: 'CSRF token invalid.' });
  }

  next();
}

// Auth routes
app.post('/api/signup', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (tooManySignups(ip)) {
      return res.status(429).json({ error: 'Too many signups. Try again later.' });
    }

    const { username, password, ageConfirmed } = req.body;

    if (!ageConfirmed) {
      return res.status(400).json({ error: 'You must confirm you are 18 or older.' });
    }

    if (!validateUsername(username)) {
      return res.status(400).json({ error: 'Username: 3-20 chars, letters/numbers/underscore only.' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Username taken.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const isAdmin = ADMIN_USERNAMES.includes(username.toLowerCase());

    const result = await pool.query(
  `INSERT INTO users
  (username, password_hash, is_admin, display_name, bio, avatar_url)
  VALUES ($1, $2, $3, $4, $5, $6)
  RETURNING id, username, is_admin, display_name, bio, avatar_url`,
  [
    username,
    passwordHash,
    isAdmin,
    username,      // default display name
    '',            // empty bio
    ''             // no avatar yet
  ]
);
   
    const user = result.rows[0];
    const token = makeToken();
    const csrfToken = generateCSRFToken();

    sessions.set(token, {
      userId: user.id,
      createdAt: Date.now()
    });
    csrfTokens.set(token, csrfToken);

    res.json({
      token,
      username: user.username,
      isAdmin: user.is_admin,
      csrfToken
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Check rate limit
    if (!checkLoginAttempts(ip)) {
      return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
    }

    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username || '']);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password || '', user.password_hash))) {
      return res.status(401).json({ error: 'Wrong username or password.' });
    }
    if (user.suspended) {
      return res.status(403).json({ error: 'Account suspended.' });
    }
    const token = makeToken();
    const csrfToken = generateCSRFToken();

    sessions.set(token, {
      userId: user.id,
      createdAt: Date.now()
    });
    csrfTokens.set(token, csrfToken);

    res.json({
      token,
      username: user.username,
      isAdmin: user.is_admin,
      csrfToken
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/logout', verifyCsrfToken, (req, res) => {
  const token = req.headers['x-auth-token'];
  sessions.delete(token);
  csrfTokens.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    username: req.user.username,
    isAdmin: req.user.is_admin,
    csrfToken: csrfTokens.get(req.token)
  });
});

app.get('/api/rooms', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT slug, name FROM rooms ORDER BY sort_order');
  res.json(result.rows);
});
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({
    username: req.user.username,
    display_name: req.user.display_name,
    bio: req.user.bio,
    avatar_url: req.user.avatar_url,
    created_at: req.user.created_at
  });
});

app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { display_name, bio, avatar_url } = req.body;

    const result = await pool.query(
      `UPDATE users
       SET display_name = $1,
           bio = $2,
           avatar_url = $3
       WHERE id = $4
       RETURNING display_name, bio, avatar_url`,
      [
        (display_name || '').substring(0, 30),
        (bio || '').substring(0, 250),
        avatar_url || '',
        req.user.id
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update profile.' });
  }
});
// Socket.io chat
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  const user = token ? await getUserFromToken(token) : null;
  if (!user) return next(new Error('unauthorized'));
  if (user.suspended) return next(new Error('suspended'));
  socket.user = user;
  socket.token = token;
  next();
});

const lastMessageAt = new Map();
const messageCountToday = new Map();

io.on('connection', (socket) => {
  socket.on('join_room', async (roomSlug) => {
    socket.join(roomSlug);
    const result = await pool.query(
      'SELECT id, username, content, created_at FROM messages WHERE room_slug = $1 AND hidden = FALSE ORDER BY created_at DESC LIMIT 30',
      [roomSlug]
    );
    socket.emit('room_history', result.rows.reverse());
  });

  socket.on('send_message', async ({ roomSlug, content }) => {
    try {
      content = (content || '').slice(0, 1000);
      if (!content) {
        return;
      }

      const user = socket.user;
      if (!user) {
        socket.emit('chat_error', 'Message failed.');
        return;
      }

      // Rate limiting - prevent rapid messages
      const now = Date.now();
      if ((now - (lastMessageAt.get(user.id) || 0)) < 1000) {
        socket.emit('chat_error', 'Sending too fast.');
        return;
      }
      lastMessageAt.set(user.id, now);

      // Check daily message limit (100 per day)
      const today = new Date().toDateString();
      const countKey = `${user.id}:${today}`;
      const count = messageCountToday.get(countKey) || 0;

      if (count >= 100) {
        socket.emit('chat_error', 'Daily message limit reached (100). Try again tomorrow.');
        return;
      }

      messageCountToday.set(countKey, count + 1);

      const msgResult = await pool.query(
        'INSERT INTO messages (room_slug, user_id, username, content) VALUES ($1, $2, $3, $4) RETURNING id, created_at',
        [roomSlug, user.id, user.username, content]
      );

      io.to(roomSlug).emit('new_message', {
        username: user.username,
        content,
        created_at: msgResult.rows[0].created_at
      });
    } catch (err) {
      console.error(err);
      socket.emit('chat_error', 'Message failed.');
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Admins: ${ADMIN_USERNAMES.join(', ') || 'none'}`);
});