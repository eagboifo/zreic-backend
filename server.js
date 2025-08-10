// server.js (production‑ready)
try { require('dotenv').config(); } catch (_) {}

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();

// --- CORS (added) ---
const FRONTEND_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://zreic-portal-git-main-emmanuel-agboifos-projects.vercel.app',
  'https://zreic-portal.vercel.app',
];

// help caches/CDNs vary by Origin
app.use((req, res, next) => { res.setHeader('Vary', 'Origin'); next(); });

app.use(
  cors({
    origin(origin, cb) {
      // allow same-origin / non-browser tools (no Origin header)
      if (!origin) return cb(null, true);
      if (FRONTEND_ORIGINS.includes(origin) || /\.vercel\.app$/.test(origin)) return cb(null, true);
      return cb(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    // credentials: false, // leave false unless you use cookies
    maxAge: 600, // cache preflight 10 minutes
  })
);

// ensure preflights succeed
app.options('*', cors());


// ✅ helper to sign JWT tokens
function signToken(user) {
  return jwt.sign(
    { sub: String(user._id), role: user.role || 'user' },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES || '2h' }
  );
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    req.auth = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// --- GET current logged-in user ---
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.auth.sub).lean();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { _id, fullName, email, role, createdAt, updatedAt } = user;
    res.json({ id: _id, fullName, email, role, createdAt, updatedAt });
  } catch (err) {
    console.error('Error fetching current user:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// --- UPDATE PROFILE (fullName/email) ---
app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    let { fullName, email } = req.body || {};
    if (!fullName && !email) {
      return res.status(400).json({ error: 'Nothing to update' });
    }

    const updates = {};
    if (fullName) updates.fullName = String(fullName).trim();

    if (email) {
      email = String(email).toLowerCase().trim();
      // block duplicates
      const exists = await User.findOne({ email, _id: { $ne: req.auth.sub } }).lean();
      if (exists) return res.status(409).json({ error: 'Email already in use' });
      updates.email = email;
    }

    const user = await User.findByIdAndUpdate(req.auth.sub, updates, { new: true }).lean();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { _id, role } = user;
    return res.json({
      message: 'Profile updated',
      user: { id: _id, fullName: user.fullName, email: user.email, role }
    });
  } catch (err) {
    console.error('Profile update error:', err);
    return res.status(500).json({ error: 'Update failed' });
  }
});

// --- CHANGE PASSWORD (verify old → set new hashed) ---
app.put('/api/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'currentPassword and newPassword are required' });
    }
    if (String(newPassword).length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    const user = await User.findById(req.auth.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(String(currentPassword), user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid current password' });

    user.password = await bcrypt.hash(String(newPassword), 12);
    await user.save();

    return res.json({ message: 'Password updated' });
  } catch (err) {
    console.error('Password update error:', err);
    return res.status(500).json({ error: 'Password update failed' });
  }
});


// ----- Env & DB -----
const RAW_URI = process.env.MONGO_URI || process.env.MONGODB_URI || null;
const masked = RAW_URI ? RAW_URI.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:****@') : RAW_URI;
console.log('🔎 MONGO_URI present?', RAW_URI ? 'yes' : 'no', '| masked:', masked ?? 'undefined');
if (!RAW_URI) {
  console.error('❌ Missing MONGO_URI (or MONGODB_URI). Exiting.');
  process.exit(1);
}

mongoose.set('strictQuery', true);
mongoose.connect(RAW_URI, {
  dbName: process.env.MONGO_DB_NAME || 'zreic_db',
}).then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => { console.error('❌ Mongo error:', err?.message || err); process.exit(1); });

// ----- CORS -----
// ----- CORS -----
const ALLOWED_ORIGINS = [
  'http://localhost:5173', // Dev
];

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // Allow curl/Postman with no origin

    // Allow any *.vercel.app frontend
    if (origin.endsWith('.vercel.app') || ALLOWED_ORIGINS.includes(origin)) {
      return cb(null, true);
    }

    return cb(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: false,
}));


// ----- Middleware -----
app.use(express.json());
app.use((req, _res, next) => { console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`); next(); });

// ----- Minimal model (demo) -----
const UserSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true, index: true },
  password: String, // TODO: hash in production
});
const User = mongoose.model('User', UserSchema);

// ----- Routes -----
app.get('/', (_req, res) => {
  res.json({ ok: true, service: 'zreic-backend', routes: ['GET /api/health', 'POST /api/register', 'POST /api/login'] });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// --- REGISTER (hash password before save) ---
app.post('/api/register', async (req, res) => {
  try {
    let { fullName, email, password } = req.body || {};
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'fullName, email and password are required' });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    email = String(email).toLowerCase().trim();

    const exists = await User.findOne({ email }).lean();
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(String(password), 12);
    const newUser = await User.create({
      fullName: String(fullName).trim(),
      email,
      password: hash, // store hash, not plaintext
    });

    return res.status(201).json({
      message: 'User registered successfully',
      user: { id: newUser._id, fullName: newUser.fullName, email: newUser.email },
    });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'User registration failed' });
  }
});


// --- LOGIN (compare plaintext with stored hash) ---
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    email = String(email).toLowerCase().trim();

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const ok = await bcrypt.compare(String(password), user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = signToken(user); // ✅ added

    return res.status(200).json({
      message: 'Login successful',
      token, // ✅ added
      user: { id: user._id, fullName: user.fullName, email: user.email },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});



// JSON 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.originalUrl, method: req.method });
});

// ----- Start -----
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
