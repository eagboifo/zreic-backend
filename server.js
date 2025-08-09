// server.js (production‑ready, hardened)
try { require('dotenv').config(); } catch (_) {}

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();

// ----- Env & DB -----
const RAW_URI = process.env.MONGO_URI || process.env.MONGODB_URI || null;
const masked = RAW_URI ? RAW_URI.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:****@') : RAW_URI;
console.log('🔎 MONGO_URI present?', RAW_URI ? 'yes' : 'no', '| masked:', masked ?? 'undefined');
if (!RAW_URI) {
  console.error('❌ Missing MONGO_URI (or MONGODB_URI). Exiting.');
  process.exit(1);
}

mongoose.set('strictQuery', true);
mongoose
  .connect(RAW_URI, { dbName: process.env.MONGO_DB_NAME || 'zreic_db' })
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => {
    console.error('❌ Mongo error:', err?.message || err);
    process.exit(1);
  });

// ----- CORS (env‑driven allow‑list) -----
const envOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const ALLOWED_ORIGINS = envOrigins.length
  ? envOrigins
  : [
      // Defaults: replace with your real Vercel domain when known,
      // or set ALLOWED_ORIGINS in the Render dashboard.
      'https://YOUR-FRONTEND-DOMAIN', // e.g., https://zreic-frontend.vercel.app
      'http://localhost:5173',
    ];

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // allow curl/postman
      return ALLOWED_ORIGINS.includes(origin)
        ? cb(null, true)
        : cb(new Error('Not allowed by CORS'));
    },
    credentials: false,
  })
);

// ----- Security & basics -----
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// Basic rate limit (adjust as needed)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Request logging
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ----- User model -----
const UserSchema = new mongoose.Schema(
  {
    fullName: { type: String, trim: true },
    email: { type: String, unique: true, index: true, lowercase: true, trim: true },
    password: { type: String }, // stored as bcrypt hash
  },
  { timestamps: true }
);
const User = mongoose.model('User', UserSchema);

// ----- Routes -----
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'zreic-backend',
    routes: ['GET /api/health', 'POST /api/register', 'POST /api/login'],
    corsAllowed: ALLOWED_ORIGINS,
  });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

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

    const hash = await bcrypt.hash(password, 12);
    const newUser = await User.create({ fullName: String(fullName).trim(), email, password: hash });

    return res
      .status(201)
      .json({ message: 'User registered successfully', user: { id: newUser._id, fullName: newUser.fullName, email: newUser.email } });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'User registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

    email = String(email).toLowerCase().trim();
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(String(password), user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    return res.status(200).json({ message: 'Login successful', user: { id: user._id, email: user.email, fullName: user.fullName } });
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
