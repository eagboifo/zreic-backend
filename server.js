// server.js (production‑ready)
try { require('dotenv').config(); } catch (_) {}

const express = require('express');
const cors = require('cors');
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
mongoose.connect(RAW_URI, {
  dbName: process.env.MONGO_DB_NAME || 'zreic_db',
}).then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => { console.error('❌ Mongo error:', err?.message || err); process.exit(1); });

// ----- CORS -----
const ALLOWED_ORIGINS = [
  'https://YOUR-FRONTEND-DOMAIN',  // ← replace with your Vercel origin
  'http://localhost:5173',         // dev (optional)
];

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);                 // allow curl/postman
    return ALLOWED_ORIGINS.includes(origin)
      ? cb(null, true)
      : cb(new Error('Not allowed by CORS'));
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

app.post('/api/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    const newUser = new User({ fullName, email, password }); // TODO: hash password
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully', user: { fullName, email } });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    console.error('Registration error:', err);
    res.status(500).json({ error: 'User registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email, password }); // TODO: compare hashed password
    if (user) return res.status(200).json({ message: 'Login successful', user: { email } });
    res.status(401).json({ error: 'Invalid email or password' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// JSON 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.originalUrl, method: req.method });
});

// ----- Start -----
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
