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

// --- LOGIN (compare hash; auto-upgrade plaintext on first login) ---
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

    email = String(email).toLowerCase().trim();
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const stored = user.password || '';

    // If stored password looks like bcrypt (starts with $2), compare as hash
    const isBcrypt = stored.startsWith('$2');
    let ok = false;

    if (isBcrypt) {
      ok = await bcrypt.compare(String(password), stored);
    } else {
      // Legacy plaintext user: compare plaintext, then upgrade-in-place
      ok = stored === String(password);
      if (ok) {
        try {
          user.password = await bcrypt.hash(String(password), 12);
          await user.save();
          console.log(`🔐 Upgraded plaintext password to bcrypt for ${email}`);
        } catch (e) {
          console.warn(`Password upgrade failed for ${email}:`, e?.message || e);
        }
      }
    }

    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    return res.status(200).json({
      message: 'Login successful',
      user: { id: user._id, email: user.email, fullName: user.fullName },
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
