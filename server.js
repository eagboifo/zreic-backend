// Load env FIRST and safely log presence of MONGO_URI
try { require('dotenv').config(); } catch (_) { /* ok on Render without .env */ }

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();

// --- Safe startup check for the DB URI (masks password) ---
const RAW_URI = process.env.MONGO_URI || process.env.MONGODB_URI || null;
const masked = RAW_URI ? RAW_URI.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:****@') : RAW_URI;
console.log('🔎 MONGO_URI present?', RAW_URI ? 'yes' : 'no', '| value (masked):', masked ?? 'undefined');

if (!RAW_URI) {
  console.error('❌ Missing MONGO_URI (or MONGODB_URI) in environment. Exiting early.');
  process.exit(1);
}

// --- Connect to MongoDB Atlas ---
mongoose.set('strictQuery', true);
mongoose.connect(RAW_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  // If your URI already includes /zreic_db you can remove dbName. Otherwise this ensures a DB is used.
  dbName: process.env.MONGO_DB_NAME || 'zreic_db',
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err?.message || err);
  process.exit(1);
});

// --- Middleware ---
app.use(cors());
app.use(express.json());

// Log all incoming requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// --- Temporary model for testing ---
const UserSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  password: String, // ⚠️ hash in production
});
const User = mongoose.model('User', UserSchema);

// --- Routes ---
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Registration
app.post('/api/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  console.log('Received registration:', req.body);

  try {
    const newUser = new User({ fullName, email, password });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully', user: { fullName, email } });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'User registration failed' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt:', req.body);

  try {
    const user = await User.findOne({ email, password }); // ⚠️ hash in production
    if (user) {
      res.status(200).json({ message: 'Login successful', user: { email } });
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// --- Start server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
