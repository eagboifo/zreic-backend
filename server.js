const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// ✅ Log all incoming requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ✅ Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ✅ Define a User model (temporary, for demonstration)
const UserSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model('User', UserSchema);

// ✅ Registration endpoint
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

// ✅ Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt:', req.body);

  try {
    const user = await User.findOne({ email, password }); // 🔒 You should hash passwords in production
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

// ✅ Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
