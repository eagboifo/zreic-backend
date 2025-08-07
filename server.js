const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// ✅ Add this middleware to log all incoming requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.post('/api/register', (req, res) => {
  const { fullName, email, password } = req.body;
  console.log('Received registration:', req.body);

  // Simulate saving to DB
  res.status(201).json({ message: 'User registered successfully', user: { fullName, email } });
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt:', req.body);

  // Simulated login check (replace with DB lookup in real app)
  if (email === 'zoobee@example.com' && password === 'secure123') {
    res.status(200).json({ message: 'Login successful', user: { email } });
  } else {
    res.status(401).json({ error: 'Invalid email or password' });
  }
});

