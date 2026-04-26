const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected!'))
  .catch(err => console.log('DB Error:', err));

// ── User Schema ──────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// ── Transaction Schema ───────────────────────────────
const txSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  desc:   String,
  amt:    Number,
  cat:    String,
  date:   String,
  type:   String,
}, { timestamps: true });
const Transaction = mongoose.model('Transaction', txSchema);

// ── Auth Middleware ──────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Register ─────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ error: 'Username already taken' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Login ────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Get Transactions ─────────────────────────────────
app.get('/api/transactions', auth, async (req, res) => {
  const txs = await Transaction.find({ userId: req.user.id })
    .sort({ createdAt: -1 });
  res.json(txs);
});

// ── Add Transaction ───────────────────────────────────
app.post('/api/transactions', auth, async (req, res) => {
  const tx = await Transaction.create({
    ...req.body,
    userId: req.user.id
  });
  res.json(tx);
});

// ── Delete Transaction ────────────────────────────────
app.delete('/api/transactions/:id', auth, async (req, res) => {
  await Transaction.deleteOne({
    _id: req.params.id,
    userId: req.user.id
  });
  res.json({ success: true });
});

app.listen(process.env.PORT || 5000, () => {
  console.log('Server running on port', process.env.PORT || 5000);
});