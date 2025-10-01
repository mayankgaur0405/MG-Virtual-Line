require('dotenv').config({ override: true });
const path = require('path');
const express = require('express');
const http = require('http');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const QRCode = require('qrcode');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*'} });

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function normalizeMongoUri(input) {
  let uri = (input || '').trim();
  if (!uri) return 'mongodb://127.0.0.1:27017/mg_virtual_line';
  const hasDb = /mongodb(?:\+srv)?:\/\/[^\s\/]+\/[A-Za-z0-9_.-]+/.test(uri);
  if (!hasDb) {
    const parts = uri.split('?');
    const base = parts[0].replace(/\/?$/, '/mg_virtual_line');
    uri = parts.length > 1 ? `${base}?${parts.slice(1).join('?')}` : base;
  }
  return uri;
}

const MONGO_URI = normalizeMongoUri(process.env.MONGO_URI);
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// Mongo Models
const userSchema = new mongoose.Schema({
  phone: String,
  name: String,
  email: { type: String, unique: true, sparse: true },
  passwordHash: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
});

const vendorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  vendorCode: { type: String, required: true, unique: true },
  currentServing: { type: Number, default: 0 },
  lastIssued: { type: Number, default: 0 },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

const tokenSchema = new mongoose.Schema({
  vendorCode: { type: String, required: true },
  number: { type: Number, required: true },
  status: { type: String, enum: ['waiting', 'served', 'skipped'], default: 'waiting' },
  note: String,
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

const User = mongoose.model('User', userSchema);
const Vendor = mongoose.model('Vendor', vendorSchema);
const Token = mongoose.model('Token', tokenSchema);

// History Model
const historySchema = new mongoose.Schema({
  tokenId: { type: mongoose.Schema.Types.ObjectId, ref: 'Token', required: true, index: true },
  tokenNumber: { type: Number, required: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  vendorCode: { type: String, required: true, index: true },
  vendorName: { type: String },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date },
  adminConfirmed: { type: Boolean, default: false },
  userConfirmed: { type: Boolean, default: false },
  status: { type: String, enum: ['Created', 'Completed'], default: 'Created' },
});

const History = mongoose.model('History', historySchema);

// Auth middleware
function getTokenFromRequest(req) {
  const cookieToken = req.cookies && req.cookies.auth;
  if (cookieToken) return cookieToken;
  const auth = req.get('authorization');
  if (auth && auth.toLowerCase().startsWith('bearer ')) return auth.slice(7);
  return null;
}

function authRequired(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const payload = require('jsonwebtoken').verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

// Auth routes
app.post('/auth/signup', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: 'email already registered' });
    const bcrypt = require('bcryptjs');
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash, name, role: role === 'admin' ? 'admin' : 'user' });
    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('auth', token, { httpOnly: true, sameSite: 'lax', secure: !!process.env.COOKIE_SECURE, maxAge: 7*24*60*60*1000 });
    res.json({ user: { id: user._id, email: user.email, role: user.role, name: user.name } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'invalid credentials' });
    const bcrypt = require('bcryptjs');
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('auth', token, { httpOnly: true, sameSite: 'lax', secure: !!process.env.COOKIE_SECURE, maxAge: 7*24*60*60*1000 });
    res.json({ user: { id: user._id, email: user.email, role: user.role, name: user.name } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/auth/me', (req, res) => {
  const token = getTokenFromRequest(req);
  if (!token) return res.json({ user: null });
  try {
    const payload = require('jsonwebtoken').verify(token, JWT_SECRET);
    res.json({ user: { id: payload.id, email: payload.email, role: payload.role } });
  } catch (e) {
    res.json({ user: null });
  }
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie('auth', { httpOnly: true, sameSite: 'lax', secure: !!process.env.COOKIE_SECURE });
  res.json({ ok: true });
});

// Update user profile
app.post('/auth/updateProfile', authRequired, async (req, res) => {
  try {
    const { name, email, phone } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });
    
    // Check if email is already taken by another user
    const existingUser = await User.findOne({ email, _id: { $ne: req.user.id } });
    if (existingUser) return res.status(409).json({ error: 'email already taken' });
    
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { name, email, phone },
      { new: true }
    );
    
    if (!user) return res.status(404).json({ error: 'user not found' });
    
    res.json({ user: { id: user._id, email: user.email, role: user.role, name: user.name, phone: user.phone } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Socket.io vendor rooms
io.on('connection', (socket) => {
  socket.on('join_vendor', (vendorCode) => {
    if (vendorCode) socket.join(`vendor:${vendorCode}`);
  });
});

// Helpers
async function emitVendorUpdate(vendorCode) {
  const vendor = await Vendor.findOne({ vendorCode });
  const nextWaiting = await Token.findOne({ vendorCode, status: 'waiting' }).sort({ number: 1 });
  io.to(`vendor:${vendorCode}`).emit('vendor_update', {
    vendorCode,
    currentServing: vendor ? vendor.currentServing : 0,
    lastIssued: vendor ? vendor.lastIssued : 0,
    nextWaiting: nextWaiting ? nextWaiting.number : null,
  });
}

// Routes
// Create or get vendor QR (admin)
app.post('/vendor/create', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const existsByName = await Vendor.findOne({ name: { $regex: `^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' } });
    if (existsByName) return res.status(409).json({ error: 'vendor name already exists' });
    const vendorCode = Math.random().toString(36).slice(2, 8).toUpperCase();
    const vendor = await Vendor.create({ name, vendorCode, ownerId: req.user.id });
    const url = `${req.protocol}://${req.get('host')}/user.html?vendor=${vendor.vendorCode}`;
    const qrDataUrl = await QRCode.toDataURL(url);
    res.json({ vendor, url, qrDataUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get vendor QR (for restore)
app.get('/vendor/qr', async (req, res) => {
  try {
    const { vendorCode } = req.query;
    if (!vendorCode) return res.status(400).json({ error: 'vendorCode required' });
    const url = `${req.protocol}://${req.get('host')}/user.html?vendor=${vendorCode}`;
    const qrDataUrl = await QRCode.toDataURL(url);
    res.json({ url, qrDataUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get my vendor (single for MVP)
app.get('/vendor/mine', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const vendor = await Vendor.findOne({ ownerId: req.user.id });
    if (!vendor) return res.json({ vendor: null });
    res.json({ vendor });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// List all vendors owned by this admin
app.get('/vendor/listMine', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const vendors = await Vendor.find({ ownerId: req.user.id }).sort({ name: 1 });
    res.json({ vendors });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Public: check vendor name availability (global, case-insensitive)
app.get('/vendor/checkName', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) return res.status(400).json({ error: 'name required' });
    const exists = await Vendor.findOne({ name: { $regex: `^${String(name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' } });
    res.json({ available: !exists });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Minimal routes required
app.post('/token/create', async (req, res) => {
  try {
    const { vendorCode, note } = req.body;
    const vendor = await Vendor.findOne({ vendorCode });
    if (!vendor) return res.status(404).json({ error: 'vendor not found' });
    const next = vendor.lastIssued + 1;
    vendor.lastIssued = next;
    await vendor.save();
    // Attach userId if cookie session present
    let userId = null;
    try {
      const raw = getTokenFromRequest({ cookies: req.cookies, get: req.get.bind(req) });
      if (raw) {
        const payload = require('jsonwebtoken').verify(raw, JWT_SECRET);
        userId = payload.id;
      }
    } catch(_){}
    const token = await Token.create({ vendorCode, number: next, note, userId });
    await emitVendorUpdate(vendorCode);
    res.json({ token, vendor });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// User: get my latest token for a vendor
app.get('/token/mine', authRequired, async (req, res) => {
  try {
    const { vendorCode } = req.query;
    if (!vendorCode) return res.status(400).json({ error: 'vendorCode required' });
    const token = await Token.findOne({ vendorCode, userId: req.user.id })
      .sort({ createdAt: -1 });
    let vendor = null;
    if (token) vendor = await Vendor.findOne({ vendorCode: token.vendorCode });
    res.json({ token, vendor });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// User: get latest tokens across shops (grouped per vendor)
app.get('/token/mineAll', authRequired, async (req, res) => {
  try {
    const tokens = await Token.find({ userId: req.user.id }).sort({ createdAt: -1 });
    // Group by vendorCode and pick latest per vendor
    const latestByVendor = new Map();
    for (const t of tokens) {
      if (!latestByVendor.has(t.vendorCode)) latestByVendor.set(t.vendorCode, t);
    }
    const vendorCodes = Array.from(latestByVendor.keys());
    const vendors = await Vendor.find({ vendorCode: { $in: vendorCodes } });
    const codeToVendor = new Map(vendors.map(v => [v.vendorCode, v]));
    const items = vendorCodes.map(code => {
      const token = latestByVendor.get(code);
      const vendor = codeToVendor.get(code) || null;
      return { vendorCode: code, vendorName: vendor ? vendor.name : null, vendor, token };
    });
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/token/list', async (req, res) => {
  try {
    const { vendorCode } = req.query;
    if (!vendorCode) return res.status(400).json({ error: 'vendorCode required' });
    const tokens = await Token.find({ vendorCode }).sort({ number: 1 });
    const vendor = await Vendor.findOne({ vendorCode });
    res.json({ tokens, vendor });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Fetch token by id (works for guests too)
app.get('/token/get', async (req, res) => {
  try {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'id required' });
    const token = await Token.findById(id);
    if (!token) return res.status(404).json({ error: 'not found' });
    const vendor = await Vendor.findOne({ vendorCode: token.vendorCode });
    res.json({ token, vendor });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/token/next', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { vendorCode } = req.body;
    const vendor = await Vendor.findOne({ vendorCode });
    if (!vendor) return res.status(404).json({ error: 'vendor not found' });
    const nextWaiting = await Token.findOne({ vendorCode, status: 'waiting' }).sort({ number: 1 });
    if (!nextWaiting) return res.json({ message: 'no waiting tokens' });
    nextWaiting.status = 'served';
    await nextWaiting.save();
    vendor.currentServing = nextWaiting.number;
    await vendor.save();
    // Create or update history entry with status Created when admin advances
    try {
      await History.findOneAndUpdate(
        { tokenId: nextWaiting._id },
        {
          tokenId: nextWaiting._id,
          tokenNumber: nextWaiting.number,
          userId: nextWaiting.userId || null,
          vendorCode: vendorCode,
          vendorName: vendor ? vendor.name : undefined,
          $setOnInsert: { createdAt: new Date() },
          adminConfirmed: false,
          status: 'Created',
        },
        { upsert: true, new: true }
      );
    } catch (_) {}
    await emitVendorUpdate(vendorCode);
    res.json({ served: nextWaiting.number, vendor });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Clear queue but keep shop
app.post('/vendor/clear', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { vendorCode } = req.body;
    const vendor = await Vendor.findOne({ vendorCode });
    if (!vendor) return res.status(404).json({ error: 'vendor not found' });
    await Token.deleteMany({ vendorCode });
    vendor.currentServing = 0;
    vendor.lastIssued = 0;
    await vendor.save();
    await emitVendorUpdate(vendorCode);
    res.json({ ok: true, vendor });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete shop and its tokens
app.post('/vendor/delete', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { vendorCode } = req.body;
    const vendor = await Vendor.findOne({ vendorCode });
    if (!vendor) return res.status(404).json({ error: 'vendor not found' });
    await Token.deleteMany({ vendorCode });
    await History.deleteMany({ vendorCode });
    await vendor.deleteOne();
    io.to(`vendor:${vendorCode}`).emit('vendor_update', { vendorCode, currentServing: 0, lastIssued: 0, nextWaiting: null });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// History: list with optional date filters
app.get('/history/list', authRequired, async (req, res) => {
  try {
    const { start, end, vendorCode } = req.query;
    const query = {};
    // Role-based scoping
    if (req.user.role === 'user') {
      query.userId = req.user.id;
    } else if (req.user.role === 'admin') {
      // Restrict to this admin's vendors
      if (vendorCode) {
        // Check if admin owns this specific vendor
        const myVendor = await Vendor.findOne({ ownerId: req.user.id, vendorCode });
        if (!myVendor) return res.json({ records: [] });
        query.vendorCode = vendorCode;
      } else {
        // Get all vendors owned by this admin
        const myVendors = await Vendor.find({ ownerId: req.user.id });
        const vendorCodes = myVendors.map(v => v.vendorCode);
        if (vendorCodes.length === 0) return res.json({ records: [] });
        query.vendorCode = { $in: vendorCodes };
      }
    }
    if (start || end) {
      query.createdAt = {};
      if (start) query.createdAt.$gte = new Date(start);
      if (end) {
        const d = new Date(end);
        if (!isNaN(d.getTime())) {
          d.setHours(23, 59, 59, 999);
          query.createdAt.$lte = d;
        }
      }
    }
    const records = await History.find(query).sort({ createdAt: -1 });
    res.json({ records });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// History: confirm by role
app.post('/history/confirm', authRequired, async (req, res) => {
  try {
    const { tokenId } = req.body;
    if (!tokenId) return res.status(400).json({ error: 'tokenId required' });
    const hist = await History.findOne({ tokenId });
    if (!hist) return res.status(404).json({ error: 'history not found' });
    if (req.user.role === 'user') {
      if (hist.userId && String(hist.userId) !== String(req.user.id)) return res.status(403).json({ error: 'forbidden' });
      hist.userConfirmed = true;
      if (!hist.userId) hist.userId = req.user.id;
    } else if (req.user.role === 'admin') {
      // Ensure admin owns the vendor
      const myVendor = await Vendor.findOne({ ownerId: req.user.id, vendorCode: hist.vendorCode });
      if (!myVendor) return res.status(403).json({ error: 'forbidden' });
      hist.adminConfirmed = true;
    }
    if (hist.adminConfirmed && hist.userConfirmed) {
      hist.status = 'Completed';
      if (!hist.completedAt) hist.completedAt = new Date();
    }
    await hist.save();
    res.json({ record: hist });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// History: fetch by token
app.get('/history/byToken', authRequired, async (req, res) => {
  try {
    const { tokenId } = req.query;
    if (!tokenId) return res.status(400).json({ error: 'tokenId required' });
    const hist = await History.findOne({ tokenId });
    if (!hist) return res.json({ record: null });
    if (req.user.role === 'user') {
      if (hist.userId && String(hist.userId) !== String(req.user.id)) return res.status(403).json({ error: 'forbidden' });
    } else if (req.user.role === 'admin') {
      const myVendor = await Vendor.findOne({ ownerId: req.user.id, vendorCode: hist.vendorCode });
      if (!myVendor) return res.status(403).json({ error: 'forbidden' });
    }
    res.json({ record: hist });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// History: admin update/edit
// Editing history is disabled by design (immutable records)

// Health
app.get('/health', (req, res) => res.json({ ok: true }));



// SPA fallback
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
  try {
    const safeUri = MONGO_URI.replace(/(mongodb(?:\+srv)?:\/\/)([^:]+):([^@]+)@/i, '$1****:****@');
    console.log(`Connecting to Mongo: ${safeUri}`);
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 });
    const conn = mongoose.connection;
    console.log(`Mongo connected: host=${conn.host} db=${conn.name}`);
    server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  } catch (e) {
    console.error('Mongo connection failed:', e.message);
    process.exit(1);
  }
}

start();


