import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { Sequelize, DataTypes } from 'sequelize';
import bcrypt from 'bcrypt';

dotenv.config();
const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// Rate limiting
const limiter = rateLimit({ windowMs: 15*60*1000, max: 200 });
app.use(limiter);

// DB setup -- supports sqlite (demo) or postgres (production with DATABASE_URL)
const dialect = process.env.DB_DIALECT || 'sqlite';
const sequelize = new Sequelize(process.env.DATABASE_URL || './millo_pay_demo.sqlite', {
  dialect,
  logging: false,
});

// Models
const User = sequelize.define('User', {
  name: { type: DataTypes.STRING },
  email: { type: DataTypes.STRING, unique: true },
  passwordHash: { type: DataTypes.STRING },
}, { timestamps: true });

const Transaction = sequelize.define('Transaction', {
  userId: { type: DataTypes.INTEGER },
  amount: { type: DataTypes.FLOAT },
  cardEncrypted: { type: DataTypes.TEXT },
  status: { type: DataTypes.STRING },
  ip: { type: DataTypes.STRING },
  flagged: { type: DataTypes.BOOLEAN, defaultValue: false },
}, { timestamps: true });

// Simple helpers
const AES_KEY = process.env.AES_KEY || '0123456789abcdef0123456789abcdef'; // 32 chars for demo
function encrypt(text){
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(AES_KEY), iv);
  const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}
function decrypt(enc){
  const data = Buffer.from(enc, 'base64');
  const iv = data.slice(0,16);
  const tag = data.slice(16,32);
  const encrypted = data.slice(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(AES_KEY), iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

// Auth middleware
function authenticate(req,res,next){
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({ error: 'Missing token' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'please_change');
    req.user = payload;
    next();
  } catch(e){
    return res.status(403).json({ error: 'Invalid token' });
  }
}

// Basic fraud detection rules
async function detectFraud(userId, amount, ip){
  // rules:
  // - single tx > 10000 flagged
  // - more than 3 txs in last minute flagged
  const large = amount > 10000;
  const since = new Date(Date.now() - 60*1000);
  const recent = await Transaction.count({ where: { userId, createdAt: { [Sequelize.Op.gt]: since } } });
  const burst = recent >= 3;
  const flagged = large || burst;
  return flagged;
}

// Routes
app.post('/api/register', async (req,res)=>{
  const { name, email, password } = req.body;
  if(!email || !password) return res.status(400).json({ error: 'email & password required' });
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);
  try {
    const user = await User.create({ name, email, passwordHash });
    return res.json({ id: user.id, email: user.email });
  } catch(e){
    return res.status(400).json({ error: 'Could not create user (email may already exist)' });
  }
});

app.post('/api/login', async (req,res)=>{
  const { email, password } = req.body;
  if(!email || !password) return res.status(400).json({ error: 'email & password required' });
  const user = await User.findOne({ where: { email } });
  if(!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if(!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET || 'please_change', { expiresIn: '1h' });
  return res.json({ token });
});

app.post('/api/pay', authenticate, async (req,res)=>{
  const { amount, cardNumber, expiry } = req.body;
  if(!amount || !cardNumber) return res.status(400).json({ error: 'amount and cardNumber required' });
  const flagged = await detectFraud(req.user.id, amount, req.ip);
  const enc = encrypt({ cardNumber, expiry });
  const tx = await Transaction.create({
    userId: req.user.id,
    amount,
    cardEncrypted: enc,
    status: flagged ? 'flagged' : 'completed',
    ip: req.ip,
    flagged
  });
  return res.json({ id: tx.id, flagged, status: tx.status });
});

app.get('/api/transactions', authenticate, async (req,res)=>{
  const txs = await Transaction.findAll({ where: { userId: req.user.id }, order: [['createdAt','DESC']] });
  // do NOT send decrypted card numbers in real app. For demo we show masked PAN
  const out = txs.map(t=> ({
    id: t.id, amount: t.amount, status: t.status, flagged: t.flagged, createdAt: t.createdAt
  }));
  return res.json(out);
});

// Admin endpoint to view decrypted (FOR DEMO ONLY)
app.get('/api/admin/decrypted/:id', async (req,res)=>{
  // demo only: decrypt a tx by id
  const id = req.params.id;
  const tx = await Transaction.findByPk(id);
  if(!tx) return res.status(404).json({ error: 'not found' });
  try {
    const card = decrypt(tx.cardEncrypted);
    return res.json({ id: tx.id, card });
  } catch(e){
    return res.status(500).json({ error: 'decrypt error' });
  }
});

// Start server and sync DB
app.listen(PORT, async ()=>{
  await sequelize.sync();
  console.log('Millo Pay backend running on port', PORT);
});
