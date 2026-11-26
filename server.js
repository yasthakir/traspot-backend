import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import express from 'express';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import nodemailer from 'nodemailer';
import { fileURLToPath } from 'node:url';

const backendDirectory = dirname(fileURLToPath(import.meta.url));
const backendEnvPath = resolve(backendDirectory, '.env');
const workspaceEnvPath = resolve(backendDirectory, '..', '.env');
if (existsSync(backendEnvPath)) {
  dotenv.config({ path: backendEnvPath });
} else if (existsSync(workspaceEnvPath)) {
  dotenv.config({ path: workspaceEnvPath });
}

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const sessionCookie = 'srk_admin_session';
const sessionDurationMs = 12 * 60 * 60 * 1000;

const quoteSchema = new mongoose.Schema({
  full_name: { type: String, required: true, maxlength: 120 },
  company_name: { type: String, maxlength: 160, default: '' },
  email: { type: String, required: true, maxlength: 254 },
  phone: { type: String, required: true, maxlength: 40 },
  service_type: { type: String, required: true, maxlength: 100 },
  pickup_location: { type: String, required: true, maxlength: 240 },
  delivery_location: { type: String, required: true, maxlength: 240 },
  collection_date: { type: String, maxlength: 10, default: '' },
  cargo_type: { type: String, maxlength: 100, default: '' },
  weight: { type: String, maxlength: 80, default: '' },
  num_pallets: { type: Number, min: 1, default: null },
  additional_notes: { type: String, maxlength: 4000, default: '' },
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  fullName: { type: String, required: true, maxlength: 120 },
  companyName: { type: String, maxlength: 160, default: '' },
  email: { type: String, required: true, maxlength: 254 },
  phone: { type: String, required: true, maxlength: 40 },
  service: { type: String, maxlength: 100, default: '' },
  message: { type: String, required: true, maxlength: 4000 },
}, { timestamps: true });

const QuoteRequest = mongoose.model('QuoteRequest', quoteSchema);
const ContactMessage = mongoose.model('ContactMessage', messageSchema);

class InputError extends Error {}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb', strict: true }));
app.use(cookieParser());

const publicFormLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many submissions. Please try again later.' },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' },
});

function readText(data, key, { required = false, max = 500 } = {}) {
  const raw = data?.[key];
  if (raw === undefined || raw === null || raw === '') {
    if (required) throw new InputError(`${key} is required.`);
    return '';
  }
  if (typeof raw !== 'string') throw new InputError(`${key} must be text.`);
  const value = raw.trim();
  if (required && !value) throw new InputError(`${key} is required.`);
  if (value.length > max) throw new InputError(`${key} is too long.`);
  return value;
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function createSmtpTransporter() {
  const host = process.env.SMTP_HOST?.trim();
  const port = Number(process.env.SMTP_PORT || 587);
  const secureValue = process.env.SMTP_SECURE?.trim().toLowerCase();
  const user = process.env.SMTP_USER?.trim();
  const rawPass = process.env.SMTP_PASS;
  const pass = host?.toLowerCase() === 'smtp.gmail.com' ? rawPass?.replace(/\s/g, '') : rawPass;
  const from = process.env.MAIL_FROM?.trim() || user;
  const to = process.env.MAIL_TO?.trim();

  if (!host || !Number.isInteger(port) || port < 1 || port > 65535
    || !user || !pass || !from || !to
    || (secureValue && !['true', 'false'].includes(secureValue))) {
    throw new Error('SMTP is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS, MAIL_FROM, and MAIL_TO.');
  }

  return {
    transporter: nodemailer.createTransport({
      host,
      port,
      secure: secureValue ? secureValue === 'true' : port === 465,
      auth: { user, pass },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 20000,
    }),
    from,
    to,
  };
}

async function sendFormNotification({ subject, text, replyTo }) {
  try {
    const { transporter, from, to } = createSmtpTransporter();
    await transporter.sendMail({ from, to, replyTo, subject, text });
    return true;
  } catch (error) {
    console.error('Website form notification email failed.', {
      code: error.code || 'SMTP_CONFIGURATION',
      message: error.message,
      command: error.command,
      responseCode: error.responseCode,
    });
    return false;
  }
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function requireAdmin(req, res, next) {
  const token = req.cookies[sessionCookie];
  if (!token) return res.status(401).json({ error: 'Please sign in again.' });

  try {
    const session = jwt.verify(token, process.env.JWT_SECRET);
    if (session.sub !== process.env.ADMIN_EMAIL.trim().toLowerCase()) {
      return res.status(401).json({ error: 'Please sign in again.' });
    }
    req.admin = session;
    return next();
  } catch {
    return res.status(401).json({ error: 'Please sign in again.' });
  }
}

function parsePage(query) {
  const parsedPage = Number.parseInt(query.page, 10);
  const parsedLimit = Number.parseInt(query.limit, 10);
  return {
    page: Number.isInteger(parsedPage) && parsedPage > 0 ? parsedPage : 1,
    limit: Number.isInteger(parsedLimit) ? Math.min(Math.max(parsedLimit, 1), 100) : 25,
  };
}

app.post('/api/quotes', publicFormLimiter, asyncRoute(async (req, res) => {
  try {
    const email = readText(req.body, 'email', { required: true, max: 254 }).toLowerCase();
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });

    const rawPallets = readText(req.body, 'num_pallets', { max: 6 });
    const pallets = rawPallets ? Number(rawPallets) : null;
    if (rawPallets && (!Number.isInteger(pallets) || pallets < 1)) {
      return res.status(400).json({ error: 'Pallet count must be a positive whole number.' });
    }

    const collectionDate = readText(req.body, 'collection_date', { max: 10 });
    if (collectionDate) {
      const parsedDate = new Date(`${collectionDate}T00:00:00Z`);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(collectionDate)
        || Number.isNaN(parsedDate.getTime())
        || parsedDate.toISOString().slice(0, 10) !== collectionDate) {
        return res.status(400).json({ error: 'Enter a valid collection date.' });
      }
    }

    const record = await QuoteRequest.create({
      full_name: readText(req.body, 'full_name', { required: true, max: 120 }),
      company_name: readText(req.body, 'company_name', { max: 160 }),
      email,
      phone: readText(req.body, 'phone', { required: true, max: 40 }),
      service_type: readText(req.body, 'service_type', { required: true, max: 100 }),
      pickup_location: readText(req.body, 'pickup_location', { required: true, max: 240 }),
      delivery_location: readText(req.body, 'delivery_location', { required: true, max: 240 }),
      collection_date: collectionDate,
      cargo_type: readText(req.body, 'cargo_type', { max: 100 }),
      weight: readText(req.body, 'weight', { max: 80 }),
      num_pallets: pallets,
      additional_notes: readText(req.body, 'additional_notes', { max: 4000 }),
    });

    const emailSent = await sendFormNotification({
      subject: 'New website freight quote request',
      replyTo: record.email,
      text: [
        'A new freight quote request was submitted on the website.',
        '',
        `Name: ${record.full_name}`,
        `Company: ${record.company_name || 'Not provided'}`,
        `Email: ${record.email}`,
        `Phone: ${record.phone}`,
        `Service: ${record.service_type}`,
        `Pickup: ${record.pickup_location}`,
        `Delivery: ${record.delivery_location}`,
        `Collection date: ${record.collection_date || 'Not provided'}`,
        `Cargo: ${record.cargo_type || 'Not provided'}`,
        `Weight: ${record.weight || 'Not provided'}`,
        `Pallets: ${record.num_pallets || 'Not provided'}`,
        `Additional notes: ${record.additional_notes || 'Not provided'}`,
      ].join('\n'),
    });

    return res.status(201).json({ ok: true, id: record.id, emailSent });
  } catch (error) {
    if (error instanceof InputError) {
      return res.status(400).json({ error: error.message });
    }
    throw error;
  }
}));

app.post('/api/messages', publicFormLimiter, asyncRoute(async (req, res) => {
  try {
    const email = readText(req.body, 'email', { required: true, max: 254 }).toLowerCase();
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });

    const record = await ContactMessage.create({
      fullName: readText(req.body, 'fullName', { required: true, max: 120 }),
      companyName: readText(req.body, 'companyName', { max: 160 }),
      email,
      phone: readText(req.body, 'phone', { required: true, max: 40 }),
      service: readText(req.body, 'service', { max: 100 }),
      message: readText(req.body, 'message', { required: true, max: 4000 }),
    });

    const emailSent = await sendFormNotification({
      subject: 'New website contact message',
      replyTo: record.email,
      text: [
        'A new contact message was submitted on the website.',
        '',
        `Name: ${record.fullName}`,
        `Company: ${record.companyName || 'Not provided'}`,
        `Email: ${record.email}`,
        `Phone: ${record.phone}`,
        `Service: ${record.service || 'Not provided'}`,
        '',
        'Message:',
        record.message,
      ].join('\n'),
    });

    return res.status(201).json({ ok: true, id: record.id, emailSent });
  } catch (error) {
    if (error instanceof InputError) {
      return res.status(400).json({ error: error.message });
    }
    throw error;
  }
}));

app.post('/api/admin/login', loginLimiter, asyncRoute(async (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!email || password.length < 1 || password.length > 256) {
    return res.status(400).json({ error: 'Enter your email and password.' });
  }

  const passwordMatches = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
  if (email !== process.env.ADMIN_EMAIL.trim().toLowerCase() || !passwordMatches) {
    return res.status(401).json({ error: 'Email or password is incorrect.' });
  }

  const now = new Date();
  const token = jwt.sign(
    { sub: process.env.ADMIN_EMAIL.trim().toLowerCase() },
    process.env.JWT_SECRET,
    { expiresIn: '12h' },
  );
  res.cookie(sessionCookie, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: sessionDurationMs,
    path: '/',
  });
  return res.json({ ok: true, email: process.env.ADMIN_EMAIL.trim(), now });
}));

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  res.clearCookie(sessionCookie, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
  });
  return res.json({ ok: true });
});

app.get('/api/admin/session', requireAdmin, (req, res) => {
  return res.json({ ok: true, email: process.env.ADMIN_EMAIL.trim(), now: new Date() });
});

app.get('/api/admin/summary', requireAdmin, asyncRoute(async (req, res) => {
  const [quotes, messages, latestQuotes, latestMessages] = await Promise.all([
    QuoteRequest.countDocuments(),
    ContactMessage.countDocuments(),
    QuoteRequest.find().sort({ createdAt: -1 }).limit(5).select('full_name email createdAt').lean(),
    ContactMessage.find().sort({ createdAt: -1 }).limit(5).select('fullName email createdAt').lean(),
  ]);
  return res.json({ quotes, messages, latestQuotes, latestMessages });
}));

app.get('/api/admin/quotes', requireAdmin, asyncRoute(async (req, res) => {
  const { page, limit } = parsePage(req.query);
  const [items, total] = await Promise.all([
    QuoteRequest.find().sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    QuoteRequest.countDocuments(),
  ]);
  return res.json({ items, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
}));

app.get('/api/admin/messages', requireAdmin, asyncRoute(async (req, res) => {
  const { page, limit } = parsePage(req.query);
  const [items, total] = await Promise.all([
    ContactMessage.find().sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    ContactMessage.countDocuments(),
  ]);
  return res.json({ items, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
}));

app.get('/api/admin/notifications', requireAdmin, asyncRoute(async (req, res) => {
  const after = req.query.after ? new Date(req.query.after) : new Date();
  if (Number.isNaN(after.getTime())) {
    return res.status(400).json({ error: 'Invalid notification cursor.' });
  }

  const [quotes, messages] = await Promise.all([
    QuoteRequest.find({ createdAt: { $gt: after } }).sort({ createdAt: 1 }).limit(25)
      .select('full_name email createdAt').lean(),
    ContactMessage.find({ createdAt: { $gt: after } }).sort({ createdAt: 1 }).limit(25)
      .select('fullName email createdAt').lean(),
  ]);
  return res.json({
    checkedAt: new Date(),
    items: [
      ...quotes.map((item) => ({ id: item._id, type: 'quote', name: item.full_name, createdAt: item.createdAt })),
      ...messages.map((item) => ({ id: item._id, type: 'message', name: item.fullName, createdAt: item.createdAt })),
    ].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt)),
  });
}));

app.get('/api/health', (req, res) => {
  const databaseConnected = mongoose.connection.readyState === 1;
  return res.status(databaseConnected ? 200 : 503).json({ ok: databaseConnected });
});

app.use((req, res) => res.status(404).json({ error: 'Endpoint not found.' }));
app.use((error, req, res, next) => {
  console.error('Request failed:', error.message);
  if (res.headersSent) return next(error);
  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'The request body is not valid JSON.' });
  }
  return res.status(500).json({ error: 'The request could not be completed. Please try again.' });
});

async function start() {
  const required = ['MONGODB_URI', 'ADMIN_EMAIL', 'ADMIN_PASSWORD_HASH', 'JWT_SECRET'];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  if (process.env.MONGODB_URI.includes('<URL-ENCODED-PASSWORD>')) {
    throw new Error('Replace the Atlas password placeholder in MONGODB_URI with its URL-encoded value.');
  }
  if (process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long.');
  }
  if (process.env.JWT_SECRET.startsWith('replace-with-')) {
    throw new Error('Replace the JWT_SECRET placeholder with a random private secret.');
  }
  if (!/^\$2[aby]\$\d{2}\$/.test(process.env.ADMIN_PASSWORD_HASH)) {
    throw new Error('ADMIN_PASSWORD_HASH must be a bcrypt hash.');
  }
  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => console.log(`API server listening on port ${port}`));
}

start().catch((error) => {
  console.error(`Server startup failed: ${error.message}`);
  process.exitCode = 1;
});
