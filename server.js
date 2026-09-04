const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // สำหรับวางไฟล์ index.html ในโฟลเดอร์ public

// --- Swagger Configuration ---
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Invention Project & Drive API',
      version: '1.0.0',
      description: 'ระบบจัดเก็บไฟล์และบันทึกโครงการสิ่งประดิษฐ์',
    },
    servers: [{ url: 'http://localhost:3000' }],
  },
  apis: ['./server.js'],
};

const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Nakemode API is running' });
});

// --- Lightweight local database ---
const dataDirectory = path.join(__dirname, 'data');
const usersFile = path.join(dataDirectory, 'users.json');
fs.mkdirSync(dataDirectory, { recursive: true });
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, '[]');

const sessions = new Map();
let files = [];
let projects = [];

function readUsers() {
  return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
}

function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, user) {
  const candidate = crypto.scryptSync(password, user.salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}

function createToken() {
  return crypto.randomBytes(32).toString('hex');
}

function authenticate(req, res, next) {
  const authorization = req.get('authorization') || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ message: 'กรุณาเข้าสู่ระบบก่อนใช้งาน' });
  }
  req.user = session.user;
  next();
}

function publicUser(user) {
  return { id: user.id, username: user.username, createdAt: user.createdAt };
}

function validateCredentials(body) {
  const username = String(body.username || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username)) return 'กรุณากรอกอีเมลให้ถูกต้อง';
  if (password.length < 8) return 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร';
  return null;
}

// --- Auth Endpoints ---

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: สมัครสมาชิก
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: สมัครสมาชิกสำเร็จ
 */
app.post('/api/auth/register', (req, res) => {
  const validationError = validateCredentials(req.body);
  if (validationError) return res.status(400).json({ message: validationError });

  const username = req.body.username.trim().toLowerCase();
  const users = readUsers();
  if (users.some(user => user.username === username)) {
    return res.status(409).json({ message: 'อีเมลนี้ถูกใช้งานแล้ว' });
  }

  const { salt, hash } = hashPassword(req.body.password);
  const user = {
    id: crypto.randomUUID(),
    username,
    salt,
    passwordHash: hash,
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  writeUsers(users);
  res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ', user: publicUser(user) });
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: เข้าสู่ระบบ
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: เข้าสู่ระบบสำเร็จ
 */
app.post('/api/auth/login', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = readUsers().find(item => item.username === username);
  if (!user || !password || !verifyPassword(password, user)) {
    return res.status(401).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
  }

  const token = createToken();
  sessions.set(token, { user: publicUser(user), expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
  res.json({ token, user: publicUser(user) });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  const token = (req.get('authorization') || '').slice(7);
  sessions.delete(token);
  res.json({ message: 'ออกจากระบบสำเร็จ' });
});

// --- Files Endpoints ---

/**
 * @swagger
 * /api/files:
 *   get:
 *     summary: ดึงรายการไฟล์ที่อัปโหลดไว้ (Drive)
 *     tags: [Files]
 *     responses:
 *       200:
 *         description: สำเร็จ
 */
app.get('/api/files', authenticate, (req, res) => {
  res.json(files.filter(file => file.userId === req.user.id));
});

/**
 * @swagger
 * /api/files/upload:
 *   post:
 *     summary: อัปโหลดไฟล์ใหม่
 *     tags: [Files]
 *     responses:
 *       200:
 *         description: อัปโหลดไฟล์สำเร็จ
 */
app.post('/api/files/upload', authenticate, (req, res) => {
  const filename = String(req.body.filename || '').trim();
  const sizeInBytes = Number(req.body.size);
  if (!filename || !Number.isFinite(sizeInBytes) || sizeInBytes < 0) {
    return res.status(400).json({ message: 'ข้อมูลไฟล์ไม่ถูกต้อง' });
  }
  const newFile = { id: Date.now().toString(), userId: req.user.id, filename, size: `${(sizeInBytes / 1024 / 1024).toFixed(2)} MB` };
  files.push(newFile);
  res.json(newFile);
});

/**
 * @swagger
 * /api/files/{id}:
 *   delete:
 *     summary: ลบไฟล์
 *     tags: [Files]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ลบไฟล์สำเร็จ
 */
app.delete('/api/files/:id', authenticate, (req, res) => {
  files = files.filter(f => f.id !== req.params.id || f.userId !== req.user.id);
  res.json({ message: 'ลบไฟล์สำเร็จ' });
});

// --- Projects Endpoints ---

/**
 * @swagger
 * /api/projects:
 *   get:
 *     summary: ดึงรายการโครงการสิ่งประดิษฐ์ทั้งหมด
 *     tags: [Projects]
 *     responses:
 *       200:
 *         description: สำเร็จ
 *   post:
 *     summary: ส่งโครงการสิ่งประดิษฐ์ (ครบ 5 รายละเอียด)
 *     tags: [Projects]
 *     responses:
 *       200:
 *         description: บันทึกสำเร็จ
 */
app.get('/api/projects', authenticate, (req, res) => {
  res.json(projects.filter(project => project.userId === req.user.id));
});

app.post('/api/projects', authenticate, (req, res) => {
  const { title, category, description } = req.body;
  if (!title || !category) return res.status(400).json({ message: 'กรุณากรอกชื่อโครงการและหมวดหมู่' });
  const newProj = { id: Date.now().toString(), userId: req.user.id, title, category, description };
  projects.push(newProj);
  res.json(newProj);
});

/**
 * @swagger
 * /api/projects/{id}:
 *   get:
 *     summary: ดึงรายละเอียดโครงการตาม ID
 *     tags: [Projects]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: สำเร็จ
 *   put:
 *     summary: แก้ไขข้อมูลโครงการ
 *     tags: [Projects]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: แก้ไขสำเร็จ
 *   delete:
 *     summary: ลบโครงการสิ่งประดิษฐ์
 *     tags: [Projects]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: ลบสำเร็จ
 */
app.get('/api/projects/:id', authenticate, (req, res) => {
  const proj = projects.find(p => p.id === req.params.id && p.userId === req.user.id);
  res.json(proj || {});
});

app.put('/api/projects/:id', authenticate, (req, res) => {
  const project = projects.find(item => item.id === req.params.id && item.userId === req.user.id);
  if (!project) return res.status(404).json({ message: 'ไม่พบโครงการ' });
  Object.assign(project, req.body);
  res.json(project);
});

app.delete('/api/projects/:id', authenticate, (req, res) => {
  projects = projects.filter(p => p.id !== req.params.id || p.userId !== req.user.id);
  res.json({ message: 'ลบโครงการสำเร็จ' });
});

// --- Start Server ---
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});