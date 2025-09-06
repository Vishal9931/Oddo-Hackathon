// Load environment variables
require('dotenv').config();

// Core imports
const express = require('express');
const path = require('path');
const fs = require('fs');

// Security & middleware
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');

// Auth & encryption
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// File uploads
const multer = require('multer');

// Database (Sequelize + SQLite)
const { Sequelize, DataTypes } = require('sequelize');

// Initialize app
const app = express();

// Middleware
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter);

// CORS
app.use(cors({
    origin: 'http://localhost:3000', // change when deploying
    credentials: true
}));

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'database.sqlite'
});

const User = sequelize.define('User', {
    username: DataTypes.STRING,
    email: { type: DataTypes.STRING, unique: true },
    password: DataTypes.STRING,
});

const Product = sequelize.define('Product', {
    title: DataTypes.STRING,
    description: DataTypes.TEXT,
    price: DataTypes.FLOAT,
    image: DataTypes.STRING,
    userId: DataTypes.INTEGER,
});

sequelize.sync();

// Auth middleware
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

function authenticateToken(req, res, next) {
  try {
    // 1) Check Authorization header
    const authHeader = req.headers['authorization'];
    let token = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }

    // 2) If not present, check httpOnly cookie
    if (!token && req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, payload) => {
      if (err) return res.status(403).json({ error: 'Invalid or expired token' });
      req.user = { id: payload.id, email: payload.email };
      next();
    });
  } catch (err) {
    next(err);
  }
}


// Multer config (safe uploads)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const dir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir);
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname).toLowerCase();
        const name = `${req.user ? req.user.id : 'anon'}-${Date.now()}-${Math.round(Math.random() * 1E6)}${ext}`;
        cb(null, name);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = /jpeg|jpg|png|webp/;
        const ext = path.extname(file.originalname).toLowerCase();
        const mimetypeAllowed = allowed.test(file.mimetype);
        const extAllowed = allowed.test(ext);
        if (mimetypeAllowed && extAllowed) return cb(null, true);
        cb(new Error('Only image files (jpg, jpeg, png, webp) are allowed'));
    }
});

// Routes

// Register
app.post('/api/register',
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('username').optional().trim().escape(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, email, password } = req.body;
        try {
            const hashed = await bcrypt.hash(password, 10);
            const user = await User.create({ username, email, password: hashed });
            res.json({ id: user.id, email: user.email, username: user.username });
        } catch (err) {
            res.status(400).json({ error: 'Email already in use' });
        }
    }
);

// Login
app.post('/api/login',
    body('email').isEmail().normalizeEmail(),
    body('password').exists(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '8h' });

        // Send token in response
        // Send token as httpOnly cookie (more secure)
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 8 * 60 * 60 * 1000 // 8 hours
        });
        res.json({ id: user.id, email: user.email, username: user.username });

    }
);

// Get products
app.get('/api/products', async (req, res) => {
    const products = await Product.findAll();
    res.json(products);
});

// Create product
app.post('/api/products',
    authenticateToken,
    upload.single('image'),
    body('title').trim().isLength({ min: 1 }).escape(),
    body('price').isFloat({ min: 0 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { title, description, price } = req.body;
        const product = await Product.create({
            title,
            description,
            price,
            image: req.file ? '/uploads/' + req.file.filename : null,
            userId: req.user.id
        });
        res.json(product);
    }
);

// Edit product
app.put('/api/products/:id', authenticateToken, upload.single('image'), async (req, res) => {
    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ error: 'Not found' });
    if (product.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

    const { title, description, price } = req.body;
    if (title) product.title = title;
    if (description) product.description = description;
    if (price) product.price = price;
    if (req.file) product.image = '/uploads/' + req.file.filename;
    await product.save();
    res.json(product);
});

// Delete product
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ error: 'Not found' });
    if (product.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

    if (product.image) {
        const imgPath = path.join(__dirname, product.image);
        try { if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath); } catch (e) { console.warn('Failed to delete image', e); }
    }
    await product.destroy();
    res.json({ success: true });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err);
    if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.status(500).json({ error: err.message, stack: err.stack });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
