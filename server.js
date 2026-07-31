require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // Upgraded from jwt-simple to jsonwebtoken
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// --- Express Middleware ---
app.use(express.json());
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));

// --- 1. MySQL Connection Pool ---
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test Database Connection on Startup
(async () => {
    try {
        const connection = await db.getConnection();
        console.log('✅ Connected to MySQL database successfully.');
        connection.release();
    } catch (err) {
        console.error('❌ Database connection failed:', err.message);
    }
})();

// --- 2. HTTP Server & Socket.IO Setup ---
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || "*",
        methods: ["GET", "POST"]
    }
});

// Optional: Socket Authentication Middleware
io.use((socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization;
    if (!token) {
        return next(); // Proceed as guest or handle strict auth by returning new Error("Unauthorized")
    }
    
    try {
        const cleanToken = token.replace('Bearer ', '');
        const decoded = jwt.verify(cleanToken, process.env.JWT_SECRET);
        socket.user = decoded;
        next();
    } catch (err) {
        next(new Error("Authentication error"));
    }
});

io.on('connection', (socket) => {
    console.log(`⚡ Client connected: ${socket.id}`);

    // Join a specific Circle/Room for real-time tracking
    socket.on('join_circle', (circleId) => {
        if (!circleId) return;
        socket.join(`circle_${circleId}`);
        console.log(`Socket ${socket.id} joined circle_${circleId}`);
    });

    // Leave Circle/Room
    socket.on('leave_circle', (circleId) => {
        if (!circleId) return;
        socket.leave(`circle_${circleId}`);
        console.log(`Socket ${socket.id} left circle_${circleId}`);
    });

    // Broadcast location update to all members in the circle except sender
    socket.on('update_location', (data) => {
        const { circleId, latitude, longitude, userId } = data;
        if (!circleId || !latitude || !longitude) return;

        socket.to(`circle_${circleId}`).emit('member_location_updated', {
            userId: userId || socket.user?.id,
            latitude,
            longitude,
            timestamp: new Date().toISOString()
        });
    });

    socket.on('disconnect', () => {
        console.log(`🔌 Client disconnected: ${socket.id}`);
    });
});

// --- JWT Verification Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expecting "Bearer <token>"

    if (!token) {
        return res.status(401).json({ success: false, message: "Access token required" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ success: false, message: "Invalid or expired token" });
        }
        req.user = decoded;
        next();
    });
};

// --- 3. Auth Routes ---

// SIGNUP ENDPOINT
app.post('/api/auth/signup', async (req, res) => {
    // 1. Notice confirmPassword is removed here
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, message: "Password must be at least 6 characters long" });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();

        // Check if user exists
        const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [normalizedEmail]);
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: "Email is already registered" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user
        const [result] = await db.query(
            "INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)",
            [fullName.trim(), normalizedEmail, hashedPassword]
        );

        res.status(201).json({
            success: true,
            message: "User registered successfully",
            userId: result.insertId
        });

    } catch (err) {
        console.error('Signup Error:', err);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// LOGIN ENDPOINT
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();
        const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [normalizedEmail]);
        
        if (rows.length === 0) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        // Sign JWT Token with explicit expiration (7 days)
        const token = jwt.sign(
            { id: user.id, email: user.email }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' }
        );

        res.status(200).json({
            success: true,
            message: "Login successful",
            token: token,
            user: {
                id: user.id,
                fullName: user.full_name,
                email: user.email
            }
        });

    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// GET CURRENT USER PROFILE (Protected Route Example)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.query("SELECT id, full_name, email, created_at FROM users WHERE id = ?", [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found" });
        }
        res.status(200).json({ success: true, user: rows[0] });
    } catch (err) {
        console.error('Profile Fetch Error:', err);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// --- Server Startup ---
const PORT = process.env.PORT || 5100;
server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});