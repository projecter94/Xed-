/*
    VANTA API SERVER (MongoDB Atlas Edition)
    File: server.js
*/

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// ================= CONFIGURATION =================
// 1. Get these from your Render Environment Variables
const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.SERVER_SECRET || "vanta_supersecretkey_2025_ABC123"; 
const MONGO_URI = process.env.MONGO_URI; 
// Example URI: mongodb+srv://jerdakalex125_db_user:PASSWORD@cluster0.5vjwmsf.mongodb.net/?retryWrites=true&w=majority

if (!MONGO_URI) {
    console.error("❌ CRITICAL ERROR: MONGO_URI is missing in environment variables.");
    process.exit(1);
}

// ================= MONGODB CONNECT =================
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => {
        console.error('❌ MongoDB Connection Error:', err);
        process.exit(1);
    });

// Define Key Schema
const keySchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    note: { type: String, default: "Generated" },
    discordId: { type: String, default: null },
    hwid: { type: String, default: null },
    isBlacklisted: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    lastUsed: { type: Date, default: null },
    logs: [{ 
        action: String, 
        hwid: String, 
        ip: String, 
        executor: String, 
        time: Date 
    }]
});

const Key = mongoose.model('Key', keySchema);

// ================= MIDDLEWARE =================
function checkAdmin(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: "Missing Authorization Header" });
    
    // Allow "Bearer <secret>" or just "<secret>"
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : auth;
    
    if (token !== ADMIN_SECRET) {
        return res.status(403).json({ error: "Invalid Server Secret" });
    }
    next();
}

// ================= ROUTES (LUA SCRIPT) =================
app.post('/api/verify', async (req, res) => {
    const providedSecret = req.headers['x-client-secret'];
    
    // 1. Verify Script Integrity
    if (providedSecret !== ADMIN_SECRET) {
        return res.status(401).json({ ok: false, msg: "Invalid Client Secret (Server Mismatch)" });
    }

    const { key, device } = req.body;
    if (!key || !device) return res.status(400).json({ ok: false, msg: "Missing Data" });

    try {
        // 2. Find Key in DB
        const entry = await Key.findOne({ key: key });
        
        if (!entry) {
            return res.json({ ok: false, msg: "Invalid Key" });
        }

        if (entry.isBlacklisted) {
            return res.json({ ok: false, msg: "Key is Blacklisted" });
        }

        // 3. HWID Logic
        if (!entry.hwid) {
            // Bind New HWID
            entry.hwid = device.hwid;
            entry.lastUsed = new Date();
            entry.logs.push({ 
                action: "Bind", 
                hwid: device.hwid, 
                ip: "0.0.0.0", // IP logging removed for privacy/simplicity or use req.ip
                executor: device.executor, 
                time: new Date() 
            });
            await entry.save();
        } else if (entry.hwid !== device.hwid) {
            return res.json({ ok: false, msg: "HWID Mismatch" });
        } else {
            // Update Last Seen
            entry.lastUsed = new Date();
            await entry.save();
        }

        return res.json({ ok: true, msg: "Authenticated" });

    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, msg: "Database Error" });
    }
});

// ================= ROUTES (DISCORD BOT ADMIN) =================

// Add Key
app.post('/admin/addkey', checkAdmin, async (req, res) => {
    const { key, note, discordId } = req.body;
    if (!key) return res.status(400).json({ error: "Missing key" });

    try {
        const exists = await Key.findOne({ key });
        if (exists) return res.status(400).json({ error: "Key already exists" });

        const newKey = new Key({
            key,
            note: note || "Manual Add",
            discordId: discordId || null
        });
        await newKey.save();
        res.json({ success: true, key: newKey });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Delete Key
app.post('/admin/deletekey', checkAdmin, async (req, res) => {
    const { key } = req.body;
    try {
        const result = await Key.deleteOne({ key });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Key not found" });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Toggle Blacklist
app.post('/admin/blacklist', checkAdmin, async (req, res) => {
    const { key, status } = req.body; 
    try {
        const entry = await Key.findOne({ key });
        if (!entry) return res.status(404).json({ error: "Key not found" });

        entry.isBlacklisted = status;
        await entry.save();
        res.json({ success: true, isBlacklisted: entry.isBlacklisted });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Reset HWID
app.post('/admin/resethwid', checkAdmin, async (req, res) => {
    const { key } = req.body;
    try {
        const entry = await Key.findOne({ key });
        if (!entry) return res.status(404).json({ error: "Key not found" });

        entry.hwid = null;
        await entry.save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Whitelist (Link Discord)
app.post('/admin/whitelist', checkAdmin, async (req, res) => {
    const { key, userId } = req.body;
    try {
        const entry = await Key.findOne({ key });
        if (!entry) return res.status(404).json({ error: "Key not found" });

        entry.discordId = userId;
        await entry.save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// List Keys
app.get('/admin/listkeys', checkAdmin, async (req, res) => {
    try {
        const allKeys = await Key.find({});
        res.json({ keys: allKeys });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.listen(PORT, () => console.log(`🌍 Mongo API Server running on port ${PORT}`));
