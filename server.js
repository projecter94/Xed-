// server.js
const express = require('express');
const fs = require('fs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const ADMIN_SECRET = "vanta_supersecretkey_2025"; // Keep private
const KEYS_FILE = './keys.json';

// Load or initialize keys file
let keys = {};
if (fs.existsSync(KEYS_FILE)) {
    keys = JSON.parse(fs.readFileSync(KEYS_FILE));
} else {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// Save keys helper
function saveKeys() {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// ------------------ Public endpoint ------------------
// Validate key & log execution
app.post('/validate', (req, res) => {
    const { key, userId, hwid, ip } = req.body;
    if (!key || !userId) return res.json({ allowed: false });

    const entry = keys[key];
    if (!entry) return res.json({ allowed: false });

    // First-time use: bind userId and hwid
    if (!entry.boundUserId) {
        entry.boundUserId = userId;
        entry.hwid = hwid || null;
        entry.logs = [{ userId, hwid, ip, time: new Date().toISOString() }];
        entry.firstUsed = new Date().toISOString();
        entry.lastUsed = new Date().toISOString();
        saveKeys();
        return res.json({ allowed: true });
    }

    // Check if UserId matches
    if (entry.boundUserId == userId) {
        entry.lastUsed = new Date().toISOString();
        entry.hwid = hwid || entry.hwid;
        if (!entry.logs) entry.logs = [];
        entry.logs.push({ userId, hwid, ip, time: new Date().toISOString() });
        saveKeys();
        return res.json({ allowed: true });
    }

    return res.json({ allowed: false });
});

// ------------------ Admin endpoints ------------------
function checkAdmin(req, res) {
    if (req.headers.authorization !== `Bearer ${ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Unauthorized" });
    }
}

// Add key
app.post('/admin/addkey', (req, res) => {
    checkAdmin(req, res);
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: "Missing key" });
    if (keys[key]) return res.status(400).json({ error: "Key exists" });
    keys[key] = {};
    saveKeys();
    res.json({ success: true });
});

// Delete key
app.post('/admin/deletekey', (req, res) => {
    checkAdmin(req, res);
    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    delete keys[key];
    saveKeys();
    res.json({ success: true });
});

// Reset HWID & binding
app.post('/admin/resethwid', (req, res) => {
    checkAdmin(req, res);
    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    keys[key].hwid = null;
    keys[key].boundUserId = null;
    keys[key].logs = [];
    saveKeys();
    res.json({ success: true });
});

// Whitelist user
app.post('/admin/whitelist', (req, res) => {
    checkAdmin(req, res);
    const { key, userId } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    keys[key].boundUserId = userId;
    if (!keys[key].logs) keys[key].logs = [];
    saveKeys();
    res.json({ success: true });
});

// Unwhitelist user
app.post('/admin/unwhitelist', (req, res) => {
    checkAdmin(req, res);
    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    keys[key].boundUserId = null;
    keys[key].hwid = null;
    keys[key].logs = [];
    saveKeys();
    res.json({ success: true });
});

// List keys (optional)
app.get('/admin/listkeys', (req, res) => {
    checkAdmin(req, res);
    res.json(keys);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Render API server running on port ${PORT}`));