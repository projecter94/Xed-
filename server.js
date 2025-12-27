// server.js
const express = require('express');
const fs = require('fs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// CONFIGURATION
// This secret is used for both Admin commands AND the Lua script
const ADMIN_SECRET = process.env.SERVER_SECRET || "vanta_supersecretkey_2025"; 
const KEYS_FILE = './keys.json';

// Load or initialize keys file
let keys = {};
if (fs.existsSync(KEYS_FILE)) {
    try {
        keys = JSON.parse(fs.readFileSync(KEYS_FILE));
    } catch (e) {
        console.error("Error reading keys file, resetting:", e);
        keys = {};
    }
} else {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// Save keys helper
function saveKeys() {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// ==================================================================
//  ✅ NEW ENDPOINT FOR LUA SCRIPT (Fixes 404 Error)
// ==================================================================
app.post('/api/verify', (req, res) => {
    // 1. Security Check
    // The Lua script sends the secret in 'x-client-secret' header
    const providedSecret = req.headers['x-client-secret'];
    if (providedSecret !== ADMIN_SECRET) {
        return res.status(401).json({ ok: false, msg: "Invalid Client Secret" });
    }

    const { key, device } = req.body;
    if (!key || !device) return res.status(400).json({ ok: false, msg: "Missing Data" });

    // 2. Check if key exists
    const entry = keys[key];
    if (!entry) {
        return res.json({ ok: false, msg: "Invalid Key" });
    }

    // 3. HWID Logic
    // In your structure, we use entry.hwid
    if (!entry.hwid) {
        // New User -> Bind HWID
        console.log(`[Auth] Binding new HWID for key: ${key}`);
        entry.hwid = device.hwid;
        entry.lastUsed = new Date().toISOString();
        // Save extra device info if you want
        if(!entry.logs) entry.logs = [];
        entry.logs.push({ 
            action: "Bind", 
            hwid: device.hwid, 
            ip: "0.0.0.0", // Render doesn't always show real client IP easily
            executor: device.executor,
            time: new Date().toISOString() 
        });
        saveKeys();
    } else if (entry.hwid !== device.hwid) {
        // Mismatch
        console.log(`[Auth] HWID Mismatch for key: ${key}`);
        return res.json({ ok: false, msg: "HWID Mismatch. Please reset HWID." });
    } else {
        // Match -> Update Last Seen
        entry.lastUsed = new Date().toISOString();
        saveKeys();
    }

    // 4. Success
    return res.json({ ok: true, msg: "Authenticated" });
});

// ==================================================================
//  EXISTING ENDPOINTS (Bot Integration & Admin)
// ==================================================================

// Validate key & log execution (Legacy / Public endpoint)
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

// Helper for Admin Endpoints
function checkAdmin(req, res) {
    // Check Authorization header against ADMIN_SECRET
    // Some bots send "Bearer <secret>", others just "<secret>"
    // We check both for compatibility
    const auth = req.headers.authorization;
    if (!auth) return false;
    
    if (auth === `Bearer ${ADMIN_SECRET}` || auth === ADMIN_SECRET) {
        return true;
    }
    return false;
}

// Add key
app.post('/admin/addkey', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: "Missing key" });
    if (keys[key]) return res.status(400).json({ error: "Key exists" });
    
    keys[key] = {
        created: new Date().toISOString(),
        hwid: null,
        boundUserId: null,
        logs: []
    };
    saveKeys();
    res.json({ success: true });
});

// Delete key
app.post('/admin/deletekey', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });

    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    delete keys[key];
    saveKeys();
    res.json({ success: true });
});

// Reset HWID & binding
app.post('/admin/resethwid', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });

    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    keys[key].hwid = null;
    // Note: We don't reset boundUserId here based on your original logic, 
    // usually you only reset HWID so the user can switch PC but keep ownership.
    // If you want to full reset, uncomment next line:
    // keys[key].boundUserId = null; 
    saveKeys();
    res.json({ success: true });
});

// Whitelist user (Manually bind a Discord User ID)
app.post('/admin/whitelist', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });

    const { key, userId } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    keys[key].boundUserId = userId;
    if (!keys[key].logs) keys[key].logs = [];
    saveKeys();
    res.json({ success: true });
});

// Unwhitelist user
app.post('/admin/unwhitelist', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });

    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key does not exist" });
    keys[key].boundUserId = null;
    keys[key].hwid = null;
    keys[key].logs = [];
    saveKeys();
    res.json({ success: true });
});

// List keys
app.get('/admin/listkeys', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    res.json(keys);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Render API server running on port ${PORT}`));
