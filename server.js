// server.js
const express = require('express');
const fs = require('fs');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// ==================================================================
//  ✅ CONFIGURATION (Updated to match Lua Script)
// ==================================================================
// This must match the Lua script EXACTLY
const ADMIN_SECRET = process.env.SERVER_SECRET || "vanta_supersecretkey_2025_ABC123"; 
const KEYS_FILE = './keys.json';

// Load or initialize keys file
let keys = {};
if (fs.existsSync(KEYS_FILE)) {
    try { keys = JSON.parse(fs.readFileSync(KEYS_FILE)); }
    catch (e) { keys = {}; }
} else {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

function saveKeys() {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// Helper: Check Admin Auth
function checkAdmin(req, res) {
    const auth = req.headers.authorization;
    if (!auth) return false;
    // Allow both strict match and Bearer match
    return (auth === `Bearer ${ADMIN_SECRET}` || auth === ADMIN_SECRET);
}

// ==================================================================
//  ✅ LUA SCRIPT ENDPOINT
// ==================================================================
app.post('/api/verify', (req, res) => {
    const providedSecret = req.headers['x-client-secret'];
    
    // DEBUG LOG: Remove this after fixing if you want cleaner logs
    // console.log(`[Auth Attempt] Provided: ${providedSecret} | Expected: ${ADMIN_SECRET}`);

    if (providedSecret !== ADMIN_SECRET) {
        return res.status(401).json({ ok: false, msg: "Invalid Client Secret (Server Mismatch)" });
    }

    const { key, device } = req.body;
    if (!key || !device) return res.status(400).json({ ok: false, msg: "Missing Data" });

    // Since keys are objects in your structure: keys = { "KEY": { ...data... } }
    const entry = keys[key];
    
    if (!entry) {
        return res.json({ ok: false, msg: "Invalid Key" });
    }

    // CHECK BLACKLIST
    if (entry.isBlacklisted) return res.json({ ok: false, msg: "Key is Blacklisted" });

    // HWID Logic
    if (!entry.hwid) {
        // New User -> Bind
        entry.hwid = device.hwid;
        entry.lastUsed = new Date().toISOString();
        if(!entry.logs) entry.logs = [];
        entry.logs.push({ 
            action: "Bind", 
            hwid: device.hwid, 
            ip: "0.0.0.0", 
            executor: device.executor, 
            time: new Date().toISOString() 
        });
        saveKeys();
    } else if (entry.hwid !== device.hwid) {
        return res.json({ ok: false, msg: "HWID Mismatch. Reset HWID via Bot." });
    } else {
        // Just Update Last Seen
        entry.lastUsed = new Date().toISOString();
        saveKeys();
    }

    return res.json({ ok: true, msg: "Authenticated" });
});

// ==================================================================
//  ✅ BOT API ENDPOINTS
// ==================================================================

// Add Key
app.post('/admin/addkey', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    
    const { key, note, discordId } = req.body;
    if (!key) return res.status(400).json({ error: "Missing key" });
    if (keys[key]) return res.status(400).json({ error: "Key exists" });
    
    keys[key] = {
        key: key, 
        created: new Date().toISOString(),
        hwid: null,
        discordId: discordId || null,
        note: note || "Generated",
        isBlacklisted: false,
        logs: []
    };
    saveKeys();
    res.json({ success: true, key: keys[key] });
});

// Delete Key
app.post('/admin/deletekey', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key not found" });
    delete keys[key];
    saveKeys();
    res.json({ success: true });
});

// Toggle Blacklist
app.post('/admin/blacklist', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    const { key, status } = req.body; 
    if (!keys[key]) return res.status(400).json({ error: "Key not found" });
    
    keys[key].isBlacklisted = status;
    saveKeys();
    res.json({ success: true, isBlacklisted: keys[key].isBlacklisted });
});

// Reset HWID
app.post('/admin/resethwid', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    const { key } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key not found" });
    keys[key].hwid = null;
    saveKeys();
    res.json({ success: true });
});

// Whitelist (Link Discord ID)
app.post('/admin/whitelist', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    const { key, userId } = req.body;
    if (!keys[key]) return res.status(400).json({ error: "Key not found" });
    
    keys[key].discordId = userId;
    saveKeys();
    res.json({ success: true });
});

// List Keys
app.get('/admin/listkeys', (req, res) => {
    if (!checkAdmin(req, res)) return res.status(403).json({ error: "Unauthorized" });
    // Convert object to array for the bot
    const keyArray = Object.values(keys); 
    res.json(keyArray);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Render API server running on port ${PORT}`));
