// ============================================================
// 🛡️ PREMIUM LOADER v5.0.0 - COMPATIBLE VERSION
// Menggunakan /script endpoint seperti versi lama
// ============================================================

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const config = require('./config');
const { db, scriptCache, blockedDevices, challenges } = require('./database');
const { generateProtectedScript, generateSessionKey } = require('./protection');

const app = express();

// ============================================================
// 🌐 UNAUTHORIZED HTML
// ============================================================

const UNAUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Unauthorized</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: #000; color: #fff; font-family: system-ui;
            height: 100vh; display: flex; align-items: center; 
            justify-content: center; text-align: center;
        }
        h1 { font-size: 2rem; margin-bottom: 1rem; }
        p { color: #666; }
    </style>
</head>
<body>
    <div>
        <h1>⛔ Not Authorized</h1>
        <p>You are not allowed to view this.</p>
    </div>
</body>
</html>`;

// ============================================================
// 🔧 MIDDLEWARE
// ============================================================

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'PUT'] }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

const authLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { success: false, error: "Too many attempts" }
});

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: { success: false, error: "Too many requests" }
});

app.use('/api/auth/', authLimiter);
app.use('/api/', generalLimiter);

// ============================================================
// 🔧 HELPER FUNCTIONS
// ============================================================

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.ip || 'unknown';
}

function getHWID(req) {
    return req.headers['x-hwid'] || req.query.hwid || null;
}

function getPlayerID(req) {
    return req.headers['x-player-id'] || req.query.pid || null;
}

function logAccess(req, action, success, details = {}) {
    const log = { 
        ip: getClientIP(req), 
        hwid: getHWID(req),
        playerId: getPlayerID(req),
        action, 
        success, 
        timestamp: new Date().toISOString(),
        ...details 
    };
    db.addLog(log);
    console.log(`[${log.timestamp}] ${success ? '✅' : '❌'} ${action}`);
}

function isBrowser(req) {
    const accept = req.headers['accept'] || '';
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    
    const executors = ['synapse', 'krnl', 'fluxus', 'delta', 'script-ware', 
                       'sentinel', 'oxygen', 'evon', 'arceus', 'hydrogen',
                       'solara', 'wave', 'zorara', 'codex', 'celery', 'swift',
                       'executor', 'exploit', 'roblox', 'wininet'];
    
    if (executors.some(e => ua.includes(e))) return false;
    
    if (accept.includes('text/html')) {
        const hasBrowserUA = ua.includes('mozilla') || ua.includes('chrome') || 
                             ua.includes('safari') || ua.includes('firefox');
        if (hasBrowserUA && req.headers['accept-language']) return true;
    }
    return false;
}

function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

// ============================================================
// 🏠 ROOT & HEALTH
// ============================================================

app.get('/', (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    res.json({ status: "online", version: "5.0.0" });
});

app.get('/health', (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ============================================================
// 🔐 AUTH ENDPOINTS (NEW - 2-Step Verification)
// ============================================================

app.post('/api/auth/challenge', async (req, res) => {
    console.log('📥 [CHALLENGE] Request received');
    
    if (isBrowser(req)) {
        return res.status(403).json({ success: false, error: "Forbidden" });
    }

    try {
        const { userId, hwid, placeId } = req.body;
        
        if (!userId || !hwid || !placeId) {
            return res.status(400).json({ success: false, error: "Missing fields" });
        }

        const userIdNum = parseInt(userId);
        const placeIdNum = parseInt(placeId);

        // Check blocked
        const blockInfo = blockedDevices.isBlocked(hwid, getClientIP(req), userIdNum);
        if (blockInfo.blocked) {
            logAccess(req, 'CHALLENGE_BLOCKED', false, { userId: userIdNum });
            return res.status(403).json({ success: false, error: "Access denied" });
        }

        // Check whitelist
        if (config.WHITELIST_USER_IDS.length > 0) {
            if (!config.WHITELIST_USER_IDS.includes(userIdNum)) {
                logAccess(req, 'CHALLENGE_NOT_WHITELISTED', false, { userId: userIdNum });
                return res.status(403).json({ success: false, error: "Not whitelisted" });
            }
        }

        // Check allowed games
        if (config.ALLOWED_PLACE_IDS.length > 0) {
            if (!config.ALLOWED_PLACE_IDS.includes(placeIdNum)) {
                logAccess(req, 'CHALLENGE_WRONG_GAME', false, { placeId: placeIdNum });
                return res.status(403).json({ success: false, error: "Game not allowed" });
            }
        }

        // Create challenge
        const challenge = challenges.create(userIdNum, hwid, placeIdNum, getClientIP(req));
        
        logAccess(req, 'CHALLENGE_ISSUED', true, { userId: userIdNum });

        res.json({
            success: true,
            challengeId: challenge.id,
            puzzle: challenge.puzzle,
            expiresIn: 60
        });

    } catch (error) {
        console.error('Challenge error:', error);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

app.post('/api/auth/verify', async (req, res) => {
    console.log('📥 [VERIFY] Request received');
    
    if (isBrowser(req)) {
        return res.status(403).json({ success: false, error: "Forbidden" });
    }

    try {
        const { challengeId, solution, timestamp } = req.body;
        
        if (!challengeId || solution === undefined || !timestamp) {
            return res.status(400).json({ success: false, error: "Missing fields" });
        }

        // Verify challenge
        const result = challenges.verify(challengeId, solution, getClientIP(req));
        
        if (!result.valid) {
            logAccess(req, 'VERIFY_FAILED', false, { error: result.error });
            return res.status(403).json({ success: false, error: result.error });
        }

        const challenge = result.challenge;
        console.log(`✅ [VERIFY] User ${challenge.userId} verified`);

        // Get script
        let script = scriptCache.get('main_script');
        
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) {
                return res.status(500).json({ success: false, error: "Server not configured" });
            }

            try {
                const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                    timeout: 15000,
                    headers: { 'User-Agent': 'Roblox/WinInet' }
                });
                script = response.data;
                scriptCache.set('main_script', script);
            } catch (fetchError) {
                console.error('Fetch error:', fetchError.message);
                return res.status(500).json({ success: false, error: "Failed to fetch script" });
            }
        }

        // Generate session key
        const sessionKey = generateSessionKey(
            challenge.userId, 
            challenge.hwid, 
            timestamp, 
            config.SECRET_KEY
        );

        // Encrypt script
        const chunks = [];
        const chunkSize = 2000;
        
        for (let i = 0; i < script.length; i += chunkSize) {
            const chunk = script.substring(i, i + chunkSize);
            const encrypted = [];
            for (let j = 0; j < chunk.length; j++) {
                encrypted.push(chunk.charCodeAt(j) ^ sessionKey.charCodeAt(j % sessionKey.length));
            }
            chunks.push(encrypted);
        }

        const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;

        logAccess(req, 'SCRIPT_SERVED_SECURE', true, { userId: challenge.userId });

        res.json({
            success: true,
            key: sessionKey,
            chunks: chunks,
            ownerIds: config.OWNER_USER_IDS,
            banEndpoint: `${serverUrl}/api/ban`
        });

    } catch (error) {
        console.error('Verify error:', error);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// ============================================================
// 📜 LOADER ENDPOINT (untuk 2-step auth)
// ============================================================

app.get('/loader', (req, res) => {
    console.log('📥 [LOADER] Request received');
    
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;

    const loaderScript = `--[[ Secure Loader v5.0 ]]
local SERVER = "${serverUrl}"
local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local StarterGui = game:GetService("StarterGui")
local LocalPlayer = Players.LocalPlayer

local function notify(title, text, duration)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title, Text = text, Duration = duration or 3
        })
    end)
end

local function getHWID()
    local ok, result = pcall(function()
        if gethwid then return gethwid() end
        if get_hwid then return get_hwid() end
        return "FALLBACK_" .. tostring(LocalPlayer.UserId)
    end)
    return ok and result or "UNKNOWN"
end

local function httpPost(url, data)
    local req = (syn and syn.request) or request or http_request
    if not req then return nil end
    
    local ok, response = pcall(function()
        return req({
            Url = url, Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = HttpService:JSONEncode(data)
        })
    end)
    
    if not ok or response.StatusCode ~= 200 then return nil end
    
    local parseOk, parsed = pcall(function()
        return HttpService:JSONDecode(response.Body)
    end)
    
    return parseOk and parsed or nil
end

local function xorDecrypt(data, key)
    local result = {}
    for i = 1, #data do
        result[i] = string.char(bit32.bxor(data[i], string.byte(key, ((i-1) % #key) + 1)))
    end
    return table.concat(result)
end

local function main()
    notify("🔄 Loading", "Connecting...", 2)
    
    local challengeData = httpPost(SERVER .. "/api/auth/challenge", {
        userId = LocalPlayer.UserId,
        hwid = getHWID(),
        placeId = game.PlaceId
    })
    
    if not challengeData or not challengeData.success then
        notify("❌ Error", challengeData and challengeData.error or "Connection failed", 5)
        if challengeData and challengeData.error == "Not whitelisted" then
            task.wait(1)
            LocalPlayer:Kick("⛔ Not Whitelisted")
        end
        return
    end
    
    local solution = 0
    for _, num in ipairs(challengeData.puzzle.numbers) do
        solution = solution + num
    end
    
    notify("🔄 Loading", "Verifying...", 2)
    
    local verifyData = httpPost(SERVER .. "/api/auth/verify", {
        challengeId = challengeData.challengeId,
        solution = solution,
        timestamp = os.time()
    })
    
    if not verifyData or not verifyData.success then
        notify("❌ Error", "Verification failed", 5)
        return
    end
    
    notify("✅ Verified", "Loading script...", 2)
    
    local parts = {}
    for i, chunk in ipairs(verifyData.chunks) do
        parts[i] = xorDecrypt(chunk, verifyData.key)
    end
    
    local fullScript = table.concat(parts)
    
    local OWNER_IDS = verifyData.ownerIds or {}
    if #OWNER_IDS > 0 then
        task.spawn(function()
            while task.wait(15) do
                for _, p in pairs(Players:GetPlayers()) do
                    for _, oid in ipairs(OWNER_IDS) do
                        if p.UserId == oid and p ~= LocalPlayer then
                            if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end
                            notify("⚠️ Stopped", "Owner detected", 3)
                            return
                        end
                    end
                end
            end
        end)
    end
    
    local fn = loadstring(fullScript)
    if fn then pcall(fn) end
end

main()
`;

    logAccess(req, 'LOADER_SERVED', true);
    res.type('text/plain').send(loaderScript);
});

// ============================================================
// 📜 LEGACY /script ENDPOINT (Kompatibel dengan kode lama)
// ============================================================

app.get('/script', async (req, res) => {
    console.log('📥 [SCRIPT] Request received (legacy endpoint)');
    
    if (isBrowser(req)) {
        logAccess(req, 'BROWSER_BLOCKED', false);
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const playerIdHeader = getPlayerID(req);
    const hwidHeader = getHWID(req);
    
    // Check whitelist
    let isWhitelisted = false;
    if (playerIdHeader && config.WHITELIST_USER_IDS.length > 0) {
        isWhitelisted = config.WHITELIST_USER_IDS.includes(parseInt(playerIdHeader));
    } else if (config.WHITELIST_USER_IDS.length === 0) {
        isWhitelisted = true; // No whitelist = allow all
    }

    // Check blocked
    if (!isWhitelisted) {
        const blockInfo = blockedDevices.isBlocked(hwidHeader, getClientIP(req), playerIdHeader);
        if (blockInfo.blocked) {
            logAccess(req, 'BLOCKED_DEVICE', false);
            return res.type('text/plain').send(`
game:GetService("Players").LocalPlayer:Kick("⛔ BANNED\\n\\nReason: ${blockInfo.reason}")
`);
        }
    }

    try {
        let script = scriptCache.get('main_script');
        
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) {
                console.error('❌ SCRIPT_SOURCE_URL not set!');
                return res.type('text/plain').send(`
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "⚠️ Error", Text = "Server not configured", Duration = 5
})
`);
            }
            
            console.log(`🔄 Fetching script...`);
            const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                timeout: 15000,
                headers: { 'User-Agent': 'Roblox/WinInet' }
            });
            
            script = response.data;
            scriptCache.set('main_script', script);
            console.log(`✅ Script cached (${script.length} bytes)`);
        }

        const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
        const timestamp = Date.now();
        
        // Generate session key jika ada HWID
        let sessionKey = null;
        if (hwidHeader && playerIdHeader) {
            sessionKey = generateSessionKey(playerIdHeader, hwidHeader, timestamp, config.SECRET_KEY);
        }

        const protectedScript = generateProtectedScript(script, {
            banEndpoint: `${serverUrl}/api/ban`,
            whitelistUserIds: config.WHITELIST_USER_IDS,
            ownerUserIds: config.OWNER_USER_IDS,
            allowedPlaceIds: config.ALLOWED_PLACE_IDS,
            sessionKey: sessionKey
        });

        logAccess(req, 'SCRIPT_SERVED', true, { 
            size: protectedScript.length,
            encrypted: !!sessionKey
        });
        
        res.type('text/plain').send(protectedScript);

    } catch (error) {
        console.error('Script error:', error.message);
        logAccess(req, 'SCRIPT_ERROR', false, { error: error.message });
        res.type('text/plain').send(`
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "❌ Error", Text = "Failed to load", Duration = 5
})
`);
    }
});

// ============================================================
// 🚫 BAN ENDPOINT
// ============================================================

app.post('/api/ban', (req, res) => {
    try {
        const { hwid, ip, playerId, playerName, reason, toolsDetected } = req.body;
        
        if (!hwid && !ip && !playerId) {
            return res.status(400).json({ error: "Missing identifier" });
        }
        
        const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
        
        blockedDevices.addBlock({
            hwid, ip: ip || getClientIP(req), playerId, playerName,
            reason: reason || 'Banned', toolsDetected: toolsDetected || [],
            banId, timestamp: new Date().toISOString()
        });
        
        console.log(`🔨 [BAN] ${playerName || playerId} - ${reason}`);
        logAccess(req, 'BANNED', true, { playerId, reason, banId });
        
        res.json({ success: true, banId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// 👑 ADMIN ROUTES
// ============================================================

function adminAuth(req, res, next) {
    const key = req.headers['x-admin-key'] || req.query.key;
    if (!key || !secureCompare(key, config.ADMIN_KEY)) {
        return res.status(403).json({ error: "Unauthorized" });
    }
    next();
}

app.get('/api/admin/stats', adminAuth, (req, res) => {
    res.json({ success: true, stats: db.getStats() });
});

app.get('/api/admin/logs', adminAuth, (req, res) => {
    res.json({ success: true, logs: db.getLogs(parseInt(req.query.limit) || 50) });
});

app.get('/api/admin/bans', adminAuth, (req, res) => {
    res.json({ success: true, bans: blockedDevices.getAll() });
});

app.delete('/api/admin/bans/:banId', adminAuth, (req, res) => {
    res.json({ success: blockedDevices.removeByBanId(req.params.banId) });
});

app.post('/api/admin/cache/clear', adminAuth, (req, res) => {
    scriptCache.flushAll();
    res.json({ success: true });
});

app.post('/api/admin/bans/clear', adminAuth, (req, res) => {
    blockedDevices.clearAll();
    res.json({ success: true });
});

// ============================================================
// 🔍 DEBUG
// ============================================================

app.get('/debug', (req, res) => {
    res.json({
        status: "ok",
        config: {
            hasScriptUrl: !!config.SCRIPT_SOURCE_URL,
            whitelistCount: config.WHITELIST_USER_IDS.length,
            ownerCount: config.OWNER_USER_IDS.length,
            allowedGamesCount: config.ALLOWED_PLACE_IDS.length
        },
        cached: scriptCache.has('main_script'),
        challenges: challenges.store.size,
        blocked: blockedDevices.count()
    });
});

// ============================================================
// 🚫 404
// ============================================================

app.use('*', (req, res) => {
    console.log(`⚠️ [404] ${req.method} ${req.originalUrl}`);
    if (isBrowser(req)) {
        return res.status(404).type('text/html').send(UNAUTHORIZED_HTML);
    }
    res.status(404).json({ error: "Not found", path: req.originalUrl });
});

// ============================================================
// 🚀 START
// ============================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════╗');
    console.log('║       🛡️  PREMIUM LOADER v5.0.0 - READY              ║');
    console.log('╠═══════════════════════════════════════════════════════╣');
    console.log(`║  🌐 Port: ${PORT}                                         ║`);
    console.log('║                                                       ║');
    console.log('║  📍 Endpoints:                                        ║');
    console.log('║     GET  /script  → Legacy (kompatibel lama)          ║');
    console.log('║     GET  /loader  → New secure loader                 ║');
    console.log('║     POST /api/auth/challenge → 2-step auth            ║');
    console.log('║     POST /api/auth/verify    → 2-step verify          ║');
    console.log('║                                                       ║');
    console.log(`║  ✅ SCRIPT_SOURCE_URL: ${config.SCRIPT_SOURCE_URL ? 'SET' : 'NOT SET!'}                      ║`);
    console.log(`║  👥 Whitelist: ${config.WHITELIST_USER_IDS.length} users                            ║`);
    console.log(`║  👑 Owners: ${config.OWNER_USER_IDS.length} users                               ║`);
    console.log('║                                                       ║');
    console.log('╚═══════════════════════════════════════════════════════╝');
    console.log('');
});

module.exports = app;
