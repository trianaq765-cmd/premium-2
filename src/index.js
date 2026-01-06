// ============================================================
// 🛡️ PREMIUM LOADER v5.0.0 - SECURE EDITION
// With 2-Step Verification & Roblox API Validation
// ============================================================

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const config = require('./config');
const { db, scriptCache, blockedDevices } = require('./database');
const { generateProtectedScript } = require('./protection');

const app = express();

// ============================================================
// 🔐 CHALLENGE STORE (In-Memory, gunakan Redis untuk production)
// ============================================================

const challengeStore = new Map();
const CHALLENGE_EXPIRY = 30000; // 30 detik

// Cleanup expired challenges
setInterval(() => {
    const now = Date.now();
    for (const [id, data] of challengeStore.entries()) {
        if (now - data.createdAt > CHALLENGE_EXPIRY) {
            challengeStore.delete(id);
        }
    }
}, 10000);

// ============================================================
// 🌐 UNAUTHORIZED HTML (tetap sama)
// ============================================================

const UNAUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Unauthorized | Premium Protect</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body, html {
            width: 100%; height: 100%; overflow: hidden;
            background-color: #000000;
            font-family: 'Inter', -apple-system, sans-serif;
            color: #ffffff;
        }
        .bg-layer {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(270deg, #000000, #0f172a, #000000);
            background-size: 600% 600%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }
        .container {
            position: relative; z-index: 10; height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px; user-select: none;
        }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #ffffff; font-size: 1.1rem; font-weight: 600;
            letter-spacing: 3px; text-transform: uppercase;
            margin-bottom: 25px;
        }
        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800; max-width: 700px;
            margin: 0 0 20px 0; line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p { color: rgba(255, 255, 255, 0.4); font-size: 1.1rem; margin: 0; }
        .icon { font-size: 1.4rem; }
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>
    <div class="container">
        <div class="auth-label">
            <span class="icon">⛔</span>
            Not Authorized
            <span class="icon">⛔</span>
        </div>
        <h1>You are not allowed to view these files.</h1>
        <p>Close this page & proceed.</p>
    </div>
</body>
</html>`;

// ============================================================
// 🔧 MIDDLEWARE (tetap sama + tambahan)
// ============================================================

app.use(helmet({ 
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false 
}));

app.use(cors({ 
    origin: '*', 
    methods: ['GET', 'POST', 'DELETE', 'PUT'], 
    allowedHeaders: ['Content-Type', 'x-admin-key', 'Authorization'] 
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

// Rate limiter lebih ketat untuk auth endpoints
const authLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10, // Hanya 10 request per menit untuk auth
    message: { success: false, error: "Too many attempts" },
    keyGenerator: (req) => getClientIP(req)
});

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: { success: false, error: "Too many requests" },
    keyGenerator: (req) => getClientIP(req)
});

app.use('/api/auth/', authLimiter);
app.use('/api/', generalLimiter);

// ============================================================
// 🔧 HELPER FUNCTIONS
// ============================================================

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.ip || 
           'unknown';
}

function logAccess(req, action, success, details = {}) {
    const log = { 
        ip: getClientIP(req), 
        userAgent: req.headers['user-agent'] || 'unknown', 
        action, 
        success, 
        method: req.method, 
        path: req.path,
        timestamp: new Date().toISOString(),
        ...details 
    };
    db.addLog(log);
    console.log(`[${log.timestamp}] ${success ? '✅' : '❌'} ${action} | IP: ${log.ip}`);
    return log;
}

function isBrowser(req) {
    const accept = req.headers['accept'] || '';
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    
    const executorKeywords = [
        'roblox', 'synapse', 'krnl', 'fluxus', 'delta', 
        'electron', 'script-ware', 'sentinel', 'coco', 
        'oxygen', 'evon', 'arceus', 'hydrogen', 'vegax',
        'trigon', 'comet', 'jjsploit', 'wearedevs', 
        'executor', 'exploit', 'wininet', 'solara', 'wave',
        'zorara', 'codex', 'nihon', 'celery', 'swift'
    ];
    
    if (executorKeywords.some(keyword => userAgent.includes(keyword))) {
        return false;
    }
    
    if (accept.includes('text/html')) {
        const hasBrowserUA = userAgent.includes('mozilla') || 
                             userAgent.includes('chrome') || 
                             userAgent.includes('safari') ||
                             userAgent.includes('firefox') ||
                             userAgent.includes('edge');
        
        if (hasBrowserUA && !!req.headers['accept-language']) {
            return true;
        }
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
// 🔐 CRYPTO FUNCTIONS
// ============================================================

function generateChallenge() {
    const id = crypto.randomBytes(16).toString('hex');
    const numbers = [];
    for (let i = 0; i < 4; i++) {
        numbers.push(crypto.randomInt(1, 100));
    }
    const expectedSum = numbers.reduce((a, b) => a + b, 0);
    
    return {
        id,
        puzzle: { numbers, operation: 'sum' },
        solution: expectedSum,
        createdAt: Date.now()
    };
}

function xorEncrypt(text, key) {
    const result = [];
    for (let i = 0; i < text.length; i++) {
        const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
        result.push(charCode);
    }
    return result;
}

function generateSessionKey(userId, hwid, timestamp) {
    const data = `${userId}-${hwid}-${timestamp}-${config.SECRET_KEY || 'default'}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 32);
}

// ============================================================
// 🔍 ROBLOX API VERIFICATION (PENTING!)
// ============================================================

async function verifyRobloxUser(userId) {
    try {
        const response = await axios.get(
            `https://users.roblox.com/v1/users/${userId}`,
            { timeout: 5000 }
        );
        
        if (response.data && response.data.id) {
            return {
                valid: true,
                username: response.data.name,
                displayName: response.data.displayName,
                id: response.data.id
            };
        }
        return { valid: false };
    } catch (error) {
        console.warn(`⚠️ Roblox API check failed for ${userId}:`, error.message);
        // Jika API down, fallback ke allow (optional, bisa di-deny)
        return { valid: true, fallback: true };
    }
}

async function verifyUserInGame(userId, placeId) {
    try {
        // Check user's current game (jika memungkinkan)
        // Roblox API terbatas untuk ini, tapi bisa cek presence
        const response = await axios.post(
            'https://presence.roblox.com/v1/presence/users',
            { userIds: [userId] },
            { timeout: 5000 }
        );
        
        if (response.data && response.data.userPresences) {
            const presence = response.data.userPresences[0];
            if (presence && presence.placeId === placeId) {
                return { valid: true, inGame: true };
            }
        }
        
        // Presence check gagal, tapi user mungkin tetap valid
        return { valid: true, inGame: false };
    } catch (error) {
        return { valid: true, inGame: false }; // Fallback
    }
}

// ============================================================
// 🚀 STEP 1: REQUEST CHALLENGE
// ============================================================

app.post('/api/auth/challenge', async (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).json({ success: false, error: "Forbidden" });
    }

    try {
        const { userId, hwid, placeId } = req.body;
        
        // Validasi input
        if (!userId || !hwid || !placeId) {
            logAccess(req, 'CHALLENGE_INVALID_INPUT', false);
            return res.status(400).json({ 
                success: false, 
                error: "Missing required fields" 
            });
        }

        const userIdNum = parseInt(userId);
        const placeIdNum = parseInt(placeId);
        
        if (isNaN(userIdNum) || isNaN(placeIdNum)) {
            return res.status(400).json({ 
                success: false, 
                error: "Invalid ID format" 
            });
        }

        // Cek blocked
        if (blockedDevices.isBlocked(hwid, getClientIP(req), userIdNum)) {
            logAccess(req, 'CHALLENGE_BLOCKED', false, { userId: userIdNum });
            return res.status(403).json({ 
                success: false, 
                error: "Access denied" 
            });
        }

        // ✅ VERIFIKASI ROBLOX USER (PENTING!)
        const robloxUser = await verifyRobloxUser(userIdNum);
        if (!robloxUser.valid) {
            logAccess(req, 'CHALLENGE_INVALID_USER', false, { userId: userIdNum });
            return res.status(403).json({ 
                success: false, 
                error: "Invalid user" 
            });
        }

        // Cek whitelist
        const whitelistEnv = process.env.WHITELIST_USER_IDS || '';
        const whitelistUserIds = whitelistEnv
            .split(',')
            .map(id => parseInt(id.trim()))
            .filter(id => !isNaN(id));
        
        const isWhitelisted = whitelistUserIds.includes(userIdNum);
        
        if (!isWhitelisted && whitelistUserIds.length > 0) {
            logAccess(req, 'CHALLENGE_NOT_WHITELISTED', false, { 
                userId: userIdNum,
                username: robloxUser.username 
            });
            return res.status(403).json({ 
                success: false, 
                error: "Not whitelisted" 
            });
        }

        // Cek allowed games
        const allowedGamesEnv = process.env.ALLOWED_PLACE_IDS || '';
        const allowedGames = allowedGamesEnv
            .split(',')
            .map(id => parseInt(id.trim()))
            .filter(id => !isNaN(id));
        
        if (allowedGames.length > 0 && !allowedGames.includes(placeIdNum)) {
            logAccess(req, 'CHALLENGE_WRONG_GAME', false, { 
                userId: userIdNum,
                placeId: placeIdNum 
            });
            return res.status(403).json({ 
                success: false, 
                error: "Game not allowed" 
            });
        }

        // Generate challenge
        const challenge = generateChallenge();
        
        // Store dengan metadata
        challengeStore.set(challenge.id, {
            ...challenge,
            userId: userIdNum,
            hwid,
            placeId: placeIdNum,
            ip: getClientIP(req),
            username: robloxUser.username
        });

        logAccess(req, 'CHALLENGE_ISSUED', true, { 
            challengeId: challenge.id,
            userId: userIdNum,
            username: robloxUser.username
        });

        // Kirim puzzle (BUKAN solusi!)
        res.json({
            success: true,
            challengeId: challenge.id,
            puzzle: challenge.puzzle,
            expiresIn: 30
        });

    } catch (error) {
        console.error('Challenge error:', error);
        logAccess(req, 'CHALLENGE_ERROR', false, { error: error.message });
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// ============================================================
// 🚀 STEP 2: VERIFY & GET SCRIPT
// ============================================================

app.post('/api/auth/verify', async (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).json({ success: false, error: "Forbidden" });
    }

    try {
        const { challengeId, solution, timestamp } = req.body;
        
        if (!challengeId || solution === undefined || !timestamp) {
            return res.status(400).json({ 
                success: false, 
                error: "Missing fields" 
            });
        }

        // Ambil challenge
        const challenge = challengeStore.get(challengeId);
        
        if (!challenge) {
            logAccess(req, 'VERIFY_INVALID_CHALLENGE', false);
            return res.status(400).json({ 
                success: false, 
                error: "Invalid or expired challenge" 
            });
        }

        // Cek expiry
        if (Date.now() - challenge.createdAt > CHALLENGE_EXPIRY) {
            challengeStore.delete(challengeId);
            logAccess(req, 'VERIFY_EXPIRED', false);
            return res.status(400).json({ 
                success: false, 
                error: "Challenge expired" 
            });
        }

        // Cek IP sama
        if (challenge.ip !== getClientIP(req)) {
            challengeStore.delete(challengeId);
            logAccess(req, 'VERIFY_IP_MISMATCH', false);
            return res.status(403).json({ 
                success: false, 
                error: "IP mismatch" 
            });
        }

        // Verify solution
        if (parseInt(solution) !== challenge.solution) {
            challengeStore.delete(challengeId);
            logAccess(req, 'VERIFY_WRONG_SOLUTION', false, { 
                userId: challenge.userId 
            });
            return res.status(403).json({ 
                success: false, 
                error: "Invalid solution" 
            });
        }

        // Hapus challenge (one-time use)
        challengeStore.delete(challengeId);

        // ✅ Semua valid! Siapkan script
        console.log(`✅ [VERIFIED] User: ${challenge.username} (${challenge.userId})`);

        // Ambil script
        let script = scriptCache.get('main_script');
        
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) {
                return res.status(500).json({ 
                    success: false, 
                    error: "Server not configured" 
                });
            }

            try {
                const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                    timeout: 15000,
                    headers: { 'User-Agent': 'Roblox/WinInet' }
                });
                script = response.data;
                scriptCache.set('main_script', script);
            } catch (fetchError) {
                return res.status(500).json({ 
                    success: false, 
                    error: "Failed to fetch script" 
                });
            }
        }

        // Generate session key
        const sessionKey = generateSessionKey(
            challenge.userId, 
            challenge.hwid, 
            timestamp
        );

        // Encrypt script
        const encryptedChunks = [];
        const chunkSize = 1000;
        
        for (let i = 0; i < script.length; i += chunkSize) {
            const chunk = script.substring(i, i + chunkSize);
            const encrypted = xorEncrypt(chunk, sessionKey);
            encryptedChunks.push(encrypted);
        }

        // Generate checksum
        const checksum = crypto
            .createHash('md5')
            .update(script)
            .digest('hex');

        const serverUrl = process.env.RENDER_EXTERNAL_URL || 
                          `${req.protocol}://${req.get('host')}`;

        // Parse owner IDs
        const ownerEnv = process.env.OWNER_USER_IDS || '';
        const ownerUserIds = ownerEnv
            .split(',')
            .map(id => parseInt(id.trim()))
            .filter(id => !isNaN(id));

        logAccess(req, 'SCRIPT_SERVED', true, { 
            userId: challenge.userId,
            username: challenge.username,
            placeId: challenge.placeId
        });

        res.json({
            success: true,
            key: sessionKey,
            chunks: encryptedChunks,
            checksum,
            ownerIds: ownerUserIds,
            banEndpoint: `${serverUrl}/api/ban`,
            meta: {
                userId: challenge.userId,
                username: challenge.username,
                expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 jam
            }
        });

    } catch (error) {
        console.error('Verify error:', error);
        logAccess(req, 'VERIFY_ERROR', false, { error: error.message });
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// ============================================================
// 🚀 LOADER SCRIPT (untuk di-loadstring user)
// ============================================================

app.get('/loader', (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const serverUrl = process.env.RENDER_EXTERNAL_URL || 
                      `${req.protocol}://${req.get('host')}`;

    // Ini adalah loader yang akan di-loadstring user
    const loaderScript = `--[[ Secure Loader v5.0 ]]
local SERVER = "${serverUrl}"
local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local StarterGui = game:GetService("StarterGui")
local LocalPlayer = Players.LocalPlayer

-- Notify
local function notify(title, text, duration)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title,
            Text = text,
            Duration = duration or 3
        })
    end)
end

-- Get HWID
local function getHWID()
    local ok, result = pcall(function()
        if gethwid then return gethwid() end
        if get_hwid then return get_hwid() end
        if getexecutorname then
            return getexecutorname() .. "_" .. tostring(LocalPlayer.UserId)
        end
        return "FALLBACK_" .. tostring(LocalPlayer.UserId) .. "_" .. tostring(os.time())
    end)
    return ok and result or "ERROR"
end

-- HTTP Request
local function httpRequest(url, method, body)
    local req = syn and syn.request or request or http_request or http.request
    if not req then return nil, "No HTTP" end
    
    local ok, result = pcall(function()
        return req({
            Url = url,
            Method = method or "GET",
            Headers = { ["Content-Type"] = "application/json" },
            Body = body and HttpService:JSONEncode(body) or nil
        })
    end)
    
    if ok and result then
        local parseOk, data = pcall(function()
            return HttpService:JSONDecode(result.Body)
        end)
        return parseOk and data or nil, result.StatusCode
    end
    return nil, "Request failed"
end

-- XOR Decrypt
local function xorDecrypt(data, key)
    local result = {}
    for i = 1, #data do
        local byte = data[i]
        local keyByte = string.byte(key, ((i - 1) % #key) + 1)
        result[i] = string.char(bit32.bxor(byte, keyByte))
    end
    return table.concat(result)
end

-- Main
local function main()
    notify("🔄 Loading", "Requesting access...", 2)
    
    -- Step 1: Get challenge
    local challengeData, err1 = httpRequest(
        SERVER .. "/api/auth/challenge",
        "POST",
        {
            userId = LocalPlayer.UserId,
            hwid = getHWID(),
            placeId = game.PlaceId
        }
    )
    
    if not challengeData or not challengeData.success then
        local errorMsg = challengeData and challengeData.error or "Connection failed"
        notify("❌ Error", errorMsg, 5)
        
        if errorMsg == "Not whitelisted" or errorMsg == "Access denied" then
            task.wait(1)
            LocalPlayer:Kick("⛔ Access Denied\\n\\n" .. errorMsg)
        end
        return false
    end
    
    -- Step 2: Solve puzzle
    local puzzle = challengeData.puzzle
    local solution = 0
    
    if puzzle.operation == "sum" then
        for _, num in ipairs(puzzle.numbers) do
            solution = solution + num
        end
    end
    
    notify("🔄 Loading", "Verifying...", 2)
    
    -- Step 3: Verify & get script
    local verifyData, err2 = httpRequest(
        SERVER .. "/api/auth/verify",
        "POST",
        {
            challengeId = challengeData.challengeId,
            solution = solution,
            timestamp = os.time()
        }
    )
    
    if not verifyData or not verifyData.success then
        notify("❌ Error", verifyData and verifyData.error or "Verification failed", 5)
        return false
    end
    
    -- Step 4: Decrypt script
    notify("✅ Verified", "Loading script...", 2)
    
    local decryptedParts = {}
    for i, chunk in ipairs(verifyData.chunks) do
        local decrypted = xorDecrypt(chunk, verifyData.key)
        decryptedParts[i] = decrypted
    end
    
    local fullScript = table.concat(decryptedParts)
    
    -- Step 5: Verify checksum (optional)
    -- Note: MD5 di Lua butuh library external, skip untuk simplicity
    
    -- Step 6: Setup owner protection
    local OWNER_IDS = verifyData.ownerIds or {}
    
    task.spawn(function()
        while task.wait(10) do
            for _, p in pairs(Players:GetPlayers()) do
                for _, ownerId in ipairs(OWNER_IDS) do
                    if p.UserId == ownerId and p ~= LocalPlayer then
                        if _G._SCRIPT_CLEANUP then
                            pcall(_G._SCRIPT_CLEANUP)
                        end
                        notify("⚠️ Stopping", "Owner detected", 3)
                        return
                    end
                end
            end
        end
    end)
    
    -- Step 7: Execute
    local fn, err = loadstring(fullScript)
    if fn then
        local ok, execErr = pcall(fn)
        if not ok then
            warn("Execution error:", execErr)
        end
        return ok
    else
        warn("Loadstring error:", err)
        return false
    end
end

-- Run
main()
`;

    logAccess(req, 'LOADER_SERVED', true);
    res.type('text/plain').send(loaderScript);
});

// ============================================================
// 🚫 BAN ENDPOINT (tetap sama)
// ============================================================

app.post('/api/ban', (req, res) => {
    try {
        const { hwid, ip, playerId, playerName, reason, toolsDetected } = req.body;
        
        if (!hwid && !ip && !playerId) {
            return res.status(400).json({ error: "Missing identifier" });
        }
        
        const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
        
        blockedDevices.addBlock({
            hwid,
            ip: ip || getClientIP(req),
            playerId,
            playerName,
            reason: reason || 'Malicious tools detected',
            toolsDetected: toolsDetected || [],
            banId,
            timestamp: new Date().toISOString()
        });
        
        logAccess(req, 'DEVICE_BANNED', true, { hwid, playerId, playerName, reason, banId });
        console.log(`🔨 [BAN] Player: ${playerName} | Reason: ${reason}`);
        
        res.json({ success: true, banId });
    } catch (error) {
        console.error('Ban error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// 🌐 ROOT & HEALTH
// ============================================================

app.get('/', (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.json({
        status: "online",
        name: "Premium Loader",
        version: "5.0.0",
        secure: true
    });
});

app.get('/health', (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ============================================================
// 👑 ADMIN ROUTES (tetap sama)
// ============================================================

function adminAuth(req, res, next) {
    const adminKey = req.headers['x-admin-key'] || req.query.key;
    
    if (!adminKey || !secureCompare(adminKey, config.ADMIN_KEY)) {
        logAccess(req, 'ADMIN_AUTH_FAILED', false);
        return res.status(403).json({ error: "Invalid admin key" });
    }
    
    next();
}

app.post('/api/admin/cache/clear', adminAuth, (req, res) => {
    scriptCache.flushAll();
    logAccess(req, 'CACHE_CLEARED', true);
    res.json({ success: true, message: "Cache cleared" });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
    res.json({ 
        success: true, 
        stats: db.getStats(),
        activeChallenges: challengeStore.size,
        blockedDevices: blockedDevices.count()
    });
});

app.get('/api/admin/bans', adminAuth, (req, res) => {
    res.json({ success: true, bans: blockedDevices.getAll() });
});

app.delete('/api/admin/bans/:banId', adminAuth, (req, res) => {
    const removed = blockedDevices.removeByBanId(req.params.banId);
    res.json({ success: removed });
});

// ============================================================
// 🚫 CATCH-ALL
// ============================================================

app.use('*', (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    res.status(404).json({ error: "Not found" });
});

// ============================================================
// 🚀 START SERVER
// ============================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║      🛡️  PREMIUM LOADER v5.0.0 - SECURE EDITION         ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
    console.log(`║  🌐 Port: ${PORT}                                            ║`);
    console.log('║                                                          ║');
    console.log('║  ✅ 2-Step Verification                                   ║');
    console.log('║  ✅ Roblox API Validation                                 ║');
    console.log('║  ✅ Challenge-Response System                             ║');
    console.log('║  ✅ XOR Encryption                                        ║');
    console.log('║  ✅ Session-based Keys                                    ║');
    console.log('║  ✅ IP Verification                                       ║');
    console.log('║                                                          ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
});

module.exports = app;
