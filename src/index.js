// ============================================================
// 🛡️ PREMIUM LOADER v5.1.0 - WITH OBFUSCATION SUPPORT
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
        *{margin:0;padding:0;box-sizing:border-box}
        body{background:#000;color:#fff;font-family:system-ui;height:100vh;display:flex;align-items:center;justify-content:center;text-align:center}
        h1{font-size:2rem;margin-bottom:1rem}
        p{color:#666}
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

function isScriptObfuscated(script) {
    if (!script || typeof script !== 'string') return false;
    
    // Check for common obfuscator signatures
    const obfuscatorPatterns = [
        /IronBrew/i,
        /Prometheus/i,
        /Moonsec/i,
        /Luraph/i,
        /PSU|PaidScriptUploader/i,
        /Aztup/i,
        // Common obfuscated patterns
        /^local \w{1,3}=\{/,                    // local a={
        /\\(\d{1,3})/,                          // \123 escape sequences
        /\["\\(\d+)/,                           // ["\123...]
        /local \w+="\\/,                        // local a="\...
        /getfenv\s*\(\s*\d+\s*\)/,             // getfenv(0)
        /string\.char\s*\(\s*\d+/,              // string.char(123
    ];
    
    for (const pattern of obfuscatorPatterns) {
        if (pattern.test(script)) return true;
    }
    
    // Check for high density of escape sequences (obfuscated indicator)
    const escapeCount = (script.match(/\\\d{1,3}/g) || []).length;
    if (escapeCount > 50 && script.length > 1000) return true;
    
    // Check for very long single lines (obfuscated scripts are often minified)
    const lines = script.split('\n');
    for (const line of lines) {
        if (line.length > 5000) return true;
    }
    
    return false;
}

// ============================================================
// 🏠 ROOT & HEALTH
// ============================================================

app.get('/', (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    res.json({ status: "online", version: "5.1.0" });
});

app.get('/health', (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.get('/debug', (req, res) => {
    res.json({
        status: "ok",
        version: "5.1.0",
        config: {
            hasScriptUrl: !!config.SCRIPT_SOURCE_URL,
            scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED,
            whitelistCount: config.WHITELIST_USER_IDS.length,
            ownerCount: config.OWNER_USER_IDS.length,
            allowedGamesCount: config.ALLOWED_PLACE_IDS.length
        },
        stats: db.getStats()
    });
});

// ============================================================
// 🔐 AUTH ENDPOINTS
// ============================================================

app.post('/api/auth/challenge', async (req, res) => {
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

        const blockInfo = blockedDevices.isBlocked(hwid, getClientIP(req), userIdNum);
        if (blockInfo.blocked) {
            logAccess(req, 'CHALLENGE_BLOCKED', false, { userId: userIdNum });
            return res.status(403).json({ success: false, error: "Access denied" });
        }

        if (config.WHITELIST_USER_IDS.length > 0) {
            if (!config.WHITELIST_USER_IDS.includes(userIdNum)) {
                logAccess(req, 'CHALLENGE_NOT_WHITELISTED', false, { userId: userIdNum });
                return res.status(403).json({ success: false, error: "Not whitelisted" });
            }
        }

        if (config.ALLOWED_PLACE_IDS.length > 0) {
            if (!config.ALLOWED_PLACE_IDS.includes(placeIdNum)) {
                logAccess(req, 'CHALLENGE_WRONG_GAME', false, { placeId: placeIdNum });
                return res.status(403).json({ success: false, error: "Game not allowed" });
            }
        }

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
    if (isBrowser(req)) {
        return res.status(403).json({ success: false, error: "Forbidden" });
    }

    try {
        const { challengeId, solution, timestamp } = req.body;
        
        if (!challengeId || solution === undefined || !timestamp) {
            return res.status(400).json({ success: false, error: "Missing fields" });
        }

        const result = challenges.verify(challengeId, solution, getClientIP(req));
        
        if (!result.valid) {
            logAccess(req, 'VERIFY_FAILED', false, { error: result.error });
            return res.status(403).json({ success: false, error: result.error });
        }

        const challenge = result.challenge;

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
                return res.status(500).json({ success: false, error: "Failed to fetch script" });
            }
        }

        const sessionKey = generateSessionKey(challenge.userId, challenge.hwid, timestamp, config.SECRET_KEY);
        const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;

        // Check if script is already obfuscated
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);

        if (alreadyObfuscated) {
            // Return script as-is with minimal wrapper
            logAccess(req, 'SCRIPT_SERVED_RAW', true, { userId: challenge.userId });
            
            return res.json({
                success: true,
                mode: 'raw',
                script: script,
                ownerIds: config.OWNER_USER_IDS,
                banEndpoint: `${serverUrl}/api/ban`
            });
        }

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

        logAccess(req, 'SCRIPT_SERVED_ENCRYPTED', true, { userId: challenge.userId });

        res.json({
            success: true,
            mode: 'encrypted',
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
// 📜 LOADER ENDPOINT
// ============================================================

app.get('/loader', (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;

    const loaderScript = `--[[ Secure Loader v5.1 ]]
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

local function setupOwnerProtection(ownerIds)
    if not ownerIds or #ownerIds == 0 then return end
    
    local function isOwner(uid)
        for _, id in ipairs(ownerIds) do
            if uid == id then return true end
        end
        return false
    end
    
    local function checkOwner()
        for _, p in pairs(Players:GetPlayers()) do
            if isOwner(p.UserId) and p ~= LocalPlayer then
                return true
            end
        end
        return false
    end
    
    if checkOwner() then
        notify("⚠️", "Cannot load here", 3)
        return false
    end
    
    task.spawn(function()
        while task.wait(15) do
            if checkOwner() then
                if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end
                notify("⚠️", "Owner detected", 3)
                break
            end
        end
    end)
    
    Players.PlayerAdded:Connect(function(p)
        task.wait(1)
        if isOwner(p.UserId) then
            if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end
            notify("⚠️", "Owner detected", 3)
        end
    end)
    
    return true
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
    
    -- Setup owner protection
    if not setupOwnerProtection(verifyData.ownerIds) then
        return
    end
    
    local fullScript
    
    if verifyData.mode == "raw" then
        -- Script sudah obfuscated, langsung pakai
        fullScript = verifyData.script
    else
        -- Decrypt chunks
        local parts = {}
        for i, chunk in ipairs(verifyData.chunks) do
            parts[i] = xorDecrypt(chunk, verifyData.key)
        end
        fullScript = table.concat(parts)
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
// 📜 LEGACY /script ENDPOINT
// ============================================================

app.get('/script', async (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const playerIdHeader = getPlayerID(req);
    const hwidHeader = getHWID(req);

    let isWhitelisted = config.WHITELIST_USER_IDS.length === 0 || 
        (playerIdHeader && config.WHITELIST_USER_IDS.includes(parseInt(playerIdHeader)));

    if (!isWhitelisted) {
        const blockInfo = blockedDevices.isBlocked(hwidHeader, getClientIP(req), playerIdHeader);
        if (blockInfo.blocked) {
            return res.type('text/plain').send(
                `game:GetService("Players").LocalPlayer:Kick("⛔ BANNED\\n\\n${blockInfo.reason}")`
            );
        }
    }

    try {
        let script = scriptCache.get('main_script');
        
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) {
                return res.type('text/plain').send(`
                    game:GetService("StarterGui"):SetCore("SendNotification", {
                        Title = "⚠️ Error", Text = "Not configured", Duration = 5
                    })
                `);
            }
            
            const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                timeout: 15000,
                headers: { 'User-Agent': 'Roblox/WinInet' }
            });
            
            script = response.data;
            scriptCache.set('main_script', script);
            console.log(`✅ Script cached (${script.length} bytes)`);
        }

        const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
        const ownerStr = config.OWNER_USER_IDS.join(', ');

        // Check if already obfuscated
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);

        if (alreadyObfuscated) {
            console.log('📦 [SCRIPT] RAW MODE - Script already obfuscated');
            
            const wrappedScript = `-- Secure Loader (Raw Mode) v5.1
local _O = {${ownerStr}}
local _P = game:GetService("Players")
local _L = _P.LocalPlayer
local _S = game:GetService("StarterGui")
local _A = true

local function _IO(u)
    for _,i in ipairs(_O) do if u==i then return true end end
    return false
end

local function _CO()
    if _IO(_L.UserId) then return false end
    for _,p in pairs(_P:GetPlayers()) do
        if _IO(p.UserId) and p~=_L then return true end
    end
    return false
end

if _CO() then
    _S:SetCore("SendNotification",{Title="⚠️",Text="Cannot load",Duration=3})
    return
end

task.spawn(function()
    while _A and task.wait(15) do
        for _,p in pairs(_P:GetPlayers()) do
            if _IO(p.UserId) and p~=_L then
                _A=false
                if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end
                _S:SetCore("SendNotification",{Title="⚠️",Text="Owner detected",Duration=3})
                return
            end
        end
    end
end)

_P.PlayerAdded:Connect(function(p)
    if _A and _IO(p.UserId) then
        _A=false
        if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end
        _S:SetCore("SendNotification",{Title="⚠️",Text="Owner detected",Duration=3})
    end
end)

${script}
`;

            logAccess(req, 'SCRIPT_SERVED_RAW', true, { size: wrappedScript.length });
            return res.type('text/plain').send(wrappedScript);
        }

        // Not obfuscated, use full protection
        console.log('📦 [SCRIPT] PROTECTED MODE');
        
        const timestamp = Date.now();
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

        logAccess(req, 'SCRIPT_SERVED_PROTECTED', true, { size: protectedScript.length });
        return res.type('text/plain').send(protectedScript);

    } catch (error) {
        console.error('Script error:', error.message);
        return res.type('text/plain').send(`
            game:GetService("StarterGui"):SetCore("SendNotification", {
                Title = "❌ Error", Text = "Failed", Duration = 5
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
    res.json({ success: true, message: "Cache cleared" });
});

app.post('/api/admin/bans/clear', adminAuth, (req, res) => {
    blockedDevices.clearAll();
    res.json({ success: true, message: "All bans cleared" });
});

// ============================================================
// 🚫 404
// ============================================================

app.use('*', (req, res) => {
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
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║        🛡️  PREMIUM LOADER v5.1.0 - READY                  ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  🌐 Port: ${PORT}                                              ║`);
    console.log('║                                                            ║');
    console.log('║  📍 Endpoints:                                             ║');
    console.log('║     GET  /script  → Legacy endpoint                        ║');
    console.log('║     GET  /loader  → Secure loader                          ║');
    console.log('║     GET  /debug   → Debug info                             ║');
    console.log('║                                                            ║');
    console.log(`║  ✅ SCRIPT_SOURCE_URL: ${config.SCRIPT_SOURCE_URL ? 'SET' : 'NOT SET!'}                          ║`);
    console.log(`║  ✅ SCRIPT_ALREADY_OBFUSCATED: ${config.SCRIPT_ALREADY_OBFUSCATED}                    ║`);
    console.log(`║  👥 Whitelist: ${config.WHITELIST_USER_IDS.length} users                                 ║`);
    console.log(`║  👑 Owners: ${config.OWNER_USER_IDS.length} users                                    ║`);
    console.log('║                                                            ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');
});

module.exports = app;
