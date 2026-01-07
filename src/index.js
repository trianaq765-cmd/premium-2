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
// 🔐 ANTI-SCRAPER: Session & Token Store
// ============================================================
const pendingTokens = new Map();  // Untuk validasi 2-step
const validatedSessions = new Map(); // Session yang sudah tervalidasi

// Cleanup expired tokens setiap 5 menit
setInterval(() => {
    const now = Date.now();
    for (const [key, data] of pendingTokens.entries()) {
        if (now - data.created > 60000) pendingTokens.delete(key);
    }
    for (const [key, data] of validatedSessions.entries()) {
        if (now - data.created > 300000) validatedSessions.delete(key);
    }
}, 300000);

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
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            color: #ffffff;
        }
        .bg-layer {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(270deg, #000000, #0f172a, #1e1b4b, #0f172a, #000000);
            background-size: 800% 800%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }
        .container {
            position: relative; z-index: 10; height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px; user-select: none;
        }
        .shield { font-size: 4rem; margin-bottom: 20px; }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #ef4444; font-size: 1.1rem; font-weight: 600;
            letter-spacing: 3px; text-transform: uppercase;
            margin-bottom: 25px;
        }
        h1 { color: #ffffff; font-size: 2rem; font-weight: 800; margin: 0 0 20px 0; }
        p { color: rgba(255, 255, 255, 0.4); font-size: 1.1rem; }
        .code { margin-top: 30px; padding: 15px 30px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: rgba(255, 255, 255, 0.6); }
        @keyframes gradientShift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
    </style>
</head>
<body>
    <div class="bg-layer"></div>
    <div class="container">
        <div class="shield">🛡️</div>
        <div class="auth-label"><span>⛔</span> Access Denied <span>⛔</span></div>
        <h1>You are not authorized to view this resource.</h1>
        <p>This endpoint is protected and requires valid executor authentication.</p>
        <div class="code">Error Code: 403 | Forbidden</div>
    </div>
</body>
</html>`;

// ============================================================
// 🛡️ FAKE SCRIPT - Untuk Bot/Scraper
// ============================================================
const FAKE_SCRIPT = `--[[ 
    Premium Script Loader v5.4.4
    Protected by Advanced Anti-Tamper
]]

print("Loading...")
task.wait(2)
print("Initializing security checks...")
task.wait(1)

-- This is a decoy script for scrapers/bots
-- Real script requires valid Roblox environment

local function init()
    local success, err = pcall(function()
        game:GetService("Players").LocalPlayer:Kick("Session expired. Please re-execute.")
    end)
end

init()`;

const HONEYPOT_SCRIPT = `--[[ Protected Script ]]
local _=[[
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
This script is protected and requires valid authentication
Contact admin for access
]]
print(_)`;

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'PUT', 'PATCH'], allowedHeaders: ['Content-Type', 'x-admin-key', 'Authorization', 'x-hwid', 'x-player-id', 'x-place-id', 'x-executor', 'x-roblox-token', 'x-session-token', 'x-game-data'] }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.set('trust proxy', 1);

const authLimiter = rateLimit({ windowMs: 60000, max: 20, message: { success: false, error: "Too many attempts" }, keyGenerator: (req) => getClientIP(req) });
const generalLimiter = rateLimit({ windowMs: 60000, max: 100, message: { success: false, error: "Too many requests" }, keyGenerator: (req) => getClientIP(req) });
const strictLimiter = rateLimit({ windowMs: 60000, max: 10, message: { success: false, error: "Rate limit exceeded" }, keyGenerator: (req) => getClientIP(req) });

// Rate limiter khusus untuk loader - sangat ketat
const loaderLimiter = rateLimit({ 
    windowMs: 60000, 
    max: 5, 
    message: '--[[ Rate Limited ]]', 
    keyGenerator: (req) => getClientIP(req),
    handler: (req, res) => {
        logAccess(req, 'LOADER_RATE_LIMITED', false);
        res.type('text/plain').send(FAKE_SCRIPT);
    }
});

app.use('/api/auth/', authLimiter);
app.use('/api/ban', strictLimiter);
app.use('/api/loader', loaderLimiter);
app.use('/loader', loaderLimiter);
app.use('/api/', generalLimiter);

function getClientIP(req) { const f = req.headers['x-forwarded-for']; return f ? f.split(',')[0].trim() : req.headers['x-real-ip'] || req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip || 'unknown'; }
function getHWID(req) { return req.headers['x-hwid'] || req.query.hwid || req.body?.hwid || null; }
function getPlayerID(req) { return req.headers['x-player-id'] || req.query.pid || req.body?.playerId || null; }
function logAccess(req, action, success, details = {}) { const log = { ip: getClientIP(req), hwid: getHWID(req), playerId: getPlayerID(req), userAgent: req.headers['user-agent']?.substring(0, 100) || 'unknown', action, success, method: req.method, path: req.path, timestamp: new Date().toISOString(), ...details }; db.addLog(log); return log; }

// ============================================================
// 🛡️ ADVANCED ANTI-BOT DETECTION
// ============================================================

// Deteksi pattern request yang mencurigakan
function detectSuspiciousRequest(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    const acceptLang = req.headers['accept-language'] || '';
    const acceptEnc = req.headers['accept-encoding'] || '';
    
    const suspicionScore = {
        score: 0,
        reasons: []
    };
    
    // 1. Browser headers tapi claim executor
    if (acceptLang && (accept.includes('text/html') || accept.includes('application/xml'))) {
        suspicionScore.score += 30;
        suspicionScore.reasons.push('browser_headers');
    }
    
    // 2. Accept header terlalu generic atau web-like
    if (accept.includes('text/html') || accept.includes('application/xhtml')) {
        suspicionScore.score += 25;
        suspicionScore.reasons.push('html_accept');
    }
    
    // 3. Punya accept-language (browser biasanya punya, executor tidak)
    if (acceptLang && acceptLang.length > 0) {
        suspicionScore.score += 20;
        suspicionScore.reasons.push('has_accept_language');
    }
    
    // 4. User-Agent pattern analysis
    const botPatterns = [
        /bot/i, /crawler/i, /spider/i, /scraper/i,
        /python/i, /node/i, /axios/i, /fetch/i, /request/i,
        /curl/i, /wget/i, /postman/i, /insomnia/i,
        /discord/i, /telegram/i, /slack/i,
        /http/i, /client/i
    ];
    
    for (const pattern of botPatterns) {
        if (pattern.test(ua)) {
            suspicionScore.score += 40;
            suspicionScore.reasons.push(`ua_pattern:${pattern.source}`);
            break;
        }
    }
    
    // 5. Missing headers yang biasa ada di HTTP client
    if (!req.headers['connection']) {
        suspicionScore.score += 5;
        suspicionScore.reasons.push('no_connection_header');
    }
    
    // 6. Referer header (executor tidak punya, browser punya)
    if (req.headers['referer'] || req.headers['origin']) {
        suspicionScore.score += 30;
        suspicionScore.reasons.push('has_referer_or_origin');
    }
    
    // 7. Cookie header (executor tidak punya)
    if (req.headers['cookie']) {
        suspicionScore.score += 25;
        suspicionScore.reasons.push('has_cookie');
    }
    
    // 8. Sec- headers (browser modern punya)
    const secHeaders = ['sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-ch-ua'];
    for (const h of secHeaders) {
        if (req.headers[h]) {
            suspicionScore.score += 20;
            suspicionScore.reasons.push(`has_${h}`);
        }
    }
    
    // 9. Empty atau terlalu pendek User-Agent
    if (!ua || ua.length < 5) {
        suspicionScore.score += 15;
        suspicionScore.reasons.push('short_ua');
    }
    
    // 10. Request timing analysis (jika terlalu cepat setelah server start)
    const uptimeSeconds = process.uptime();
    if (uptimeSeconds < 10) {
        suspicionScore.score += 10;
        suspicionScore.reasons.push('early_request');
    }
    
    return suspicionScore;
}

// Validasi apakah request kemungkinan dari Roblox executor
function isLikelyRobloxExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    
    // Pattern yang HARUS ada untuk executor
    const requiredPatterns = [
        'roblox', 'wininet', 'win32', 'windows',
        'synapse', 'krnl', 'fluxus', 'delta', 'electron',
        'script-ware', 'sentinel', 'oxygen', 'evon',
        'arceus', 'hydrogen', 'vegax', 'trigon', 'comet',
        'solara', 'wave', 'zorara', 'codex', 'celery',
        'swift', 'sirhurt'
    ];
    
    const hasValidUA = requiredPatterns.some(p => ua.includes(p));
    
    // Headers yang TIDAK boleh ada
    const forbiddenHeaders = [
        'accept-language',  // Browser header
        'sec-fetch-dest',   // Browser security header
        'sec-fetch-mode',
        'sec-ch-ua',        // Chrome UA hints
        'referer',          // Biasanya browser
        'origin',           // CORS header dari browser
    ];
    
    for (const h of forbiddenHeaders) {
        if (req.headers[h]) {
            return { valid: false, reason: `forbidden_header:${h}` };
        }
    }
    
    if (!hasValidUA) {
        return { valid: false, reason: 'invalid_ua_pattern' };
    }
    
    return { valid: true };
}

function isBrowser(req) {
    const accept = req.headers['accept'] || '';
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    if (accept.includes('text/html') && req.headers['accept-language']) {
        const browsers = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera'];
        return browsers.some(b => ua.includes(b));
    }
    return false;
}

function secureCompare(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }

function isScriptObfuscated(script) { if (!script || typeof script !== 'string') return false; const patterns = [/IronBrew/i, /Prometheus/i, /Moonsec/i, /Luraph/i, /PSU|PaidScriptUploader/i, /Aztup/i, /Synapse Xen/i, /-- Obfuscated/i, /-- Protected/i]; for (const p of patterns) if (p.test(script.substring(0, 500))) return true; const code = [/^local \w{1,3}=\{/, /getfenv\s*\(\s*\d+\s*\)/, /string\.char\s*\(\s*\d+/, /loadstring\s*\(\s*['"]\\x/, /\[\[.{100,}\]\]/]; for (const p of code) if (p.test(script)) return true; if ((script.match(/\\\d{1,3}/g) || []).length > 100 && script.length > 2000) return true; for (const line of script.split('\n')) if (line.length > 10000) return true; if ((script.match(/[a-zA-Z]/g) || []).length / script.length < 0.3 && script.length > 1000) return true; return false; }

function isDeviceBlocked(req) { return blockedDevices.isBlocked(getHWID(req), getClientIP(req), getPlayerID(req)); }

async function verifyRobloxUser(userId) { try { const r = await axios.get(`https://users.roblox.com/v1/users/${userId}`, { timeout: 5000 }); if (r.data?.id) return { valid: true, id: r.data.id, username: r.data.name, displayName: r.data.displayName }; return { valid: false }; } catch { return { valid: true, fallback: true }; } }

// ============================================================
// 🔐 TOKEN GENERATION - Untuk 2-Step Verification
// ============================================================
function generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateTimeBasedChallenge() {
    const timestamp = Date.now();
    const random = crypto.randomBytes(16).toString('hex');
    const numbers = [];
    for (let i = 0; i < 5; i++) {
        numbers.push(Math.floor(Math.random() * 100) + 1);
    }
    
    return {
        id: crypto.randomBytes(16).toString('hex'),
        timestamp,
        random,
        puzzle: { numbers, operation: 'sum' },
        expectedAnswer: numbers.reduce((a, b) => a + b, 0)
    };
}

// ============================================================
// 🌐 BASIC ENDPOINTS
// ============================================================
app.get('/', (req, res) => {
    if (isBrowser(req)) return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    
    const suspicion = detectSuspiciousRequest(req);
    if (suspicion.score >= 30) {
        logAccess(req, 'ROOT_SUSPICIOUS', false, { score: suspicion.score, reasons: suspicion.reasons });
        return res.status(403).json({ error: "Forbidden" });
    }
    
    res.json({ status: "online", version: "5.5.0", protected: true });
});

app.get('/health', (req, res) => { res.json({ status: "ok", uptime: Math.floor(process.uptime()) }); });

app.get('/api/health', (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    if (suspicion.score >= 30) return res.status(403).json({ error: "Forbidden" });
    res.json({ status: "healthy", cached: scriptCache.has('main_script'), stats: db.getStats() });
});

app.get('/debug', (req, res) => {
    res.json({
        status: "ok",
        version: "5.5.0",
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
// 🔐 NEW: STEP 1 - Initialize Session (Loader akan call ini dulu)
// ============================================================
app.post('/api/init', (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    
    // Jika sangat mencurigakan, kirim fake response
    if (suspicion.score >= 40) {
        logAccess(req, 'INIT_BLOCKED_SUSPICIOUS', false, { score: suspicion.score, reasons: suspicion.reasons });
        // Delay response untuk confuse bot
        setTimeout(() => {
            res.json({ 
                success: true, 
                token: crypto.randomBytes(32).toString('hex'),
                challenge: { fake: true }
            });
        }, Math.random() * 2000 + 1000);
        return;
    }
    
    const validExecutor = isLikelyRobloxExecutor(req);
    if (!validExecutor.valid) {
        logAccess(req, 'INIT_INVALID_EXECUTOR', false, { reason: validExecutor.reason });
        return res.status(403).json({ success: false, error: "Invalid client" });
    }
    
    try {
        const { robloxData } = req.body;
        
        // robloxData harus berisi info yang hanya bisa didapat dari dalam Roblox
        if (!robloxData || !robloxData.userId || !robloxData.placeId || !robloxData.gameJobId) {
            return res.status(400).json({ success: false, error: "Missing Roblox data" });
        }
        
        // Generate challenge yang harus dijawab
        const challenge = generateTimeBasedChallenge();
        const token = generateSecureToken();
        
        // Simpan pending token
        pendingTokens.set(token, {
            challenge,
            robloxData,
            ip: getClientIP(req),
            created: Date.now(),
            hwid: getHWID(req)
        });
        
        logAccess(req, 'INIT_SUCCESS', true, { userId: robloxData.userId });
        
        res.json({
            success: true,
            token,
            challenge: {
                id: challenge.id,
                puzzle: challenge.puzzle,
                timestamp: challenge.timestamp
            },
            expiresIn: 60
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// ============================================================
// 🔐 NEW: STEP 2 - Validate & Get Script
// ============================================================
app.post('/api/validate', async (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    
    if (suspicion.score >= 40) {
        logAccess(req, 'VALIDATE_BLOCKED_SUSPICIOUS', false, { score: suspicion.score });
        // Kirim fake delayed response
        setTimeout(() => {
            res.json({ success: true, script: FAKE_SCRIPT });
        }, Math.random() * 3000 + 2000);
        return;
    }
    
    try {
        const { token, solution, executorInfo } = req.body;
        
        if (!token || solution === undefined) {
            return res.status(400).json({ success: false, error: "Missing fields" });
        }
        
        // Cek pending token
        const pending = pendingTokens.get(token);
        if (!pending) {
            logAccess(req, 'VALIDATE_INVALID_TOKEN', false);
            return res.status(403).json({ success: false, error: "Invalid or expired token" });
        }
        
        // Cek expiry (60 detik)
        if (Date.now() - pending.created > 60000) {
            pendingTokens.delete(token);
            return res.status(403).json({ success: false, error: "Token expired" });
        }
        
        // Validasi IP sama
        if (getClientIP(req) !== pending.ip) {
            logAccess(req, 'VALIDATE_IP_MISMATCH', false);
            pendingTokens.delete(token);
            return res.status(403).json({ success: false, error: "Session invalid" });
        }
        
        // Validasi solution
        if (parseInt(solution) !== pending.challenge.expectedAnswer) {
            logAccess(req, 'VALIDATE_WRONG_SOLUTION', false);
            return res.status(403).json({ success: false, error: "Invalid solution" });
        }
        
        // Validasi executor info (opsional tapi menambah keamanan)
        if (executorInfo) {
            // executorInfo harus berisi data yang hanya executor bisa provide
            // seperti: identifyexecutor(), getexecutorname(), dll
            if (!executorInfo.name || !executorInfo.version) {
                logAccess(req, 'VALIDATE_MISSING_EXECUTOR_INFO', false);
                // Tidak langsung reject, tapi catat
            }
        }
        
        // Hapus pending token (sudah terpakai)
        pendingTokens.delete(token);
        
        // Cek whitelist & blacklist
        const userId = parseInt(pending.robloxData.userId);
        const placeId = parseInt(pending.robloxData.placeId);
        
        const blockInfo = blockedDevices.isBlocked(pending.hwid, pending.ip, userId);
        if (blockInfo.blocked) {
            return res.status(403).json({ 
                success: false, 
                error: "Access denied", 
                reason: blockInfo.reason,
                banId: blockInfo.banId 
            });
        }
        
        if (config.WHITELIST_USER_IDS.length > 0 && !config.WHITELIST_USER_IDS.includes(userId)) {
            return res.status(403).json({ success: false, error: "Not whitelisted", userId });
        }
        
        if (config.ALLOWED_PLACE_IDS.length > 0 && !config.ALLOWED_PLACE_IDS.includes(placeId)) {
            return res.status(403).json({ success: false, error: "Game not allowed", placeId });
        }
        
        // Generate session token untuk akses script
        const sessionToken = generateSecureToken();
        validatedSessions.set(sessionToken, {
            userId,
            placeId,
            hwid: pending.hwid,
            ip: pending.ip,
            created: Date.now()
        });
        
        logAccess(req, 'VALIDATE_SUCCESS', true, { userId, placeId });
        
        // Kirim session token, bukan script langsung
        res.json({
            success: true,
            sessionToken,
            expiresIn: 300 // 5 menit untuk fetch script
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// ============================================================
// 🔐 NEW: STEP 3 - Get Script (Dengan Session Token)
// ============================================================
app.post('/api/getScript', async (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    
    if (suspicion.score >= 40) {
        logAccess(req, 'GETSCRIPT_BLOCKED_SUSPICIOUS', false, { score: suspicion.score });
        setTimeout(() => {
            res.type('text/plain').send(FAKE_SCRIPT);
        }, Math.random() * 2000 + 1000);
        return;
    }
    
    try {
        const { sessionToken } = req.body;
        
        if (!sessionToken) {
            return res.status(400).json({ success: false, error: "Missing session token" });
        }
        
        const session = validatedSessions.get(sessionToken);
        if (!session) {
            logAccess(req, 'GETSCRIPT_INVALID_SESSION', false);
            return res.status(403).json({ success: false, error: "Invalid session" });
        }
        
        // Cek expiry (5 menit)
        if (Date.now() - session.created > 300000) {
            validatedSessions.delete(sessionToken);
            return res.status(403).json({ success: false, error: "Session expired" });
        }
        
        // Validasi IP sama
        if (getClientIP(req) !== session.ip) {
            logAccess(req, 'GETSCRIPT_IP_MISMATCH', false);
            validatedSessions.delete(sessionToken);
            return res.status(403).json({ success: false, error: "Session invalid" });
        }
        
        // Hapus session (single use)
        validatedSessions.delete(sessionToken);
        
        // Ambil script
        let script = scriptCache.get('main_script');
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) {
                return res.status(500).json({ success: false, error: "Server not configured" });
            }
            try {
                const response = await axios.get(config.SCRIPT_SOURCE_URL, { 
                    timeout: 15000, 
                    headers: { 'User-Agent': 'Roblox/WinInet' },
                    validateStatus: (s) => s === 200 
                });
                script = response.data;
                if (typeof script !== 'string' || script.length < 10) throw new Error('Invalid');
                scriptCache.set('main_script', script);
            } catch {
                return res.status(500).json({ success: false, error: "Failed to fetch script" });
            }
        }
        
        const serverUrl = process.env.RENDER_EXTERNAL_URL || process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
        const banEndpoint = `${serverUrl}/api/ban`;
        const ownerStr = config.OWNER_USER_IDS.join(', ');
        
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);
        
        // Wrap script dengan proteksi
        const protectedScript = `-- Session verified: ${session.userId}
local _OWNER_IDS={${ownerStr}}
local _BAN_EP="${banEndpoint}"
local _SESSION_USER=${session.userId}
local _SESSION_PLACE=${session.placeId}

-- Anti-spy check
local function _checkSpy()
    local _CORE=game:GetService("CoreGui")
    local _spyPatterns={"simplespy","httpspy","remotespy","hydroxide","dex_explorer"}
    for _,g in pairs(_CORE:GetChildren()) do
        if g:IsA("ScreenGui") and g.Enabled then
            local nm=g.Name:lower()
            for _,p in pairs(_spyPatterns) do
                if nm:find(p,1,true) then return true,g.Name end
            end
        end
    end
    local env=getgenv and getgenv() or _G
    local markers={"SimpleSpyExecuted","SimpleSpy_Loaded","HttpSpy_Active"}
    for _,m in pairs(markers) do
        if rawget(env,m)==true then return true,m end
    end
    return false,nil
end

local spyActive,spyName=_checkSpy()
if spyActive then
    game:GetService("Players").LocalPlayer:Kick("⛔ Spy Tool Detected: "..spyName)
    return
end

-- Owner protection
local _PLAYERS=game:GetService("Players")
local _LOCAL=_PLAYERS.LocalPlayer
local function _isOwner(uid)
    for _,id in ipairs(_OWNER_IDS) do
        if uid==id then return true end
    end
    return false
end
for _,p in pairs(_PLAYERS:GetPlayers()) do
    if _isOwner(p.UserId) and p~=_LOCAL then
        game:GetService("StarterGui"):SetCore("SendNotification",{Title="⚠️",Text="Cannot load: Owner in server",Duration=5})
        return
    end
end

-- Main script
${script}`;
        
        logAccess(req, 'GETSCRIPT_SUCCESS', true, { userId: session.userId, size: protectedScript.length });
        
        res.json({
            success: true,
            script: protectedScript,
            meta: {
                userId: session.userId,
                placeId: session.placeId,
                timestamp: Date.now()
            }
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// ============================================================
// 🔐 AUTH ENDPOINTS (Legacy - untuk backward compatibility)
// ============================================================
app.post('/api/auth/challenge', async (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    if (suspicion.score >= 40) {
        logAccess(req, 'CHALLENGE_BLOCKED', false, { score: suspicion.score, reasons: suspicion.reasons });
        setTimeout(() => {
            res.json({ 
                success: true, 
                challengeId: crypto.randomBytes(16).toString('hex'),
                puzzle: { numbers: [1,2,3,4,5], operation: 'sum' },
                expiresIn: 60 
            });
        }, Math.random() * 2000 + 1000);
        return;
    }
    
    try {
        const { userId, hwid, placeId } = req.body;
        if (!userId || !hwid || !placeId) return res.status(400).json({ success: false, error: "Missing required fields" });
        
        const userIdNum = parseInt(userId), placeIdNum = parseInt(placeId);
        if (isNaN(userIdNum) || isNaN(placeIdNum)) return res.status(400).json({ success: false, error: "Invalid ID format" });
        
        const blockInfo = blockedDevices.isBlocked(hwid, getClientIP(req), userIdNum);
        if (blockInfo.blocked) return res.status(403).json({ success: false, error: "Access denied", reason: blockInfo.reason, banId: blockInfo.banId });
        
        if (config.WHITELIST_USER_IDS.length > 0 && !config.WHITELIST_USER_IDS.includes(userIdNum)) return res.status(403).json({ success: false, error: "Not whitelisted", userId: userIdNum });
        if (config.ALLOWED_PLACE_IDS.length > 0 && !config.ALLOWED_PLACE_IDS.includes(placeIdNum)) return res.status(403).json({ success: false, error: "This game is not allowed", placeId: placeIdNum });
        
        const challenge = challenges.create(userIdNum, hwid, placeIdNum, getClientIP(req));
        logAccess(req, 'CHALLENGE_ISSUED', true, { challengeId: challenge.id, userId: userIdNum });
        res.json({ success: true, challengeId: challenge.id, puzzle: challenge.puzzle, expiresIn: 60 });
    } catch (error) { 
        res.status(500).json({ success: false, error: "Server error" }); 
    }
});

app.post('/api/auth/verify', async (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    if (suspicion.score >= 40) {
        logAccess(req, 'VERIFY_BLOCKED', false, { score: suspicion.score });
        setTimeout(() => {
            res.json({ success: true, mode: 'raw', script: FAKE_SCRIPT });
        }, Math.random() * 3000 + 2000);
        return;
    }
    
    try {
        const { challengeId, solution, timestamp } = req.body;
        if (!challengeId || solution === undefined || !timestamp) return res.status(400).json({ success: false, error: "Missing fields" });
        
        const result = challenges.verify(challengeId, solution, getClientIP(req));
        if (!result.valid) return res.status(403).json({ success: false, error: result.error });
        
        const challenge = result.challenge;
        let script = scriptCache.get('main_script');
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) return res.status(500).json({ success: false, error: "Server not configured" });
            try {
                const response = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000, headers: { 'User-Agent': 'Roblox/WinInet' }, validateStatus: (s) => s === 200 });
                script = response.data;
                if (typeof script !== 'string' || script.length < 10) throw new Error('Invalid script');
                scriptCache.set('main_script', script);
            } catch { return res.status(500).json({ success: false, error: "Failed to fetch script" }); }
        }
        
        const serverUrl = process.env.RENDER_EXTERNAL_URL || process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);
        
        if (alreadyObfuscated) {
            logAccess(req, 'SCRIPT_SERVED_RAW', true, { userId: challenge.userId, size: script.length });
            return res.json({ 
                success: true, 
                mode: 'raw', 
                script, 
                ownerIds: config.OWNER_USER_IDS, 
                whitelistIds: config.WHITELIST_USER_IDS, 
                banEndpoint: `${serverUrl}/api/ban`, 
                meta: { userId: challenge.userId, placeId: challenge.placeId, timestamp: Date.now() } 
            });
        }
        
        const sessionKey = generateSessionKey(challenge.userId, challenge.hwid, timestamp, config.SECRET_KEY);
        const chunks = []; 
        const chunkSize = 2000;
        for (let i = 0; i < script.length; i += chunkSize) { 
            const chunk = script.substring(i, i + chunkSize); 
            const encrypted = []; 
            for (let j = 0; j < chunk.length; j++) 
                encrypted.push(chunk.charCodeAt(j) ^ sessionKey.charCodeAt(j % sessionKey.length)); 
            chunks.push(encrypted); 
        }
        
        const checksum = crypto.createHash('md5').update(script).digest('hex');
        logAccess(req, 'SCRIPT_SERVED_ENCRYPTED', true, { userId: challenge.userId, chunks: chunks.length });
        
        res.json({ 
            success: true, 
            mode: 'encrypted', 
            key: sessionKey, 
            chunks, 
            checksum, 
            ownerIds: config.OWNER_USER_IDS, 
            whitelistIds: config.WHITELIST_USER_IDS, 
            banEndpoint: `${serverUrl}/api/ban`, 
            meta: { userId: challenge.userId, placeId: challenge.placeId, timestamp: Date.now() } 
        });
    } catch (error) { 
        res.status(500).json({ success: false, error: "Server error" }); 
    }
});

// ============================================================
// 📜 LOADER ENDPOINT - HONEYPOT VERSION
// ============================================================
const loaderHandler = (req, res) => {
    const ua = req.headers['user-agent'] || '';
    const suspicion = detectSuspiciousRequest(req);
    
    // Log semua request untuk analisis
    logAccess(req, 'LOADER_REQUEST', true, { 
        ua: ua.substring(0, 100), 
        score: suspicion.score, 
        reasons: suspicion.reasons 
    });
    
    // Jika mencurigakan, kirim HONEYPOT script (fake)
    if (suspicion.score >= 30) {
        logAccess(req, 'LOADER_HONEYPOT_SERVED', false, { score: suspicion.score });
        return res.type('text/plain').send(HONEYPOT_SCRIPT);
    }
    
    // Validasi executor
    const validExecutor = isLikelyRobloxExecutor(req);
    if (!validExecutor.valid) {
        logAccess(req, 'LOADER_INVALID_EXECUTOR', false, { reason: validExecutor.reason });
        return res.type('text/plain').send(HONEYPOT_SCRIPT);
    }
    
    const serverUrl = process.env.RENDER_EXTERNAL_URL || process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
    
    // LOADER BARU: 3-Step Verification
    const loaderScript = `--[[ Premium Loader v5.5.0 - Secure ]]
local _S="${serverUrl}"
local _HTTP=game:GetService("HttpService")
local _PLAYERS=game:GetService("Players")
local _LOCAL=_PLAYERS.LocalPlayer
local _STAR=game:GetService("StarterGui")

-- Utility functions
local function _notify(t,x,d) 
    pcall(function() 
        _STAR:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) 
    end) 
end

local function _kick(msg)
    task.wait(0.5)
    _LOCAL:Kick(msg)
end

local function _getHWID()
    local s,r=pcall(function()
        if gethwid then return gethwid() end
        if get_hwid then return get_hwid() end
        if getexecutorname then return getexecutorname().."_"..tostring(_LOCAL.UserId) end
        return "FB_"..tostring(_LOCAL.UserId)
    end)
    return s and r or "UNK"
end

local function _getExecutorInfo()
    local info = {name="Unknown",version="1.0"}
    pcall(function()
        if identifyexecutor then
            local name,ver = identifyexecutor()
            info.name = name or "Unknown"
            info.version = ver or "1.0"
        elseif getexecutorname then
            info.name = getexecutorname()
        end
    end)
    return info
end

local function _httpPost(url,data)
    local req=(syn and syn.request) or request or http_request or (http and http.request)
    if not req then return nil,"No HTTP" end
    
    local s,r=pcall(function()
        return req({
            Url=url,
            Method="POST",
            Headers={
                ["Content-Type"]="application/json",
                ["User-Agent"]="Roblox/WinInet",
                ["X-HWID"]=_getHWID(),
                ["X-Player-ID"]=tostring(_LOCAL.UserId),
                ["X-Place-ID"]=tostring(game.PlaceId)
            },
            Body=_HTTP:JSONEncode(data)
        })
    end)
    
    if not s then return nil,tostring(r) end
    if r.StatusCode~=200 then
        local e=nil
        pcall(function() e=_HTTP:JSONDecode(r.Body) end)
        return e,"HTTP "..r.StatusCode
    end
    
    local ps,pd=pcall(function() return _HTTP:JSONDecode(r.Body) end)
    return ps and pd or nil
end

-- Anti-spy check
local function _checkSpy()
    local _CORE=game:GetService("CoreGui")
    local _spyPatterns={"simplespy","simple_spy","httpspy","http_spy","remotespy","remote_spy","hydroxide","dex_explorer","networkspy"}
    
    for _,g in pairs(_CORE:GetChildren()) do
        if g:IsA("ScreenGui") and g.Enabled then
            local nm=g.Name:lower()
            for _,p in pairs(_spyPatterns) do
                if nm:find(p,1,true) then return true,g.Name end
            end
        end
    end
    
    local env=getgenv and getgenv() or _G
    local markers={"SimpleSpyExecuted","SimpleSpy_Loaded","HttpSpy_Active","RemoteSpy_Active"}
    for _,m in pairs(markers) do
        if rawget(env,m)==true then return true,m end
    end
    
    return false,nil
end

-- Main loader
local function _main()
    -- Step 0: Check spy
    local spyActive,spyName=_checkSpy()
    if spyActive then
        _notify("🚨 Blocked",spyName.." detected",3)
        _kick("⛔ Spy Tool Detected\\n\\n"..spyName)
        return
    end
    
    _notify("🔄 Loading","Initializing...",2)
    
    -- Collect Roblox data (only available in real Roblox environment)
    local robloxData = {
        userId = _LOCAL.UserId,
        username = _LOCAL.Name,
        displayName = _LOCAL.DisplayName,
        placeId = game.PlaceId,
        gameJobId = game.JobId,
        placeVersion = game.PlaceVersion
    }
    
    -- Step 1: Initialize session
    local initRes,initErr = _httpPost(_S.."/api/init", {
        robloxData = robloxData,
        executorInfo = _getExecutorInfo()
    })
    
    if not initRes or not initRes.success then
        _notify("❌ Error",initRes and initRes.error or "Init failed",5)
        return
    end
    
    -- Solve puzzle
    local solution = 0
    if initRes.challenge and initRes.challenge.puzzle and initRes.challenge.puzzle.numbers then
        for _,n in ipairs(initRes.challenge.puzzle.numbers) do
            solution = solution + n
        end
    end
    
    -- Check spy again
    local spyActive2,spyName2=_checkSpy()
    if spyActive2 then
        _notify("🚨 Blocked",spyName2.." detected",3)
        _kick("⛔ Spy Tool Detected: "..spyName2)
        return
    end
    
    _notify("🔄 Loading","Validating...",2)
    
    -- Step 2: Validate
    local valRes,valErr = _httpPost(_S.."/api/validate", {
        token = initRes.token,
        solution = solution,
        executorInfo = _getExecutorInfo()
    })
    
    if not valRes or not valRes.success then
        _notify("❌ Denied",valRes and valRes.error or "Validation failed",5)
        if valRes and valRes.error == "Not whitelisted" then
            task.wait(2)
            _kick("⛔ Not Whitelisted\\n\\nYour User ID: "..tostring(_LOCAL.UserId))
        end
        return
    end
    
    -- Final spy check
    local spyActive3,spyName3=_checkSpy()
    if spyActive3 then
        _notify("🚨 Blocked",spyName3.." detected",3)
        _kick("⛔ Spy Tool Detected: "..spyName3)
        return
    end
    
    _notify("🔄 Loading","Fetching script...",2)
    
    -- Step 3: Get script
    local scriptRes,scriptErr = _httpPost(_S.."/api/getScript", {
        sessionToken = valRes.sessionToken
    })
    
    if not scriptRes or not scriptRes.success then
        _notify("❌ Error",scriptRes and scriptRes.error or "Script fetch failed",5)
        return
    end
    
    _notify("✅ Success","Executing...",2)
    
    -- Execute script
    local fn,err = loadstring(scriptRes.script)
    if fn then
        local ok,runErr = pcall(fn)
        if not ok then
            _notify("❌ Error","Script error",5)
        end
    else
        _notify("❌ Error","Parse failed",5)
    end
end

-- Execute
task.spawn(function()
    task.wait(0.1)
    pcall(_main)
end)`;
    
    logAccess(req, 'LOADER_SERVED_SECURE', true, { size: loaderScript.length });
    res.type('text/plain').send(loaderScript);
};

app.get('/api/loader.lua', loaderHandler);
app.get('/loader', loaderHandler);

// ============================================================
// 📜 SCRIPT ENDPOINT - Protected
// ============================================================
app.get('/script', async (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    
    // Selalu kirim honeypot untuk direct access ke /script
    // Karena script asli harus didapat melalui 3-step verification
    logAccess(req, 'SCRIPT_DIRECT_ACCESS', false, { score: suspicion.score });
    
    res.type('text/plain').send(HONEYPOT_SCRIPT);
});

// ============================================================
// 🚫 BAN ENDPOINT
// ============================================================
app.post('/api/ban', (req, res) => {
    try {
        const { hwid, ip, playerId, playerName, reason, toolsDetected } = req.body;
        if (!hwid && !ip && !playerId) return res.status(400).json({ error: "Missing identifier" });
        
        const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
        blockedDevices.addBlock({ 
            hwid, 
            ip: ip || getClientIP(req), 
            playerId, 
            playerName, 
            reason: reason || 'Manual ban', 
            toolsDetected: toolsDetected || [], 
            banId, 
            timestamp: new Date().toISOString(), 
            bannedBy: 'system' 
        });
        
        logAccess(req, 'DEVICE_BANNED', true, { playerId, playerName, reason, toolsDetected, banId });
        res.json({ success: true, banId });
    } catch (error) { 
        res.status(500).json({ error: error.message }); 
    }
});

// ============================================================
// 👑 ADMIN ENDPOINTS
// ============================================================
function adminAuth(req, res, next) { 
    const k = req.headers['x-admin-key'] || req.query.key; 
    if (!k) return res.status(401).json({ error: "Admin key required" }); 
    if (!secureCompare(k, config.ADMIN_KEY)) return res.status(403).json({ error: "Invalid admin key" }); 
    next(); 
}

app.get('/api/admin/stats', adminAuth, (req, res) => { 
    res.json({ 
        success: true, 
        stats: db.getStats(),
        sessions: {
            pending: pendingTokens.size,
            validated: validatedSessions.size
        },
        config: { 
            hasScriptUrl: !!config.SCRIPT_SOURCE_URL, 
            scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED, 
            whitelistCount: config.WHITELIST_USER_IDS.length, 
            ownerCount: config.OWNER_USER_IDS.length 
        }, 
        server: { 
            uptime: Math.floor(process.uptime()) + 's', 
            memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB' 
        } 
    }); 
});

app.get('/api/admin/logs', adminAuth, (req, res) => { 
    const limit = Math.min(parseInt(req.query.limit) || 50, 500); 
    let logs = db.getLogs(limit); 
    if (req.query.filter) logs = logs.filter(l => l.action?.includes(req.query.filter.toUpperCase())); 
    res.json({ success: true, count: logs.length, logs }); 
});

app.get('/api/admin/bans', adminAuth, (req, res) => { 
    res.json({ success: true, count: blockedDevices.count(), bans: blockedDevices.getAll() }); 
});

app.delete('/api/admin/bans/:banId', adminAuth, (req, res) => { 
    const removed = blockedDevices.removeByBanId(req.params.banId); 
    res.json({ success: removed, message: removed ? 'Ban removed' : 'Ban not found' }); 
});

app.post('/api/admin/bans', adminAuth, (req, res) => { 
    const { hwid, ip, playerId, playerName, reason } = req.body; 
    if (!hwid && !ip && !playerId) return res.status(400).json({ error: "Identifier required" }); 
    const banId = crypto.randomBytes(8).toString('hex').toUpperCase(); 
    blockedDevices.addBlock({ hwid, ip, playerId, playerName, reason: reason || 'Manual ban by admin', banId, timestamp: new Date().toISOString(), bannedBy: 'admin' }); 
    res.json({ success: true, banId }); 
});

app.post('/api/admin/bans/clear', adminAuth, (req, res) => { 
    const count = blockedDevices.count(); 
    blockedDevices.clearAll(); 
    res.json({ success: true, message: `Cleared ${count} bans` }); 
});

app.post('/api/admin/cache/clear', adminAuth, (req, res) => { 
    scriptCache.flushAll(); 
    res.json({ success: true, message: "Cache cleared" }); 
});

app.post('/api/admin/refresh', adminAuth, async (req, res) => { 
    try { 
        scriptCache.flushAll(); 
        if (!config.SCRIPT_SOURCE_URL) return res.status(400).json({ success: false, error: 'No URL configured' }); 
        const response = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000, headers: { 'User-Agent': 'Roblox/WinInet' } }); 
        if (typeof response.data === 'string' && response.data.length > 10) { 
            scriptCache.set('main_script', response.data); 
            res.json({ success: true, size: response.data.length }); 
        } else throw new Error('Invalid content'); 
    } catch (error) { 
        res.status(500).json({ success: false, error: error.message }); 
    } 
});

app.get('/api/admin/whitelist', adminAuth, (req, res) => { 
    res.json({ success: true, whitelist: config.WHITELIST_USER_IDS, count: config.WHITELIST_USER_IDS.length }); 
});

app.get('/api/admin/user/:userId', adminAuth, async (req, res) => { 
    try { 
        const userId = parseInt(req.params.userId); 
        const userInfo = await verifyRobloxUser(userId); 
        res.json({ 
            success: true, 
            user: { 
                ...userInfo, 
                isWhitelisted: config.WHITELIST_USER_IDS.includes(userId), 
                isOwner: config.OWNER_USER_IDS.includes(userId) 
            } 
        }); 
    } catch (error) { 
        res.status(500).json({ success: false, error: error.message }); 
    } 
});

// ============================================================
// 404 Handler
// ============================================================
app.use('*', (req, res) => {
    const suspicion = detectSuspiciousRequest(req);
    
    if (suspicion.score >= 20) {
        return res.status(404).type('text/plain').send('--[[ 404 ]]');
    }
    
    if (isBrowser(req)) {
        return res.status(404).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.status(404).json({ error: "Not found" });
});

// ============================================================
// 🚀 START SERVER
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ Premium Loader v5.5.0 SECURE | Port: ${PORT} | ${new Date().toISOString()}`);
    console.log(`📍 Whitelist: ${config.WHITELIST_USER_IDS.length} | Owners: ${config.OWNER_USER_IDS.length} | Games: ${config.ALLOWED_PLACE_IDS.length || 'ALL'}`);
    console.log(`🔧 Script URL: ${config.SCRIPT_SOURCE_URL ? 'Configured' : 'NOT SET'} | Obfuscated: ${config.SCRIPT_ALREADY_OBFUSCATED}`);
    console.log(`🔒 Anti-Bot: ENABLED | 3-Step Verification: ACTIVE`);
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));

module.exports = app;
