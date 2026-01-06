// ============================================================
// 🛡️ PREMIUM LOADER v5.1.0 - FULL FEATURES
// Complete protection with all features
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
// 🌐 UNAUTHORIZED HTML - Full styled page
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
        .particles {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            z-index: 2;
            pointer-events: none;
        }
        .particle {
            position: absolute;
            width: 2px; height: 2px;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            animation: float 15s infinite;
        }
        .container {
            position: relative; z-index: 10; height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px; user-select: none;
        }
        .shield {
            font-size: 4rem;
            margin-bottom: 20px;
            animation: pulse 2s ease-in-out infinite;
        }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #ef4444; font-size: 1.1rem; font-weight: 600;
            letter-spacing: 3px; text-transform: uppercase;
            margin-bottom: 25px;
            text-shadow: 0 0 20px rgba(239, 68, 68, 0.5);
        }
        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800; max-width: 700px;
            margin: 0 0 20px 0; line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        p { 
            color: rgba(255, 255, 255, 0.4); 
            font-size: 1.1rem; 
            margin: 0;
            max-width: 500px;
        }
        .code {
            margin-top: 30px;
            padding: 15px 30px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.9rem;
            color: rgba(255, 255, 255, 0.6);
        }
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }
        @keyframes float {
            0%, 100% { transform: translateY(100vh) rotate(0deg); opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { transform: translateY(-100vh) rotate(720deg); opacity: 0; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>
    <div class="particles">
        ${Array.from({length: 20}, (_, i) => 
            `<div class="particle" style="left: ${Math.random() * 100}%; animation-delay: ${Math.random() * 15}s; animation-duration: ${15 + Math.random() * 10}s;"></div>`
        ).join('')}
    </div>
    <div class="container">
        <div class="shield">🛡️</div>
        <div class="auth-label">
            <span>⛔</span>
            Access Denied
            <span>⛔</span>
        </div>
        <h1>You are not authorized to view this resource.</h1>
        <p>This endpoint is protected and requires valid executor authentication.</p>
        <div class="code">Error Code: 403 | Forbidden</div>
    </div>
</body>
</html>`;

// ============================================================
// 🔧 MIDDLEWARE SETUP
// ============================================================

// Security headers
app.use(helmet({ 
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false
}));

// CORS
app.use(cors({ 
    origin: '*', 
    methods: ['GET', 'POST', 'DELETE', 'PUT', 'PATCH'], 
    allowedHeaders: ['Content-Type', 'x-admin-key', 'Authorization', 'x-hwid', 'x-player-id'] 
}));

// Body parsing
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Trust proxy untuk mendapatkan IP yang benar
app.set('trust proxy', 1);

// Rate limiters
const authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 menit
    max: 20, // 20 request per menit untuk auth
    message: { success: false, error: "Too many authentication attempts. Please wait." },
    keyGenerator: (req) => getClientIP(req),
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logAccess(req, 'RATE_LIMIT_AUTH', false);
        res.status(429).json({ success: false, error: "Too many attempts. Wait 1 minute." });
    }
});

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100, // 100 request per menit
    message: { success: false, error: "Too many requests" },
    keyGenerator: (req) => getClientIP(req),
    standardHeaders: true,
    legacyHeaders: false
});

const strictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10, // 10 request per menit untuk endpoint sensitif
    message: { success: false, error: "Rate limit exceeded" },
    keyGenerator: (req) => getClientIP(req)
});

// Apply rate limiters
app.use('/api/auth/', authLimiter);
app.use('/api/ban', strictLimiter);
app.use('/api/', generalLimiter);

// ============================================================
// 🔧 HELPER FUNCTIONS
// ============================================================

function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress ||
           req.ip || 
           'unknown';
}

function getHWID(req) {
    return req.headers['x-hwid'] || 
           req.query.hwid || 
           req.body?.hwid || 
           null;
}

function getPlayerID(req) {
    return req.headers['x-player-id'] || 
           req.query.pid || 
           req.body?.playerId ||
           null;
}

function logAccess(req, action, success, details = {}) {
    const timestamp = new Date().toISOString();
    const log = { 
        ip: getClientIP(req), 
        hwid: getHWID(req),
        playerId: getPlayerID(req),
        userAgent: req.headers['user-agent']?.substring(0, 100) || 'unknown', 
        action, 
        success, 
        method: req.method, 
        path: req.path,
        timestamp,
        ...details 
    };
    
    db.addLog(log);
    
    // Console output dengan warna
    const icon = success ? '✅' : '❌';
    const color = success ? '\x1b[32m' : '\x1b[31m';
    const reset = '\x1b[0m';
    
    console.log(`${color}[${timestamp}] ${icon} ${action}${reset} | IP: ${log.ip} | Path: ${log.path}`);
    
    if (details.userId) {
        console.log(`   └── User: ${details.userId} ${details.username ? `(${details.username})` : ''}`);
    }
    if (details.error) {
        console.log(`   └── Error: ${details.error}`);
    }
    
    return log;
}

function isBrowser(req) {
    const accept = req.headers['accept'] || '';
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    
    // Known executor keywords
    const executorKeywords = [
        'roblox', 'synapse', 'krnl', 'fluxus', 'delta', 
        'electron', 'script-ware', 'sentinel', 'coco', 
        'oxygen', 'evon', 'arceus', 'hydrogen', 'vegax',
        'trigon', 'comet', 'jjsploit', 'wearedevs', 
        'executor', 'exploit', 'wininet', 'solara', 'wave',
        'zorara', 'codex', 'nihon', 'celery', 'swift',
        'scriptware', 'sirhurt', 'temple', 'valyse'
    ];
    
    // Jika user agent mengandung keyword executor, bukan browser
    if (executorKeywords.some(keyword => userAgent.includes(keyword))) {
        return false;
    }
    
    // Cek apakah request dari browser
    if (accept.includes('text/html')) {
        const hasBrowserUA = userAgent.includes('mozilla') || 
                             userAgent.includes('chrome') || 
                             userAgent.includes('safari') ||
                             userAgent.includes('firefox') ||
                             userAgent.includes('edge') ||
                             userAgent.includes('opera');
        
        // Browser biasanya punya accept-language
        if (hasBrowserUA && req.headers['accept-language']) {
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

function generateToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
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
        /Synapse Xen/i,
        /-- Obfuscated/i,
        /-- Protected/i,
    ];
    
    for (const pattern of obfuscatorPatterns) {
        if (pattern.test(script.substring(0, 500))) return true;
    }
    
    // Check for common obfuscated code patterns
    const codePatterns = [
        /^local \w{1,3}=\{/,                      // local a={
        /getfenv\s*\(\s*\d+\s*\)/,                // getfenv(0)
        /string\.char\s*\(\s*\d+/,                // string.char(123
        /loadstring\s*\(\s*['"]\\x/,              // loadstring("\x...
        /\[\[.{100,}\]\]/,                        // Very long [[ ]] strings
    ];
    
    for (const pattern of codePatterns) {
        if (pattern.test(script)) return true;
    }
    
    // Check for high density of escape sequences
    const escapeCount = (script.match(/\\\d{1,3}/g) || []).length;
    if (escapeCount > 100 && script.length > 2000) return true;
    
    // Check for very long single lines (minified/obfuscated)
    const lines = script.split('\n');
    for (const line of lines) {
        if (line.length > 10000) return true;
    }
    
    // Check for unusual character distribution
    const alphaRatio = (script.match(/[a-zA-Z]/g) || []).length / script.length;
    if (alphaRatio < 0.3 && script.length > 1000) return true;
    
    return false;
}

function isDeviceBlocked(req) {
    const hwid = getHWID(req);
    const ip = getClientIP(req);
    const playerId = getPlayerID(req);
    
    return blockedDevices.isBlocked(hwid, ip, playerId);
}

// ============================================================
// 🔍 ROBLOX API VERIFICATION
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
                id: response.data.id,
                username: response.data.name,
                displayName: response.data.displayName,
                created: response.data.created,
                isBanned: response.data.isBanned || false
            };
        }
        return { valid: false, error: 'Invalid response' };
    } catch (error) {
        console.warn(`⚠️ Roblox API check failed for ${userId}:`, error.message);
        // Fallback: allow if API is down
        return { valid: true, fallback: true };
    }
}

async function getUserThumbnail(userId) {
    try {
        const response = await axios.get(
            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${userId}&size=150x150&format=Png`,
            { timeout: 5000 }
        );
        
        if (response.data?.data?.[0]?.imageUrl) {
            return response.data.data[0].imageUrl;
        }
        return null;
    } catch {
        return null;
    }
}

// ============================================================
// 🏠 ROOT & HEALTH ENDPOINTS
// ============================================================

app.get('/', (req, res) => {
    if (isBrowser(req)) {
        logAccess(req, 'BROWSER_ROOT', false);
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.json({
        status: "online",
        name: "Premium Loader",
        version: "5.1.0",
        protected: true,
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: "ok", 
        uptime: Math.floor(process.uptime()),
        timestamp: new Date().toISOString(),
        memory: {
            used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
            total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
        }
    });
});

app.get('/api/health', (req, res) => {
    if (isBrowser(req)) {
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.json({ 
        status: "healthy", 
        timestamp: new Date().toISOString(), 
        uptime: Math.floor(process.uptime()) + "s",
        cached: scriptCache.has('main_script'),
        stats: db.getStats()
    });
});

app.get('/debug', (req, res) => {
    res.json({
        status: "ok",
        version: "5.1.0",
        timestamp: new Date().toISOString(),
        config: {
            hasScriptUrl: !!config.SCRIPT_SOURCE_URL,
            scriptUrlPreview: config.SCRIPT_SOURCE_URL ? 
                config.SCRIPT_SOURCE_URL.substring(0, 50) + '...' : 'NOT SET',
            scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED,
            whitelistCount: config.WHITELIST_USER_IDS.length,
            whitelistIds: config.WHITELIST_USER_IDS,
            ownerCount: config.OWNER_USER_IDS.length,
            ownerIds: config.OWNER_USER_IDS,
            allowedGamesCount: config.ALLOWED_PLACE_IDS.length,
            allowedGames: config.ALLOWED_PLACE_IDS
        },
        stats: db.getStats(),
        server: {
            uptime: Math.floor(process.uptime()) + 's',
            nodeVersion: process.version,
            platform: process.platform
        }
    });
});

// ============================================================
// 🔐 AUTH ENDPOINTS - Challenge-Response System
// ============================================================

app.post('/api/auth/challenge', async (req, res) => {
    console.log('📥 [CHALLENGE] Request received');
    
    if (isBrowser(req)) {
        logAccess(req, 'CHALLENGE_BROWSER', false);
        return res.status(403).json({ success: false, error: "Forbidden" });
    }

    try {
        const { userId, hwid, placeId } = req.body;
        
        // Validate required fields
        if (!userId || !hwid || !placeId) {
            logAccess(req, 'CHALLENGE_MISSING_FIELDS', false, { 
                hasUserId: !!userId, 
                hasHwid: !!hwid, 
                hasPlaceId: !!placeId 
            });
            return res.status(400).json({ 
                success: false, 
                error: "Missing required fields (userId, hwid, placeId)" 
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

        // Check if device is blocked
        const blockInfo = blockedDevices.isBlocked(hwid, getClientIP(req), userIdNum);
        if (blockInfo.blocked) {
            logAccess(req, 'CHALLENGE_BLOCKED', false, { 
                userId: userIdNum, 
                reason: blockInfo.reason 
            });
            return res.status(403).json({ 
                success: false, 
                error: "Access denied",
                reason: blockInfo.reason,
                banId: blockInfo.banId
            });
        }

        // Verify Roblox user (optional but recommended)
        const robloxUser = await verifyRobloxUser(userIdNum);
        if (!robloxUser.valid) {
            logAccess(req, 'CHALLENGE_INVALID_USER', false, { userId: userIdNum });
            return res.status(403).json({ 
                success: false, 
                error: "Invalid Roblox user" 
            });
        }

        if (robloxUser.isBanned) {
            logAccess(req, 'CHALLENGE_BANNED_USER', false, { userId: userIdNum });
            return res.status(403).json({ 
                success: false, 
                error: "This Roblox account is banned" 
            });
        }

        // Check whitelist
        if (config.WHITELIST_USER_IDS.length > 0) {
            if (!config.WHITELIST_USER_IDS.includes(userIdNum)) {
                logAccess(req, 'CHALLENGE_NOT_WHITELISTED', false, { 
                    userId: userIdNum,
                    username: robloxUser.username
                });
                return res.status(403).json({ 
                    success: false, 
                    error: "Not whitelisted",
                    userId: userIdNum
                });
            }
        }

        // Check allowed games
        if (config.ALLOWED_PLACE_IDS.length > 0) {
            if (!config.ALLOWED_PLACE_IDS.includes(placeIdNum)) {
                logAccess(req, 'CHALLENGE_WRONG_GAME', false, { 
                    userId: userIdNum,
                    placeId: placeIdNum 
                });
                return res.status(403).json({ 
                    success: false, 
                    error: "This game is not allowed",
                    placeId: placeIdNum
                });
            }
        }

        // Create challenge
        const challenge = challenges.create(userIdNum, hwid, placeIdNum, getClientIP(req));
        
        logAccess(req, 'CHALLENGE_ISSUED', true, { 
            challengeId: challenge.id,
            userId: userIdNum,
            username: robloxUser.username || 'unknown',
            placeId: placeIdNum
        });

        console.log(`✅ [CHALLENGE] Issued for ${robloxUser.username || userIdNum}`);

        res.json({
            success: true,
            challengeId: challenge.id,
            puzzle: challenge.puzzle,
            expiresIn: 60,
            user: {
                id: userIdNum,
                username: robloxUser.username,
                displayName: robloxUser.displayName
            }
        });

    } catch (error) {
        console.error('❌ [CHALLENGE] Error:', error);
        logAccess(req, 'CHALLENGE_ERROR', false, { error: error.message });
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
        
        // Validate fields
        if (!challengeId || solution === undefined || !timestamp) {
            logAccess(req, 'VERIFY_MISSING_FIELDS', false);
            return res.status(400).json({ 
                success: false, 
                error: "Missing fields" 
            });
        }

        // Verify challenge
        const result = challenges.verify(challengeId, solution, getClientIP(req));
        
        if (!result.valid) {
            logAccess(req, 'VERIFY_FAILED', false, { error: result.error });
            return res.status(403).json({ 
                success: false, 
                error: result.error 
            });
        }

        const challenge = result.challenge;
        console.log(`✅ [VERIFY] User ${challenge.userId} verified successfully`);

        // Fetch script
        let script = scriptCache.get('main_script');
        
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) {
                logAccess(req, 'VERIFY_NO_SCRIPT_URL', false);
                return res.status(500).json({ 
                    success: false, 
                    error: "Server not configured - SCRIPT_SOURCE_URL missing" 
                });
            }

            console.log(`🔄 [VERIFY] Fetching script from: ${config.SCRIPT_SOURCE_URL}`);
            
            try {
                const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                    timeout: 15000,
                    headers: { 
                        'User-Agent': 'Roblox/WinInet',
                        'Accept': '*/*',
                        'Cache-Control': 'no-cache'
                    },
                    validateStatus: (status) => status === 200
                });
                
                script = response.data;
                
                if (typeof script !== 'string' || script.length < 10) {
                    throw new Error('Invalid script content received');
                }
                
                scriptCache.set('main_script', script);
                console.log(`✅ [VERIFY] Script cached (${script.length} bytes)`);
                
            } catch (fetchError) {
                console.error('❌ [VERIFY] Fetch error:', fetchError.message);
                logAccess(req, 'VERIFY_FETCH_ERROR', false, { error: fetchError.message });
                return res.status(500).json({ 
                    success: false, 
                    error: "Failed to fetch script" 
                });
            }
        }

        // Determine server URL
        const serverUrl = process.env.RENDER_EXTERNAL_URL || 
                          process.env.SERVER_URL ||
                          `${req.protocol}://${req.get('host')}`;

        // Check if script is already obfuscated
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);

        if (alreadyObfuscated) {
            console.log('📦 [VERIFY] Script already obfuscated, serving RAW');
            
            logAccess(req, 'SCRIPT_SERVED_RAW', true, { 
                userId: challenge.userId,
                size: script.length 
            });
            
            return res.json({
                success: true,
                mode: 'raw',
                script: script,
                ownerIds: config.OWNER_USER_IDS,
                banEndpoint: `${serverUrl}/api/ban`,
                meta: {
                    userId: challenge.userId,
                    placeId: challenge.placeId,
                    timestamp: Date.now()
                }
            });
        }

        // Generate session key for encryption
        const sessionKey = generateSessionKey(
            challenge.userId, 
            challenge.hwid, 
            timestamp, 
            config.SECRET_KEY
        );

        // Encrypt script in chunks
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

        // Generate checksum
        const checksum = crypto
            .createHash('md5')
            .update(script)
            .digest('hex');

        logAccess(req, 'SCRIPT_SERVED_ENCRYPTED', true, { 
            userId: challenge.userId,
            chunks: chunks.length,
            checksum: checksum.substring(0, 8)
        });

        console.log(`📦 [VERIFY] Script served encrypted (${chunks.length} chunks)`);

        res.json({
            success: true,
            mode: 'encrypted',
            key: sessionKey,
            chunks: chunks,
            checksum: checksum,
            ownerIds: config.OWNER_USER_IDS,
            banEndpoint: `${serverUrl}/api/ban`,
            meta: {
                userId: challenge.userId,
                placeId: challenge.placeId,
                timestamp: Date.now(),
                expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
            }
        });

    } catch (error) {
        console.error('❌ [VERIFY] Error:', error);
        logAccess(req, 'VERIFY_ERROR', false, { error: error.message });
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// ============================================================
// 📜 LOADER ENDPOINT - For secure 2-step loading
// ============================================================

app.get('/loader', (req, res) => {
    console.log('📥 [LOADER] Request received');
    
    if (isBrowser(req)) {
        logAccess(req, 'LOADER_BROWSER', false);
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const serverUrl = process.env.RENDER_EXTERNAL_URL || 
                      process.env.SERVER_URL ||
                      `${req.protocol}://${req.get('host')}`;

    console.log(`📍 [LOADER] Server URL: ${serverUrl}`);

    const loaderScript = `--[[ 
    ╔════════════════════════════════════════════════════════════╗
    ║           🛡️ Secure Loader v5.1.0 - Full Features         ║
    ║                 Challenge-Response System                  ║
    ╚════════════════════════════════════════════════════════════╝
]]

local SERVER = "${serverUrl}"
local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local StarterGui = game:GetService("StarterGui")
local CoreGui = game:GetService("CoreGui")
local RunService = game:GetService("RunService")
local LocalPlayer = Players.LocalPlayer

-- ============================================================
-- UTILITY FUNCTIONS
-- ============================================================

local function notify(title, text, duration)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title,
            Text = text,
            Duration = duration or 3
        })
    end)
end

local function getHWID()
    local success, result = pcall(function()
        if gethwid then return gethwid() end
        if get_hwid then return get_hwid() end
        if getexecutorname then
            return getexecutorname() .. "_" .. tostring(LocalPlayer.UserId) .. "_" .. tostring(os.time())
        end
        return "FALLBACK_" .. tostring(LocalPlayer.UserId) .. "_" .. tostring(tick())
    end)
    return success and result or "UNKNOWN_" .. tostring(LocalPlayer.UserId)
end

local function getExecutorInfo()
    local info = {
        name = "Unknown",
        version = "Unknown"
    }
    pcall(function()
        if getexecutorname then info.name = getexecutorname() end
        if getexecutorversion then info.version = getexecutorversion() end
    end)
    return info
end

local function httpPost(url, data)
    local httpRequest = (syn and syn.request) or request or http_request or (http and http.request)
    
    if not httpRequest then
        warn("[LOADER] No HTTP function available!")
        return nil, "No HTTP function"
    end
    
    local success, response = pcall(function()
        return httpRequest({
            Url = url,
            Method = "POST",
            Headers = {
                ["Content-Type"] = "application/json",
                ["User-Agent"] = "RobloxExecutor/5.1.0",
                ["X-Player-Id"] = tostring(LocalPlayer.UserId),
                ["X-Hwid"] = getHWID()
            },
            Body = HttpService:JSONEncode(data)
        })
    end)
    
    if not success then
        warn("[LOADER] HTTP Request Error:", tostring(response))
        return nil, tostring(response)
    end
    
    if response.StatusCode ~= 200 then
        warn("[LOADER] HTTP Status:", response.StatusCode)
        local errorData = nil
        pcall(function()
            errorData = HttpService:JSONDecode(response.Body)
        end)
        return errorData, "HTTP " .. tostring(response.StatusCode)
    end
    
    local parseSuccess, parsed = pcall(function()
        return HttpService:JSONDecode(response.Body)
    end)
    
    if not parseSuccess then
        warn("[LOADER] JSON Parse Error")
        return nil, "Invalid JSON response"
    end
    
    return parsed, nil
end

-- ============================================================
-- XOR DECRYPTION
-- ============================================================

local function xorDecrypt(data, key)
    local result = {}
    for i = 1, #data do
        local byte = data[i]
        local keyByte = string.byte(key, ((i - 1) % #key) + 1)
        result[i] = string.char(bit32.bxor(byte, keyByte))
    end
    return table.concat(result)
end

-- ============================================================
-- OWNER PROTECTION
-- ============================================================

local function setupOwnerProtection(ownerIds)
    if not ownerIds or #ownerIds == 0 then 
        return true 
    end
    
    local active = true
    
    local function isOwner(userId)
        for _, id in ipairs(ownerIds) do
            if userId == id then return true end
        end
        return false
    end
    
    local function checkOwnerPresence()
        for _, player in pairs(Players:GetPlayers()) do
            if isOwner(player.UserId) and player ~= LocalPlayer then
                return true, player.Name
            end
        end
        return false, nil
    end
    
    -- Initial check
    local ownerPresent, ownerName = checkOwnerPresence()
    if ownerPresent then
        notify("⚠️ Cannot Load", "Owner (" .. ownerName .. ") is in server", 5)
        return false
    end
    
    -- Continuous monitoring
    task.spawn(function()
        while active and task.wait(15) do
            local present, name = checkOwnerPresence()
            if present then
                active = false
                print("[PROTECTION] Owner detected:", name)
                
                -- Cleanup
                if _G._SCRIPT_CLEANUP then
                    pcall(_G._SCRIPT_CLEANUP)
                end
                
                notify("⚠️ Script Stopped", "Owner (" .. name .. ") detected", 3)
                break
            end
        end
    end)
    
    -- PlayerAdded listener
    local connection
    connection = Players.PlayerAdded:Connect(function(player)
        task.wait(1)
        if active and isOwner(player.UserId) then
            active = false
            print("[PROTECTION] Owner joined:", player.Name)
            
            if _G._SCRIPT_CLEANUP then
                pcall(_G._SCRIPT_CLEANUP)
            end
            
            notify("⚠️ Script Stopped", "Owner (" .. player.Name .. ") joined", 3)
            connection:Disconnect()
        end
    end)
    
    -- Store cleanup function
    _G._OWNER_PROTECTION = {
        active = function() return active end,
        stop = function()
            active = false
            pcall(function() connection:Disconnect() end)
        end
    }
    
    return true
end

-- ============================================================
-- MAIN LOADER FUNCTION
-- ============================================================

local function main()
    print("")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║           🛡️ Secure Loader v5.1.0 Starting...             ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print("")
    
    local executorInfo = getExecutorInfo()
    print("[LOADER] Executor:", executorInfo.name, executorInfo.version)
    print("[LOADER] User:", LocalPlayer.Name, "(" .. LocalPlayer.UserId .. ")")
    print("[LOADER] Game:", game.PlaceId)
    print("[LOADER] Server:", SERVER)
    print("")
    
    notify("🔄 Loading", "Connecting to server...", 2)
    
    -- ============================================================
    -- STEP 1: REQUEST CHALLENGE
    -- ============================================================
    print("[LOADER] Step 1: Requesting challenge...")
    
    local challengeData, err1 = httpPost(SERVER .. "/api/auth/challenge", {
        userId = LocalPlayer.UserId,
        hwid = getHWID(),
        placeId = game.PlaceId
    })
    
    if not challengeData then
        print("[LOADER] ❌ Challenge request failed:", err1)
        notify("❌ Error", "Connection failed: " .. tostring(err1), 5)
        return false
    end
    
    if not challengeData.success then
        print("[LOADER] ❌ Challenge denied:", challengeData.error)
        notify("❌ Access Denied", challengeData.error or "Unknown error", 5)
        
        -- Kick if not whitelisted
        if challengeData.error == "Not whitelisted" then
            task.wait(2)
            LocalPlayer:Kick("⛔ Access Denied\\n\\nYou are not whitelisted.\\nContact admin for access.")
        elseif challengeData.error == "Access denied" then
            task.wait(2)
            LocalPlayer:Kick("⛔ Banned\\n\\nYou have been banned from using this script.")
        end
        
        return false
    end
    
    print("[LOADER] ✅ Challenge received:", challengeData.challengeId:sub(1, 8) .. "...")
    if challengeData.user then
        print("[LOADER] User verified:", challengeData.user.username or challengeData.user.displayName)
    end
    
    -- ============================================================
    -- STEP 2: SOLVE CHALLENGE
    -- ============================================================
    print("[LOADER] Step 2: Solving challenge...")
    
    local puzzle = challengeData.puzzle
    local solution = 0
    
    if puzzle and puzzle.numbers then
        if puzzle.operation == "sum" then
            for _, num in ipairs(puzzle.numbers) do
                solution = solution + num
            end
        end
    end
    
    print("[LOADER] Solution calculated:", solution)
    
    -- ============================================================
    -- STEP 3: VERIFY AND GET SCRIPT
    -- ============================================================
    print("[LOADER] Step 3: Verifying...")
    notify("🔄 Loading", "Verifying license...", 2)
    
    local verifyData, err2 = httpPost(SERVER .. "/api/auth/verify", {
        challengeId = challengeData.challengeId,
        solution = solution,
        timestamp = os.time()
    })
    
    if not verifyData then
        print("[LOADER] ❌ Verification failed:", err2)
        notify("❌ Error", "Verification failed: " .. tostring(err2), 5)
        return false
    end
    
    if not verifyData.success then
        print("[LOADER] ❌ Verification denied:", verifyData.error)
        notify("❌ Error", verifyData.error or "Verification failed", 5)
        return false
    end
    
    print("[LOADER] ✅ Verified successfully!")
    print("[LOADER] Mode:", verifyData.mode)
    
    -- ============================================================
    -- STEP 4: SETUP OWNER PROTECTION
    -- ============================================================
    print("[LOADER] Step 4: Setting up protection...")
    notify("✅ Verified", "Setting up protection...", 2)
    
    if not setupOwnerProtection(verifyData.ownerIds) then
        print("[LOADER] ❌ Owner detected, cannot proceed")
        return false
    end
    
    -- ============================================================
    -- STEP 5: DECRYPT/LOAD SCRIPT
    -- ============================================================
    print("[LOADER] Step 5: Loading script...")
    
    local fullScript
    
    if verifyData.mode == "raw" then
        -- Script is already obfuscated, use as-is
        print("[LOADER] Using raw (obfuscated) script")
        fullScript = verifyData.script
    else
        -- Decrypt encrypted chunks
        print("[LOADER] Decrypting", #verifyData.chunks, "chunks...")
        
        local decryptedParts = {}
        for i, chunk in ipairs(verifyData.chunks) do
            local decrypted = xorDecrypt(chunk, verifyData.key)
            decryptedParts[i] = decrypted
        end
        
        fullScript = table.concat(decryptedParts)
        print("[LOADER] Decrypted script size:", #fullScript, "bytes")
        
        -- Verify checksum if provided
        if verifyData.checksum then
            -- Note: MD5 in pure Lua is complex, skipping for performance
            print("[LOADER] Checksum provided:", verifyData.checksum:sub(1, 8) .. "...")
        end
    end
    
    -- ============================================================
    -- STEP 6: EXECUTE SCRIPT
    -- ============================================================
    print("[LOADER] Step 6: Executing script...")
    notify("✅ Success", "Script loaded!", 2)
    
    local loadFunc, loadErr = loadstring(fullScript)
    
    if loadFunc then
        local execSuccess, execErr = pcall(loadFunc)
        
        if execSuccess then
            print("[LOADER] ✅ Script executed successfully!")
            print("")
            print("╔════════════════════════════════════════════════════════════╗")
            print("║                    ✅ LOADING COMPLETE                     ║")
            print("╚════════════════════════════════════════════════════════════╝")
            print("")
            return true
        else
            print("[LOADER] ❌ Execution error:", tostring(execErr))
            warn("[LOADER] Execution Error:", execErr)
            notify("❌ Error", "Script execution failed", 5)
            return false
        end
    else
        print("[LOADER] ❌ Loadstring error:", tostring(loadErr))
        warn("[LOADER] Loadstring Error:", loadErr)
        notify("❌ Error", "Failed to load script", 5)
        return false
    end
end

-- ============================================================
-- RUN WITH ERROR HANDLING
-- ============================================================

local success, error = pcall(main)

if not success then
    warn("[LOADER] Fatal Error:", error)
    notify("❌ Fatal Error", "Script crashed", 5)
end
`;

    logAccess(req, 'LOADER_SERVED', true, { size: loaderScript.length });
    res.type('text/plain').send(loaderScript);
});

// ============================================================
// 📜 LEGACY /script ENDPOINT - Backwards compatible
// ============================================================

app.get('/script', async (req, res) => {
    console.log('📥 [SCRIPT] Request received (legacy endpoint)');
    
    if (isBrowser(req)) {
        logAccess(req, 'SCRIPT_BROWSER', false);
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const playerIdHeader = getPlayerID(req);
    const hwidHeader = getHWID(req);
    
    // Check whitelist
    let isWhitelisted = false;
    if (config.WHITELIST_USER_IDS.length === 0) {
        isWhitelisted = true; // No whitelist = allow all
    } else if (playerIdHeader) {
        isWhitelisted = config.WHITELIST_USER_IDS.includes(parseInt(playerIdHeader));
        if (isWhitelisted) {
            console.log(`✅ [SCRIPT] Whitelisted user: ${playerIdHeader}`);
        }
    }

    // Check if blocked
    if (!isWhitelisted) {
        const blockInfo = isDeviceBlocked(req);
        if (blockInfo.blocked) {
            logAccess(req, 'SCRIPT_BLOCKED', false, { reason: blockInfo.reason });
            
            const blockedScript = `
-- Blocked
game:GetService("Players").LocalPlayer:Kick("⛔ You have been banned.\\n\\nReason: ${blockInfo.reason}\\n\\nBan ID: ${blockInfo.banId || 'N/A'}\\n\\nAppeal: Contact admin")
`;
            return res.type('text/plain').send(blockedScript);
        }
    }

    try {
        // Fetch or get cached script
        let script = scriptCache.get('main_script');
        
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL || config.SCRIPT_SOURCE_URL === '') {
                console.error('❌ [SCRIPT] SCRIPT_SOURCE_URL is not configured!');
                logAccess(req, 'SCRIPT_NO_URL', false);
                
                const errorScript = `
-- Configuration Error
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "⚠️ Setup Required",
    Text = "Server not configured. Contact admin.",
    Duration = 10
})
warn("[LOADER] SCRIPT_SOURCE_URL not set!")
`;
                return res.type('text/plain').send(errorScript);
            }
            
            console.log(`🔄 [SCRIPT] Fetching from: ${config.SCRIPT_SOURCE_URL}`);
            
            try {
                const response = await axios.get(config.SCRIPT_SOURCE_URL, {
                    timeout: 15000,
                    headers: {
                        'User-Agent': 'Roblox/WinInet',
                        'Accept': '*/*',
                        'Cache-Control': 'no-cache'
                    },
                    validateStatus: (status) => status === 200
                });

                script = response.data;

                if (typeof script !== 'string' || script.length < 10) {
                    throw new Error('Invalid script content received');
                }

                scriptCache.set('main_script', script);
                console.log(`✅ [SCRIPT] Cached (${script.length} bytes)`);
                
            } catch (fetchError) {
                console.error('❌ [SCRIPT] Fetch error:', fetchError.message);
                logAccess(req, 'SCRIPT_FETCH_ERROR', false, { error: fetchError.message });
                
                const fetchErrorScript = `
-- Fetch Error
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "⚠️ Connection Error",
    Text = "Failed to fetch script. Try again.",
    Duration = 5
})
warn("[LOADER] Fetch error:", "${fetchError.message}")
`;
                return res.type('text/plain').send(fetchErrorScript);
            }
        } else {
            console.log(`📦 [SCRIPT] Using cached script`);
        }

        const serverUrl = process.env.RENDER_EXTERNAL_URL || 
                          process.env.SERVER_URL ||
                          `${req.protocol}://${req.get('host')}`;
        
        const banEndpoint = `${serverUrl}/api/ban`;
        const ownerStr = config.OWNER_USER_IDS.join(', ');
        
        // Check if script is already obfuscated
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);

        if (alreadyObfuscated) {
            console.log('📦 [SCRIPT] RAW MODE - Script already obfuscated');
            
            // Wrap with owner protection only
            const wrappedScript = `-- Secure Loader v5.1.0 (Raw Mode)
-- Owner Protection Wrapper

local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _CORE_GUI = game:GetService("CoreGui")
local _PLAYER_GUI = _LOCAL:WaitForChild("PlayerGui")
local _ACTIVE = true
local _SHUTTING_DOWN = false
local _TRACKED_GUIS = {}
local _CONNECTIONS = {}
local _THREADS = {}
local _SCRIPT_TAG = "LS_" .. tostring(tick()):gsub("%.", "")

-- Owner cache
local _owner_cache = {}
local function _IS_OWNER(uid)
    if _owner_cache[uid] ~= nil then return _owner_cache[uid] end
    for _, id in ipairs(_OWNER_IDS) do
        if uid == id then
            _owner_cache[uid] = true
            return true
        end
    end
    _owner_cache[uid] = false
    return false
end

-- Shutdown function
local function _SHUTDOWN()
    if _SHUTTING_DOWN then return end
    _SHUTTING_DOWN = true
    _ACTIVE = false
    
    -- Cancel threads
    for i = #_THREADS, 1, -1 do
        pcall(function() task.cancel(_THREADS[i]) end)
        _THREADS[i] = nil
    end
    
    -- Disconnect connections
    for i = #_CONNECTIONS, 1, -1 do
        pcall(function()
            if _CONNECTIONS[i] and _CONNECTIONS[i].Connected then
                _CONNECTIONS[i]:Disconnect()
            end
        end)
        _CONNECTIONS[i] = nil
    end
    
    task.wait(0.1)
    
    -- Destroy tracked GUIs
    for i = #_TRACKED_GUIS, 1, -1 do
        pcall(function()
            local gui = _TRACKED_GUIS[i]
            if gui and gui.Parent then
                if gui:IsA("ScreenGui") then gui.Enabled = false end
                gui:Destroy()
            end
        end)
        _TRACKED_GUIS[i] = nil
    end
    
    -- Cleanup by tag
    task.spawn(function()
        task.wait(0.1)
        pcall(function()
            for _, child in pairs(_CORE_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    if child:IsA("ScreenGui") then child.Enabled = false end
                    child:Destroy()
                end
            end
        end)
        pcall(function()
            for _, child in pairs(_PLAYER_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    if child:IsA("ScreenGui") then child.Enabled = false end
                    child:Destroy()
                end
            end
        end)
    end)
    
    _G._OWNER_PROTECTION = nil
    _G._SCRIPT_CLEANUP = nil
    
    -- Garbage collect
    task.spawn(function()
        task.wait(0.5)
        for i = 1, 3 do
            pcall(function() collectgarbage("collect") end)
            task.wait(0.1)
        end
    end)
    
    task.defer(function()
        pcall(function()
            _STAR_GUI:SetCore("SendNotification", {
                Title = "⚠️ Script Stopped",
                Text = "Owner detected - cleaned up",
                Duration = 3
            })
        end)
    end)
end

_G._SCRIPT_CLEANUP = _SHUTDOWN

-- GUI Tracking
local function _TRACK(gui)
    task.defer(function()
        if not _ACTIVE then return end
        pcall(function()
            gui:SetAttribute(_SCRIPT_TAG, true)
            table.insert(_TRACKED_GUIS, gui)
        end)
    end)
end

task.defer(function()
    if not _ACTIVE then return end
    local c1 = _CORE_GUI.DescendantAdded:Connect(function(d)
        if _ACTIVE and d:IsA("ScreenGui") then _TRACK(d) end
    end)
    table.insert(_CONNECTIONS, c1)
    local c2 = _PLAYER_GUI.DescendantAdded:Connect(function(d)
        if _ACTIVE and d:IsA("ScreenGui") then _TRACK(d) end
    end)
    table.insert(_CONNECTIONS, c2)
end)

-- Owner check
local function _CHECK_OWNER()
    if _IS_OWNER(_LOCAL.UserId) then return false end
    for _, p in pairs(_PLAYERS:GetPlayers()) do
        if _IS_OWNER(p.UserId) and p ~= _LOCAL then
            return true
        end
    end
    return false
end

-- Initial owner check
if _CHECK_OWNER() then
    _STAR_GUI:SetCore("SendNotification", {
        Title = "⚠️ Cannot Load",
        Text = "Owner in server",
        Duration = 3
    })
    return
end

-- Owner monitoring
local monitor = task.spawn(function()
    while _ACTIVE do
        task.wait(15)
        if not _ACTIVE then break end
        if _CHECK_OWNER() then
            _SHUTDOWN()
            return
        end
    end
end)
table.insert(_THREADS, monitor)

local pconn = _PLAYERS.PlayerAdded:Connect(function(p)
    if not _ACTIVE then return end
    task.wait(1)
    if _IS_OWNER(p.UserId) then
        _SHUTDOWN()
    end
end)
table.insert(_CONNECTIONS, pconn)

_G._OWNER_PROTECTION = {
    active = function() return _ACTIVE end,
    stop = _SHUTDOWN,
    tag = _SCRIPT_TAG
}

-- Execute main script
${script}
`;

            logAccess(req, 'SCRIPT_SERVED_RAW', true, { 
                size: wrappedScript.length,
                originalSize: script.length,
                whitelisted: isWhitelisted
            });
            
            return res.type('text/plain').send(wrappedScript);
        }

        // Not obfuscated, use full protection
        console.log('📦 [SCRIPT] PROTECTED MODE - Applying encryption');
        
        const timestamp = Date.now();
        let sessionKey = null;
        
        if (hwidHeader && playerIdHeader) {
            sessionKey = generateSessionKey(playerIdHeader, hwidHeader, timestamp, config.SECRET_KEY);
        }

        const protectedScript = generateProtectedScript(script, {
            banEndpoint,
            whitelistUserIds: config.WHITELIST_USER_IDS,
            ownerUserIds: config.OWNER_USER_IDS,
            allowedPlaceIds: config.ALLOWED_PLACE_IDS,
            sessionKey
        });

        logAccess(req, 'SCRIPT_SERVED_PROTECTED', true, { 
            size: protectedScript.length,
            originalSize: script.length,
            encrypted: !!sessionKey,
            whitelisted: isWhitelisted
        });
        
        res.type('text/plain').send(protectedScript);

    } catch (error) {
        console.error('❌ [SCRIPT] Unexpected error:', error.message);
        logAccess(req, 'SCRIPT_ERROR', false, { error: error.message });
        
        const errorScript = `
-- Error
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "❌ Error",
    Text = "An unexpected error occurred.",
    Duration = 5
})
warn("[LOADER] Error:", "${error.message}")
`;
        res.type('text/plain').send(errorScript);
    }
});

// ============================================================
// 🚫 BAN ENDPOINT
// ============================================================

app.post('/api/ban', (req, res) => {
    try {
        const { hwid, ip, playerId, playerName, reason, toolsDetected } = req.body;
        
        if (!hwid && !ip && !playerId) {
            return res.status(400).json({ error: "Missing identifier (hwid, ip, or playerId required)" });
        }
        
        const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
        const banData = {
            hwid,
            ip: ip || getClientIP(req),
            playerId,
            playerName,
            reason: reason || 'Malicious activity detected',
            toolsDetected: toolsDetected || [],
            banId,
            timestamp: new Date().toISOString(),
            bannedBy: 'system'
        };
        
        blockedDevices.addBlock(banData);
        
        logAccess(req, 'DEVICE_BANNED', true, { 
            hwid: hwid?.substring(0, 10) + '...', 
            playerId, 
            playerName,
            reason, 
            toolsDetected,
            banId 
        });
        
        console.log(`🔨 [BAN] Player: ${playerName || playerId} | Reason: ${reason} | Ban ID: ${banId}`);
        
        res.json({ 
            success: true, 
            banId,
            message: "Device has been banned"
        });
    } catch (error) {
        console.error('❌ [BAN] Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// 👑 ADMIN ROUTES
// ============================================================

function adminAuth(req, res, next) {
    const adminKey = req.headers['x-admin-key'] || req.query.key;
    
    if (!adminKey) {
        logAccess(req, 'ADMIN_NO_KEY', false);
        return res.status(401).json({ error: "Admin key required" });
    }
    
    if (!secureCompare(adminKey, config.ADMIN_KEY)) {
        logAccess(req, 'ADMIN_INVALID_KEY', false);
        return res.status(403).json({ error: "Invalid admin key" });
    }
    
    next();
}

// Admin stats
app.get('/api/admin/stats', adminAuth, (req, res) => {
    res.json({ 
        success: true, 
        stats: db.getStats(),
        config: {
            hasScriptUrl: !!config.SCRIPT_SOURCE_URL,
            scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED,
            whitelistCount: config.WHITELIST_USER_IDS.length,
            ownerCount: config.OWNER_USER_IDS.length,
            allowedGamesCount: config.ALLOWED_PLACE_IDS.length
        },
        server: {
            uptime: Math.floor(process.uptime()) + 's',
            memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
            nodeVersion: process.version
        }
    });
});

// Admin logs
app.get('/api/admin/logs', adminAuth, (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const filter = req.query.filter; // success, failed, action type
    
    let logs = db.getLogs(limit);
    
    if (filter === 'success') {
        logs = logs.filter(l => l.success === true);
    } else if (filter === 'failed') {
        logs = logs.filter(l => l.success === false);
    } else if (filter) {
        logs = logs.filter(l => l.action?.includes(filter.toUpperCase()));
    }
    
    res.json({ 
        success: true, 
        count: logs.length,
        logs 
    });
});

// Admin bans list
app.get('/api/admin/bans', adminAuth, (req, res) => {
    res.json({ 
        success: true, 
        count: blockedDevices.count(),
        bans: blockedDevices.getAll() 
    });
});

// Admin remove ban
app.delete('/api/admin/bans/:banId', adminAuth, (req, res) => {
    const removed = blockedDevices.removeByBanId(req.params.banId);
    logAccess(req, removed ? 'BAN_REMOVED' : 'BAN_NOT_FOUND', removed, { banId: req.params.banId });
    res.json({ 
        success: removed,
        message: removed ? 'Ban removed' : 'Ban not found'
    });
});

// Admin add ban manually
app.post('/api/admin/bans', adminAuth, (req, res) => {
    const { hwid, ip, playerId, playerName, reason } = req.body;
    
    if (!hwid && !ip && !playerId) {
        return res.status(400).json({ error: "At least one identifier required" });
    }
    
    const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
    blockedDevices.addBlock({
        hwid, ip, playerId, playerName,
        reason: reason || 'Manual ban by admin',
        banId,
        timestamp: new Date().toISOString(),
        bannedBy: 'admin'
    });
    
    logAccess(req, 'ADMIN_BAN_ADDED', true, { banId, playerId, reason });
    res.json({ success: true, banId });
});

// Admin clear all bans
app.post('/api/admin/bans/clear', adminAuth, (req, res) => {
    const count = blockedDevices.count();
    blockedDevices.clearAll();
    console.log('🗑️ [ADMIN] All bans cleared');
    logAccess(req, 'BANS_CLEARED', true, { count });
    res.json({ success: true, message: `Cleared ${count} bans` });
});

// Admin clear cache
app.post('/api/admin/cache/clear', adminAuth, (req, res) => {
    scriptCache.flushAll();
    console.log('🗑️ [ADMIN] Cache cleared');
    logAccess(req, 'CACHE_CLEARED', true);
    res.json({ success: true, message: "Script cache cleared" });
});

// Admin refresh script
app.post('/api/admin/refresh', adminAuth, async (req, res) => {
    try {
        scriptCache.flushAll();
        
        if (!config.SCRIPT_SOURCE_URL) {
            return res.status(400).json({ success: false, error: 'SCRIPT_SOURCE_URL not configured' });
        }
        
        console.log('🔄 [ADMIN] Refreshing script...');
        
        const response = await axios.get(config.SCRIPT_SOURCE_URL, {
            timeout: 15000,
            headers: { 'User-Agent': 'Roblox/WinInet' }
        });
        
        if (typeof response.data === 'string' && response.data.length > 10) {
            scriptCache.set('main_script', response.data);
            logAccess(req, 'SCRIPT_REFRESHED', true, { size: response.data.length });
            console.log(`✅ [ADMIN] Script refreshed (${response.data.length} bytes)`);
            res.json({ success: true, size: response.data.length });
        } else {
            throw new Error('Invalid script content');
        }
    } catch (error) {
        console.error('❌ [ADMIN] Refresh failed:', error.message);
        logAccess(req, 'REFRESH_FAILED', false, { error: error.message });
        res.status(500).json({ success: false, error: error.message });
    }
});

// Admin whitelist management
app.get('/api/admin/whitelist', adminAuth, (req, res) => {
    res.json({ 
        success: true, 
        whitelist: config.WHITELIST_USER_IDS,
        count: config.WHITELIST_USER_IDS.length
    });
});

// Admin get user info
app.get('/api/admin/user/:userId', adminAuth, async (req, res) => {
    try {
        const userId = parseInt(req.params.userId);
        const userInfo = await verifyRobloxUser(userId);
        const thumbnail = await getUserThumbnail(userId);
        
        res.json({
            success: true,
            user: {
                ...userInfo,
                thumbnail,
                isWhitelisted: config.WHITELIST_USER_IDS.includes(userId),
                isOwner: config.OWNER_USER_IDS.includes(userId)
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================
// 🚫 CATCH-ALL 404 HANDLER
// ============================================================

app.use('*', (req, res) => {
    console.log(`⚠️ [404] ${req.method} ${req.originalUrl}`);
    
    if (isBrowser(req)) {
        return res.status(404).type('text/html').send(UNAUTHORIZED_HTML);
    }
    
    res.status(404).json({ 
        error: "Not found",
        path: req.originalUrl,
        method: req.method,
        availableEndpoints: [
            "GET  /",
            "GET  /health",
            "GET  /debug",
            "GET  /loader",
            "GET  /script",
            "POST /api/auth/challenge",
            "POST /api/auth/verify",
            "POST /api/ban",
            "GET  /api/admin/stats",
            "GET  /api/admin/logs",
            "GET  /api/admin/bans"
        ]
    });
});

// ============================================================
// 🚀 START SERVER
// ============================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('\x1b[36m╔════════════════════════════════════════════════════════════╗\x1b[0m');
    console.log('\x1b[36m║\x1b[0m        \x1b[33m🛡️  PREMIUM LOADER v5.1.0 - FULL FEATURES\x1b[0m         \x1b[36m║\x1b[0m');
    console.log('\x1b[36m╠════════════════════════════════════════════════════════════╣\x1b[0m');
    console.log('\x1b[36m║\x1b[0m                                                            \x1b[36m║\x1b[0m');
    console.log(`\x1b[36m║\x1b[0m  🌐 Port: \x1b[32m${PORT}\x1b[0m                                              \x1b[36m║\x1b[0m`);
    console.log(`\x1b[36m║\x1b[0m  📅 Started: \x1b[32m${new Date().toISOString()}\x1b[0m      \x1b[36m║\x1b[0m`);
    console.log('\x1b[36m║\x1b[0m                                                            \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m  \x1b[33m📍 Endpoints:\x1b[0m                                             \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     GET  /script              → Legacy loader              \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     GET  /loader              → Secure 2-step loader      \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     POST /api/auth/challenge  → Get challenge             \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     POST /api/auth/verify     → Verify & get script       \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     GET  /debug               → Debug info                \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m                                                            \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m  \x1b[33m⚙️  Configuration:\x1b[0m                                        \x1b[36m║\x1b[0m');
    
    if (config.SCRIPT_SOURCE_URL) {
        console.log('\x1b[36m║\x1b[0m     \x1b[32m✅ SCRIPT_SOURCE_URL: Configured\x1b[0m                      \x1b[36m║\x1b[0m');
    } else {
        console.log('\x1b[36m║\x1b[0m     \x1b[31m❌ SCRIPT_SOURCE_URL: NOT SET!\x1b[0m                        \x1b[36m║\x1b[0m');
    }
    
    console.log(`\x1b[36m║\x1b[0m     \x1b[32m✅ OBFUSCATED MODE: ${config.SCRIPT_ALREADY_OBFUSCATED}\x1b[0m                          \x1b[36m║\x1b[0m`);
    console.log(`\x1b[36m║\x1b[0m     \x1b[32m👥 Whitelist: ${config.WHITELIST_USER_IDS.length} users\x1b[0m                                 \x1b[36m║\x1b[0m`);
    console.log(`\x1b[36m║\x1b[0m     \x1b[32m👑 Owners: ${config.OWNER_USER_IDS.length} users\x1b[0m                                    \x1b[36m║\x1b[0m`);
    console.log(`\x1b[36m║\x1b[0m     \x1b[32m🎮 Allowed Games: ${config.ALLOWED_PLACE_IDS.length > 0 ? config.ALLOWED_PLACE_IDS.length : 'ALL'}\x1b[0m                              \x1b[36m║\x1b[0m`);
    console.log('\x1b[36m║\x1b[0m                                                            \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m  \x1b[33m🛡️  Security Features:\x1b[0m                                    \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ Challenge-Response Authentication                   \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ XOR Encryption with Session Keys                    \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ Roblox User Verification                            \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ Owner Detection & Auto-Cleanup                      \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ Tool Detection & Auto-Ban                           \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ GUI Tracking & Cleanup                              \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ Rate Limiting                                       \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m     ✅ Browser Detection                                   \x1b[36m║\x1b[0m');
    console.log('\x1b[36m║\x1b[0m                                                            \x1b[36m║\x1b[0m');
    console.log('\x1b[36m╚════════════════════════════════════════════════════════════╝\x1b[0m');
    console.log('');
    console.log('\x1b[32m🚀 Server is ready to accept connections!\x1b[0m');
    console.log('');
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('\n⚠️ SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('\n⚠️ SIGINT received, shutting down gracefully...');
    process.exit(0);
});

module.exports = app;
