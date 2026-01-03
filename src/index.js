// ============================================================
// 🛡️ PREMIUM LOADER v4.3.0 - WITH OWNER DETECTION
// When owner joins server, all other scripts auto-destroy
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
// 🌐 UNAUTHORIZED HTML
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
// 🔧 MIDDLEWARE
// ============================================================

app.use(helmet({ 
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false 
}));

app.use(cors({ 
    origin: '*', 
    methods: ['GET', 'POST', 'DELETE', 'PUT'], 
    allowedHeaders: ['Content-Type', 'x-admin-key', 'Authorization', 'x-hwid', 'x-player-id'] 
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: { success: false, error: "Too many requests" },
    keyGenerator: (req) => getClientIP(req),
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', limiter);

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

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function isDeviceBlocked(req) {
    const hwid = getHWID(req);
    const ip = getClientIP(req);
    const playerId = getPlayerID(req);
    
    return blockedDevices.isBlocked(hwid, ip, playerId);
}

// ============================================================
// 🚀 MAIN ENDPOINT - /script
// ============================================================

app.get('/script', async (req, res) => {
    if (isBrowser(req)) {
        logAccess(req, 'BROWSER_BLOCKED', false);
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }

    const playerIdHeader = getPlayerID(req);
    const whitelistEnv = process.env.WHITELIST_USER_IDS || '';
    const whitelistUserIds = whitelistEnv
        .split(',')
        .map(id => id.trim())
        .filter(id => id !== '');
    
    let isWhitelisted = false;
    if (playerIdHeader && whitelistUserIds.includes(playerIdHeader)) {
        isWhitelisted = true;
        console.log(`✅ [WHITELISTED] Player ID ${playerIdHeader}`);
    }

    if (!isWhitelisted) {
        const blockInfo = isDeviceBlocked(req);
        if (blockInfo.blocked) {
            logAccess(req, 'BLOCKED_DEVICE_ATTEMPT', false, { reason: blockInfo.reason });
            
            const blockedScript = `
game:GetService("Players").LocalPlayer:Kick("⛔ You have been permanently banned.\\n\\nReason: ${blockInfo.reason}\\n\\nBan ID: ${blockInfo.banId || 'N/A'}")
`;
            return res.type('text/plain').send(blockedScript);
        }
    }

    try {
        console.log(`📥 [SCRIPT] Request from: ${getClientIP(req)}`);
        
        const sessionToken = generateSessionToken();
        const timestamp = Date.now();

        let script = scriptCache.get('main_script');
        
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL || config.SCRIPT_SOURCE_URL === '') {
                console.error('❌ SCRIPT_SOURCE_URL is not configured!');
                logAccess(req, 'CONFIG_ERROR', false, { error: 'SCRIPT_SOURCE_URL not set' });
                
                const configErrorScript = `
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "⚠️ Setup Required",
    Text = "Server not configured. Contact admin.",
    Duration = 10
})
warn("[LOADER] SCRIPT_SOURCE_URL not set!")
`;
                return res.status(200).type('text/plain').send(configErrorScript);
            }
            
            console.log(`🔄 Fetching from: ${config.SCRIPT_SOURCE_URL}`);
            
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
                console.log(`✅ Script cached (${script.length} bytes)`);
                
            } catch (fetchError) {
                console.error('❌ Fetch error:', fetchError.message);
                logAccess(req, 'FETCH_ERROR', false, { error: fetchError.message });
                
                const fetchErrorScript = `
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "⚠️ Connection Error",
    Text = "Failed to fetch script. Try again.",
    Duration = 5
})
warn("[LOADER] Fetch error")
`;
                return res.status(200).type('text/plain').send(fetchErrorScript);
            }
        } else {
            console.log(`📦 Using cached script`);
        }

        const serverUrl = process.env.RENDER_EXTERNAL_URL || 
                          `${req.protocol}://${req.get('host')}`;
        
        const banEndpoint = `${serverUrl}/api/ban`;
        
        // Parse owner IDs
        const ownerEnv = process.env.OWNER_USER_IDS || process.env.WHITELIST_USER_IDS || '';
        const ownerUserIds = ownerEnv
            .split(',')
            .map(id => parseInt(id.trim()))
            .filter(id => !isNaN(id));

        const protectedScript = generateProtectedScript(script, {
            sessionToken,
            timestamp,
            clientIP: getClientIP(req),
            hwid: getHWID(req),
            playerId: getPlayerID(req),
            banEndpoint,
            whitelistUserIds: whitelistUserIds.map(id => parseInt(id)).filter(id => !isNaN(id)),
            ownerUserIds: ownerUserIds
        });

        logAccess(req, 'SCRIPT_SERVED', true, { 
            size: protectedScript.length,
            originalSize: script.length,
            protected: true,
            whitelisted: isWhitelisted
        });
        
        res.status(200).type('text/plain').send(protectedScript);

    } catch (error) {
        console.error('❌ Unexpected error:', error.message);
        logAccess(req, 'SCRIPT_ERROR', false, { error: error.message });
        
        const errorScript = `
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "❌ Error",
    Text = "An error occurred.",
    Duration = 5
})
warn("[LOADER] Error")
`;
        res.status(200).type('text/plain').send(errorScript);
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
            hwid,
            ip: ip || getClientIP(req),
            playerId,
            playerName,
            reason: reason || 'Malicious tools detected',
            toolsDetected: toolsDetected || [],
            banId,
            timestamp: new Date().toISOString()
        });
        
        logAccess(req, 'DEVICE_BANNED', true, { 
            hwid, 
            playerId, 
            playerName,
            reason, 
            toolsDetected,
            banId 
        });
        
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
        version: "4.3.0",
        protected: true
    });
});

app.get('/health', (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
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
        blockedDevices: blockedDevices.count()
    });
});

// ============================================================
// 👑 ADMIN ROUTES
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
    console.log('🗑️ Cache cleared');
    logAccess(req, 'CACHE_CLEARED', true);
    res.json({ success: true, message: "Cache cleared" });
});

app.post('/api/admin/bans/clear', adminAuth, (req, res) => {
    blockedDevices.clearAll();
    console.log('🗑️ All bans cleared');
    logAccess(req, 'BANS_CLEARED', true);
    res.json({ success: true, message: "All bans cleared" });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
    res.json({ 
        success: true, 
        stats: db.getStats(),
        cache: {
            hasScript: scriptCache.has('main_script')
        },
        blockedDevices: blockedDevices.count()
    });
});

app.get('/api/admin/logs', adminAuth, (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    res.json({ success: true, logs: db.getLogs(limit) });
});

app.get('/api/admin/bans', adminAuth, (req, res) => {
    res.json({ success: true, bans: blockedDevices.getAll() });
});

app.delete('/api/admin/bans/:banId', adminAuth, (req, res) => {
    const removed = blockedDevices.removeByBanId(req.params.banId);
    logAccess(req, 'BAN_REMOVED', removed, { banId: req.params.banId });
    res.json({ success: removed });
});

app.post('/api/admin/refresh', adminAuth, async (req, res) => {
    try {
        scriptCache.flushAll();
        
        if (!config.SCRIPT_SOURCE_URL) {
            return res.status(400).json({ success: false, error: 'SCRIPT_SOURCE_URL not configured' });
        }
        
        const response = await axios.get(config.SCRIPT_SOURCE_URL, {
            timeout: 15000,
            headers: { 'User-Agent': 'Roblox/WinInet' }
        });
        
        if (typeof response.data === 'string' && response.data.length > 10) {
            scriptCache.set('main_script', response.data);
            logAccess(req, 'SCRIPT_REFRESHED', true, { size: response.data.length });
            res.json({ success: true, size: response.data.length });
        } else {
            throw new Error('Invalid response');
        }
    } catch (error) {
        logAccess(req, 'REFRESH_FAILED', false);
        res.status(500).json({ success: false, error: error.message });
    }
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
    console.log('║      🛡️  PREMIUM LOADER v4.3.0 - OWNER DETECTION        ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
    console.log(`║  🌐 Port: ${PORT}                                            ║`);
    console.log('║                                                          ║');
    console.log('║  ✅ Tool Detection                                        ║');
    console.log('║  ✅ Auto-Ban System                                       ║');
    console.log('║  ✅ Owner Detection (NEW!)                                ║');
    console.log('║     → When owner joins server                            ║');
    console.log('║     → All other scripts auto-destroy                     ║');
    console.log('║     → No kick, just disable                              ║');
    console.log('║                                                          ║');
    
    if (config.SCRIPT_SOURCE_URL) {
        console.log('║  ✅ SCRIPT_SOURCE_URL: Configured                        ║');
    } else {
        console.log('║  ❌ SCRIPT_SOURCE_URL: NOT SET!                          ║');
    }
    
    const ownerEnv = process.env.OWNER_USER_IDS || process.env.WHITELIST_USER_IDS || '';
    const ownerCount = ownerEnv.split(',').filter(id => id.trim() !== '').length;
    console.log(`║  👑 Owner IDs: ${ownerCount}                                        ║`);
    
    console.log('║                                                          ║');
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
});

module.exports = app;
