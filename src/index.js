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

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'PUT', 'PATCH'], allowedHeaders: ['Content-Type', 'x-admin-key', 'Authorization', 'x-hwid', 'x-player-id', 'x-place-id', 'x-executor'] }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.set('trust proxy', 1);

const authLimiter = rateLimit({ windowMs: 60000, max: 20, message: { success: false, error: "Too many attempts" }, keyGenerator: (req) => getClientIP(req) });
const generalLimiter = rateLimit({ windowMs: 60000, max: 100, message: { success: false, error: "Too many requests" }, keyGenerator: (req) => getClientIP(req) });
const strictLimiter = rateLimit({ windowMs: 60000, max: 10, message: { success: false, error: "Rate limit exceeded" }, keyGenerator: (req) => getClientIP(req) });

app.use('/api/auth/', authLimiter);
app.use('/api/ban', strictLimiter);
app.use('/api/', generalLimiter);

function getClientIP(req) { const f = req.headers['x-forwarded-for']; return f ? f.split(',')[0].trim() : req.headers['x-real-ip'] || req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip || 'unknown'; }
function getHWID(req) { return req.headers['x-hwid'] || req.query.hwid || req.body?.hwid || null; }
function getPlayerID(req) { return req.headers['x-player-id'] || req.query.pid || req.body?.playerId || null; }
function logAccess(req, action, success, details = {}) { const log = { ip: getClientIP(req), hwid: getHWID(req), playerId: getPlayerID(req), userAgent: req.headers['user-agent']?.substring(0, 100) || 'unknown', action, success, method: req.method, path: req.path, timestamp: new Date().toISOString(), ...details }; db.addLog(log); return log; }

// ============================================================
// 🛡️ ANTI-BOT: Detect Discord bots, Browsers, Scrapers
// ============================================================
function isBot(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    
    // Discord bots patterns
    const discordBots = ['discordbot', 'discord', 'crypta', 'mee6', 'dyno', 'carl-bot', 'dank memer'];
    for (const bot of discordBots) {
        if (ua.includes(bot)) return { isBot: true, type: 'discord', name: bot };
    }
    
    // Common bots/scrapers
    const bots = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'node-fetch', 'axios', 'got', 'request', 'http-client', 'postman', 'insomnia'];
    for (const bot of bots) {
        if (ua.includes(bot)) return { isBot: true, type: 'scraper', name: bot };
    }
    
    // Browser detection (browsers send Accept-Language, accept text/html)
    if (accept.includes('text/html') && req.headers['accept-language']) {
        const browsers = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera'];
        for (const browser of browsers) {
            if (ua.includes(browser)) return { isBot: true, type: 'browser', name: browser };
        }
    }
    
    // Empty or suspicious UA
    if (!ua || ua.length < 5) return { isBot: true, type: 'empty_ua', name: 'unknown' };
    
    return { isBot: false };
}

function isValidExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const executors = ['roblox', 'synapse', 'krnl', 'fluxus', 'delta', 'electron', 'script-ware', 'sentinel', 'oxygen', 'evon', 'arceus', 'hydrogen', 'vegax', 'trigon', 'comet', 'solara', 'wave', 'zorara', 'codex', 'celery', 'swift', 'scriptware', 'sirhurt', 'wininet', 'executor', 'exploit'];
    return executors.some(e => ua.includes(e));
}

function isBrowser(req) { 
    const botCheck = isBot(req);
    if (botCheck.isBot && botCheck.type === 'browser') return true;
    return false;
}

function secureCompare(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }
function isScriptObfuscated(script) { if (!script || typeof script !== 'string') return false; const patterns = [/IronBrew/i, /Prometheus/i, /Moonsec/i, /Luraph/i, /PSU|PaidScriptUploader/i, /Aztup/i, /Synapse Xen/i, /-- Obfuscated/i, /-- Protected/i]; for (const p of patterns) if (p.test(script.substring(0, 500))) return true; const code = [/^local \w{1,3}=\{/, /getfenv\s*\(\s*\d+\s*\)/, /string\.char\s*\(\s*\d+/, /loadstring\s*\(\s*['"]\\x/, /\[\[.{100,}\]\]/]; for (const p of code) if (p.test(script)) return true; if ((script.match(/\\\d{1,3}/g) || []).length > 100 && script.length > 2000) return true; for (const line of script.split('\n')) if (line.length > 10000) return true; if ((script.match(/[a-zA-Z]/g) || []).length / script.length < 0.3 && script.length > 1000) return true; return false; }
function isDeviceBlocked(req) { return blockedDevices.isBlocked(getHWID(req), getClientIP(req), getPlayerID(req)); }

async function verifyRobloxUser(userId) { try { const r = await axios.get(`https://users.roblox.com/v1/users/${userId}`, { timeout: 5000 }); if (r.data?.id) return { valid: true, id: r.data.id, username: r.data.name, displayName: r.data.displayName }; return { valid: false }; } catch { return { valid: true, fallback: true }; } }

app.get('/', (req, res) => { 
    const botCheck = isBot(req);
    if (botCheck.isBot) {
        logAccess(req, 'BOT_BLOCKED', false, { botType: botCheck.type, botName: botCheck.name });
        return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    }
    res.json({ status: "online", version: "5.4.3", protected: true }); 
});

app.get('/health', (req, res) => { res.json({ status: "ok", uptime: Math.floor(process.uptime()) }); });
app.get('/api/health', (req, res) => { 
    const botCheck = isBot(req);
    if (botCheck.isBot) return res.status(403).json({ error: "Forbidden" });
    res.json({ status: "healthy", cached: scriptCache.has('main_script'), stats: db.getStats() }); 
});
app.get('/debug', (req, res) => { res.json({ status: "ok", version: "5.4.3", config: { hasScriptUrl: !!config.SCRIPT_SOURCE_URL, scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED, whitelistCount: config.WHITELIST_USER_IDS.length, ownerCount: config.OWNER_USER_IDS.length, allowedGamesCount: config.ALLOWED_PLACE_IDS.length }, stats: db.getStats() }); });

app.post('/api/auth/challenge', async (req, res) => {
    const botCheck = isBot(req);
    if (botCheck.isBot) {
        logAccess(req, 'BOT_BLOCKED_CHALLENGE', false, { botType: botCheck.type });
        return res.status(403).json({ success: false, error: "Forbidden" });
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
    } catch (error) { res.status(500).json({ success: false, error: "Server error" }); }
});

app.post('/api/auth/verify', async (req, res) => {
    const botCheck = isBot(req);
    if (botCheck.isBot) {
        logAccess(req, 'BOT_BLOCKED_VERIFY', false, { botType: botCheck.type });
        return res.status(403).json({ success: false, error: "Forbidden" });
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
            return res.json({ success: true, mode: 'raw', script, ownerIds: config.OWNER_USER_IDS, whitelistIds: config.WHITELIST_USER_IDS, banEndpoint: `${serverUrl}/api/ban`, meta: { userId: challenge.userId, placeId: challenge.placeId, timestamp: Date.now() } });
        }
        const sessionKey = generateSessionKey(challenge.userId, challenge.hwid, timestamp, config.SECRET_KEY);
        const chunks = []; const chunkSize = 2000;
        for (let i = 0; i < script.length; i += chunkSize) { const chunk = script.substring(i, i + chunkSize); const encrypted = []; for (let j = 0; j < chunk.length; j++) encrypted.push(chunk.charCodeAt(j) ^ sessionKey.charCodeAt(j % sessionKey.length)); chunks.push(encrypted); }
        const checksum = crypto.createHash('md5').update(script).digest('hex');
        logAccess(req, 'SCRIPT_SERVED_ENCRYPTED', true, { userId: challenge.userId, chunks: chunks.length });
        res.json({ success: true, mode: 'encrypted', key: sessionKey, chunks, checksum, ownerIds: config.OWNER_USER_IDS, whitelistIds: config.WHITELIST_USER_IDS, banEndpoint: `${serverUrl}/api/ban`, meta: { userId: challenge.userId, placeId: challenge.placeId, timestamp: Date.now() } });
    } catch (error) { res.status(500).json({ success: false, error: "Server error" }); }
});

// ============================================================
// 📜 LOADER ENDPOINT - Anti-Bot + Fixed Spy Detection
// ============================================================
const loaderHandler = (req, res) => {
    // Block bots/browsers/scrapers
    const botCheck = isBot(req);
    if (botCheck.isBot) {
        logAccess(req, 'BOT_BLOCKED_LOADER', false, { botType: botCheck.type, botName: botCheck.name });
        return res.status(403).type('text/plain').send('--[[ Access Denied ]]');
    }
    
    // Require valid executor UA
    if (!isValidExecutor(req)) {
        logAccess(req, 'INVALID_EXECUTOR_LOADER', false, { ua: req.headers['user-agent'] });
        return res.status(403).type('text/plain').send('--[[ Invalid Request ]]');
    }
    
    const serverUrl = process.env.RENDER_EXTERNAL_URL || process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
    
    // Fixed loader - hanya detect spy yang AKTIF (bukan yang tersedia)
    const loaderScript = `local _S="${serverUrl}" 
local function _c()
    local _cg=game:GetService("CoreGui")
    local _pg=game:GetService("Players").LocalPlayer:FindFirstChild("PlayerGui")
    local _spyPatterns={"simplespy","simple_spy","httpspy","http_spy","remotespy","remote_spy","hydroxide","dex_explorer","dex v4","networkspy","requestlogger"}
    for _,g in pairs(_cg:GetChildren()) do
        if g:IsA("ScreenGui") and g.Enabled then
            local nm=g.Name:lower()
            for _,p in pairs(_spyPatterns) do
                if nm:find(p,1,true) then return true,g.Name end
            end
        end
    end
    if _pg then
        for _,g in pairs(_pg:GetChildren()) do
            if g:IsA("ScreenGui") and g.Enabled then
                local nm=g.Name:lower()
                for _,p in pairs(_spyPatterns) do
                    if nm:find(p,1,true) then return true,g.Name end
                end
            end
        end
    end
    local _g=getgenv and getgenv() or _G
    local _activeMarkers={"SimpleSpyExecuted","_G.SimpleSpyExecuted","SimpleSpy_Loaded","HttpSpy_Active","RemoteSpy_Active","IY_LOADED","InfiniteYieldLoaded"}
    for _,m in pairs(_activeMarkers) do
        local v=rawget(_g,m)
        if v==true then return true,m end
    end
    if rawget(_g,"SimpleSpy") and type(rawget(_g,"SimpleSpy"))=="table" and rawget(_g,"SimpleSpy").enabled==true then
        return true,"SimpleSpy.enabled"
    end
    if rawget(_g,"HttpSpy") and type(rawget(_g,"HttpSpy"))=="table" then
        return true,"HttpSpy"
    end
    return false,nil
end
local function _k(r) task.wait(0.5) game:GetService("Players").LocalPlayer:Kick(r) end
local function _n(t,x,d) pcall(function() game:GetService("StarterGui"):SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local _HS=game:GetService("HttpService") local _P=game:GetService("Players") local _LP=_P.LocalPlayer local _A=true
local function _hw() local s,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end if getexecutorname then return getexecutorname().."_"..tostring(_LP.UserId) end return "FB_"..tostring(_LP.UserId) end) return s and r or "UNK" end
local function _hp(u,d) local rq=(syn and syn.request) or request or http_request or (http and http.request) if not rq then return nil,"No HTTP" end local s,r=pcall(function() return rq({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="RobloxExecutor/5.4",["X-HWID"]=_hw(),["X-Player-ID"]=tostring(_LP.UserId),["X-Place-ID"]=tostring(game.PlaceId)},Body=_HS:JSONEncode(d)}) end) if not s then return nil,tostring(r) end if r.StatusCode~=200 then local e=nil pcall(function() e=_HS:JSONDecode(r.Body) end) return e,"HTTP "..r.StatusCode end local ps,pd=pcall(function() return _HS:JSONDecode(r.Body) end) return ps and pd or nil end
local function _xd(d,k) local r={} for i=1,#d do r[i]=string.char(bit32.bxor(d[i],string.byte(k,((i-1)%#k)+1))) end return table.concat(r) end
local function _op(oIds,wIds) if not oIds or #oIds==0 then return true end local function isO(uid) for _,id in ipairs(oIds) do if uid==id then return true end end return false end local function chk() for _,p in pairs(_P:GetPlayers()) do if isO(p.UserId) and p~=_LP then return true,p.Name end end return false,nil end local op,on=chk() if op then _n("⚠️ Cannot Load","Owner ("..on..") in server",5) return false end task.spawn(function() while _A and task.wait(15) do local pr,nm=chk() if pr then _A=false if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end _n("⚠️ Script Stopped","Owner ("..nm..") detected",3) break end end end) _P.PlayerAdded:Connect(function(p) task.wait(1) if _A and isO(p.UserId) then _A=false if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end _n("⚠️ Script Stopped","Owner ("..p.Name..") joined",3) end end) return true end
local function _m() 
    local sp,nm=_c() 
    if sp then 
        _n("🚨 Spy Active",nm.." is running",3) 
        _k("⛔ Active Spy Tool Detected\\n\\nTool: "..nm.."\\n\\nClose the spy tool and try again") 
        return false 
    end 
    _n("🔄 Loading","Connecting...",2) 
    local cD,e1=_hp(_S.."/api/auth/challenge",{userId=_LP.UserId,hwid=_hw(),placeId=game.PlaceId}) 
    if not cD then _n("❌ Error","Connection failed",5) return false end 
    if not cD.success then _n("❌ Denied",cD.error or "Error",5) if cD.error=="Not whitelisted" then task.wait(2) _LP:Kick("⛔ Not whitelisted") end return false end 
    local pz=cD.puzzle local sl=0 
    if pz and pz.numbers then for _,n in ipairs(pz.numbers) do sl=sl+n end end 
    local sp2,nm2=_c() 
    if sp2 then 
        _n("🚨 Spy Active",nm2.." detected",3) 
        _k("⛔ Spy Tool: "..nm2) 
        return false 
    end 
    _n("🔄 Loading","Verifying...",2) 
    local vD,e2=_hp(_S.."/api/auth/verify",{challengeId=cD.challengeId,solution=sl,timestamp=os.time()}) 
    if not vD or not vD.success then _n("❌ Error",vD and vD.error or "Verify failed",5) return false end 
    _n("✅ Verified","Loading...",2) 
    local cr=_op(vD.ownerIds,vD.whitelistIds) 
    if not cr then return false end 
    local sp3,nm3=_c() 
    if sp3 then 
        _n("🚨 Spy Active",nm3.." detected",3) 
        _k("⛔ Spy Tool: "..nm3) 
        return false 
    end 
    local fs 
    if vD.mode=="raw" then fs=vD.script else local pts={} for i,ch in ipairs(vD.chunks) do pts[i]=_xd(ch,vD.key) end fs=table.concat(pts) end 
    local fn,er=loadstring(fs) 
    if fn then 
        local _ok,_er=pcall(fn) 
        if not _ok then _n("❌ Error","Script error",5) end 
        return _ok 
    end 
    _n("❌ Error","Parse failed",5) 
    return false 
end
task.spawn(function() task.wait(0.1) pcall(_m) end)`;
    
    logAccess(req, 'LOADER_SERVED', true, { size: loaderScript.length });
    res.type('text/plain').send(loaderScript);
};

app.get('/api/loader.lua', loaderHandler);
app.get('/loader', loaderHandler);

// ============================================================
// ✅ FIXED: /script endpoint - Anti-Bot + Whitelist
// ============================================================
app.get('/script', async (req, res) => {
    // Block bots/browsers/scrapers
    const botCheck = isBot(req);
    if (botCheck.isBot) {
        logAccess(req, 'BOT_BLOCKED_SCRIPT', false, { botType: botCheck.type, botName: botCheck.name });
        return res.status(403).type('text/plain').send('--[[ Access Denied ]]');
    }
    
    // Require valid executor UA
    if (!isValidExecutor(req)) {
        logAccess(req, 'INVALID_EXECUTOR_SCRIPT', false, { ua: req.headers['user-agent'] });
        return res.status(403).type('text/plain').send('--[[ Invalid Request ]]');
    }
    
    const playerIdHeader = getPlayerID(req), hwidHeader = getHWID(req);
    
    const blockInfo = isDeviceBlocked(req); 
    if (blockInfo.blocked) return res.type('text/plain').send(`game:GetService("Players").LocalPlayer:Kick("⛔ Banned\\n\\nReason: ${blockInfo.reason}\\nBan ID: ${blockInfo.banId}")`);
    
    let isWhitelisted = config.WHITELIST_USER_IDS.length === 0 || (playerIdHeader && config.WHITELIST_USER_IDS.includes(parseInt(playerIdHeader)));
    if (!isWhitelisted) { 
        logAccess(req, 'WHITELIST_REJECTED', false, { playerId: playerIdHeader }); 
        return res.type('text/plain').send(`game:GetService("StarterGui"):SetCore("SendNotification",{Title="⛔ Not Whitelisted",Text="Your account is not whitelisted",Duration=5}) task.wait(2) game:GetService("Players").LocalPlayer:Kick("⛔ Not Whitelisted\\n\\nYour User ID: ${playerIdHeader || 'Unknown'}\\n\\nContact admin for access")`); 
    }
    
    try {
        let script = scriptCache.get('main_script');
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) return res.type('text/plain').send(`game:GetService("StarterGui"):SetCore("SendNotification",{Title="⚠️ Error",Text="Server not configured",Duration=10})`);
            try { const response = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000, headers: { 'User-Agent': 'Roblox/WinInet' }, validateStatus: (s) => s === 200 }); script = response.data; if (typeof script !== 'string' || script.length < 10) throw new Error('Invalid'); scriptCache.set('main_script', script); } catch { return res.type('text/plain').send(`game:GetService("StarterGui"):SetCore("SendNotification",{Title="⚠️ Error",Text="Failed to fetch",Duration=5})`); }
        }
        const serverUrl = process.env.RENDER_EXTERNAL_URL || process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
        const banEndpoint = `${serverUrl}/api/ban`, ownerStr = config.OWNER_USER_IDS.join(', ');
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);
        if (alreadyObfuscated) {
            const wrappedScript = `local _OWNER_IDS={${ownerStr}} local _BAN_EP="${banEndpoint}" local _PLAYERS=game:GetService("Players") local _LOCAL=_PLAYERS.LocalPlayer local _STAR=game:GetService("StarterGui") local _CORE=game:GetService("CoreGui") local _PGUI=_LOCAL:WaitForChild("PlayerGui") local _HTTP=game:GetService("HttpService") local _ACTIVE=true local _SHUTDOWN=false local _GUIS={} local _CONNS={} local _THREADS={} local _TAG="LS_"..tostring(tick()):gsub("%.","")
local _ocache={} local function _isOwner(uid) if _ocache[uid]~=nil then return _ocache[uid] end for _,id in ipairs(_OWNER_IDS) do if uid==id then _ocache[uid]=true return true end end _ocache[uid]=false return false end
local function _notify(t,x,d) pcall(function() _STAR:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function _getHWID() local s,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end if getexecutorname then return getexecutorname().."_"..tostring(_LOCAL.UserId) end return "FB_"..tostring(_LOCAL.UserId) end) return s and r or "UNK" end
local function _httpPost(url,data) local req=(syn and syn.request) or request or http_request or (http and http.request) if not req then return end pcall(function() req({Url=url,Method="POST",Headers={["Content-Type"]="application/json"},Body=_HTTP:JSONEncode(data)}) end) end
local function _banPlayer(reason,tools) _httpPost(_BAN_EP,{hwid=_getHWID(),ip="",playerId=_LOCAL.UserId,playerName=_LOCAL.Name,reason=reason,toolsDetected=tools or {}}) task.wait(0.5) _LOCAL:Kick("⛔ Banned\\n\\nReason: "..reason.."\\n\\nAppeal: Contact admin") end
local function _cleanup() if _SHUTDOWN then return end _SHUTDOWN=true _ACTIVE=false for i=#_THREADS,1,-1 do pcall(function() task.cancel(_THREADS[i]) end) _THREADS[i]=nil end for i=#_CONNS,1,-1 do pcall(function() if _CONNS[i] and _CONNS[i].Connected then _CONNS[i]:Disconnect() end end) _CONNS[i]=nil end task.wait(0.1) for i=#_GUIS,1,-1 do pcall(function() if _GUIS[i] and _GUIS[i].Parent then if _GUIS[i]:IsA("ScreenGui") then _GUIS[i].Enabled=false end _GUIS[i]:Destroy() end end) _GUIS[i]=nil end task.spawn(function() task.wait(0.1) pcall(function() for _,c in pairs(_CORE:GetChildren()) do if c:GetAttribute(_TAG) then if c:IsA("ScreenGui") then c.Enabled=false end c:Destroy() end end end) pcall(function() for _,c in pairs(_PGUI:GetChildren()) do if c:GetAttribute(_TAG) then if c:IsA("ScreenGui") then c.Enabled=false end c:Destroy() end end end) end) _G._OWNER_PROTECTION=nil _G._SCRIPT_CLEANUP=nil task.spawn(function() task.wait(0.5) for i=1,3 do pcall(function() collectgarbage("collect") end) task.wait(0.1) end end) _notify("⚠️ Stopped","Cleaned up",3) end
_G._SCRIPT_CLEANUP=_cleanup
local function _trackGUI(gui) task.defer(function() if not _ACTIVE then return end pcall(function() gui:SetAttribute(_TAG,true) table.insert(_GUIS,gui) end) end) end
task.defer(function() if not _ACTIVE then return end local c1=_CORE.DescendantAdded:Connect(function(d) if _ACTIVE and d:IsA("ScreenGui") then _trackGUI(d) end end) table.insert(_CONNS,c1) local c2=_PGUI.DescendantAdded:Connect(function(d) if _ACTIVE and d:IsA("ScreenGui") then _trackGUI(d) end end) table.insert(_CONNS,c2) end)
local _SPY_PATTERNS={"simplespy","simple_spy","httpspy","http_spy","remotespy","remote_spy","hydroxide","dex_explorer","networkspy"}
local _ACTIVE_MARKERS={"SimpleSpyExecuted","SimpleSpy_Loaded","HttpSpy_Active","RemoteSpy_Active","IY_LOADED","InfiniteYieldLoaded"}
local function _checkSpyActive()
    for _,g in pairs(_CORE:GetChildren()) do
        if g:IsA("ScreenGui") and g.Enabled then
            local nm=g.Name:lower()
            for _,p in pairs(_SPY_PATTERNS) do
                if nm:find(p,1,true) then return true,"GUI",g.Name end
            end
        end
    end
    local env=getgenv and getgenv() or _G
    for _,m in pairs(_ACTIVE_MARKERS) do
        if rawget(env,m)==true then return true,"MARKER",m end
    end
    if rawget(env,"SimpleSpy") and type(rawget(env,"SimpleSpy"))=="table" and rawget(env,"SimpleSpy").enabled==true then
        return true,"SIMPLESPY","SimpleSpy.enabled"
    end
    return false,nil,nil
end
local function _startSpyMonitor()
    local monitor=task.spawn(function()
        task.wait(10)
        while _ACTIVE do
            task.wait(5)
            if not _ACTIVE then break end
            local detected,category,signature=_checkSpyActive()
            if detected then
                _ACTIVE=false
                _notify("🚨 Spy Detected",category..": "..signature,3)
                task.wait(1)
                _cleanup()
                _banPlayer("Active spy tool detected: "..signature,{category,signature})
                break
            end
        end
    end)
    table.insert(_THREADS,monitor)
end
local function _checkOwner() for _,p in pairs(_PLAYERS:GetPlayers()) do if _isOwner(p.UserId) and p~=_LOCAL then return true end end return false end
if _checkOwner() then _notify("⚠️ Cannot Load","Owner in server",3) return end
local ownerMon=task.spawn(function() while _ACTIVE do task.wait(15) if not _ACTIVE then break end if _checkOwner() then _cleanup() return end end end) table.insert(_THREADS,ownerMon)
local pconn=_PLAYERS.PlayerAdded:Connect(function(p) if not _ACTIVE then return end task.wait(1) if _isOwner(p.UserId) then _cleanup() end end) table.insert(_CONNS,pconn)
_G._OWNER_PROTECTION={active=function() return _ACTIVE end,stop=_cleanup,tag=_TAG}
_startSpyMonitor()
${script}`;
            logAccess(req, 'SCRIPT_SERVED_RAW', true, { size: wrappedScript.length });
            return res.type('text/plain').send(wrappedScript);
        }
        const timestamp = Date.now();
        let sessionKey = null;
        if (hwidHeader && playerIdHeader) sessionKey = generateSessionKey(playerIdHeader, hwidHeader, timestamp, config.SECRET_KEY);
        const protectedScript = generateProtectedScript(script, { banEndpoint, whitelistUserIds: config.WHITELIST_USER_IDS, ownerUserIds: config.OWNER_USER_IDS, allowedPlaceIds: config.ALLOWED_PLACE_IDS, sessionKey });
        logAccess(req, 'SCRIPT_SERVED_PROTECTED', true, { size: protectedScript.length });
        res.type('text/plain').send(protectedScript);
    } catch { res.type('text/plain').send(`game:GetService("StarterGui"):SetCore("SendNotification",{Title="❌ Error",Text="Unexpected error",Duration=5})`); }
});

app.post('/api/ban', (req, res) => {
    try {
        const { hwid, ip, playerId, playerName, reason, toolsDetected } = req.body;
        if (!hwid && !ip && !playerId) return res.status(400).json({ error: "Missing identifier" });
        const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
        blockedDevices.addBlock({ hwid, ip: ip || getClientIP(req), playerId, playerName, reason: reason || 'Manual ban', toolsDetected: toolsDetected || [], banId, timestamp: new Date().toISOString(), bannedBy: 'system' });
        logAccess(req, 'DEVICE_BANNED', true, { playerId, playerName, reason, toolsDetected, banId });
        res.json({ success: true, banId });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

function adminAuth(req, res, next) { const k = req.headers['x-admin-key'] || req.query.key; if (!k) return res.status(401).json({ error: "Admin key required" }); if (!secureCompare(k, config.ADMIN_KEY)) return res.status(403).json({ error: "Invalid admin key" }); next(); }

app.get('/api/admin/stats', adminAuth, (req, res) => { res.json({ success: true, stats: db.getStats(), config: { hasScriptUrl: !!config.SCRIPT_SOURCE_URL, scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED, whitelistCount: config.WHITELIST_USER_IDS.length, ownerCount: config.OWNER_USER_IDS.length }, server: { uptime: Math.floor(process.uptime()) + 's', memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB' } }); });
app.get('/api/admin/logs', adminAuth, (req, res) => { const limit = Math.min(parseInt(req.query.limit) || 50, 500); let logs = db.getLogs(limit); if (req.query.filter) logs = logs.filter(l => l.action?.includes(req.query.filter.toUpperCase())); res.json({ success: true, count: logs.length, logs }); });
app.get('/api/admin/bans', adminAuth, (req, res) => { res.json({ success: true, count: blockedDevices.count(), bans: blockedDevices.getAll() }); });
app.delete('/api/admin/bans/:banId', adminAuth, (req, res) => { const removed = blockedDevices.removeByBanId(req.params.banId); res.json({ success: removed, message: removed ? 'Ban removed' : 'Ban not found' }); });
app.post('/api/admin/bans', adminAuth, (req, res) => { const { hwid, ip, playerId, playerName, reason } = req.body; if (!hwid && !ip && !playerId) return res.status(400).json({ error: "Identifier required" }); const banId = crypto.randomBytes(8).toString('hex').toUpperCase(); blockedDevices.addBlock({ hwid, ip, playerId, playerName, reason: reason || 'Manual ban by admin', banId, timestamp: new Date().toISOString(), bannedBy: 'admin' }); res.json({ success: true, banId }); });
app.post('/api/admin/bans/clear', adminAuth, (req, res) => { const count = blockedDevices.count(); blockedDevices.clearAll(); res.json({ success: true, message: `Cleared ${count} bans` }); });
app.post('/api/admin/cache/clear', adminAuth, (req, res) => { scriptCache.flushAll(); res.json({ success: true, message: "Cache cleared" }); });
app.post('/api/admin/refresh', adminAuth, async (req, res) => { try { scriptCache.flushAll(); if (!config.SCRIPT_SOURCE_URL) return res.status(400).json({ success: false, error: 'No URL configured' }); const response = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000, headers: { 'User-Agent': 'Roblox/WinInet' } }); if (typeof response.data === 'string' && response.data.length > 10) { scriptCache.set('main_script', response.data); res.json({ success: true, size: response.data.length }); } else throw new Error('Invalid content'); } catch (error) { res.status(500).json({ success: false, error: error.message }); } });
app.get('/api/admin/whitelist', adminAuth, (req, res) => { res.json({ success: true, whitelist: config.WHITELIST_USER_IDS, count: config.WHITELIST_USER_IDS.length }); });
app.get('/api/admin/user/:userId', adminAuth, async (req, res) => { try { const userId = parseInt(req.params.userId); const userInfo = await verifyRobloxUser(userId); res.json({ success: true, user: { ...userInfo, isWhitelisted: config.WHITELIST_USER_IDS.includes(userId), isOwner: config.OWNER_USER_IDS.includes(userId) } }); } catch (error) { res.status(500).json({ success: false, error: error.message }); } });

app.use('*', (req, res) => { 
    const botCheck = isBot(req);
    if (botCheck.isBot) return res.status(404).type('text/plain').send('--[[ Not Found ]]');
    res.status(404).json({ error: "Not found" }); 
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => { console.log(`🛡️ Premium Loader v5.4.3 | Port: ${PORT} | ${new Date().toISOString()}`); console.log(`📍 Whitelist: ${config.WHITELIST_USER_IDS.length} | Owners: ${config.OWNER_USER_IDS.length} | Games: ${config.ALLOWED_PLACE_IDS.length || 'ALL'}`); console.log(`🔧 Script URL: ${config.SCRIPT_SOURCE_URL ? 'Configured' : 'NOT SET'} | Obfuscated: ${config.SCRIPT_ALREADY_OBFUSCATED}`); });
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
module.exports = app;
