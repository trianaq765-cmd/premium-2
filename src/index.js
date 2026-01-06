// ============================================================
// 🛡️ PREMIUM LOADER v5.2.1 - EXECUTOR-AWARE TOOL DETECTION
// Fixed: Don't ban executor built-in features
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
// 🔧 MIDDLEWARE
// ============================================================

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'PUT'] }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

const authLimiter = rateLimit({ windowMs: 60000, max: 20, message: { success: false, error: "Too many attempts" } });
const generalLimiter = rateLimit({ windowMs: 60000, max: 100, message: { success: false, error: "Too many requests" } });

app.use('/api/auth/', authLimiter);
app.use('/api/', generalLimiter);

// ============================================================
// 🔧 HELPER FUNCTIONS
// ============================================================

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.ip || 'unknown';
}

function getHWID(req) {
    return req.headers['x-hwid'] || req.query.hwid || null;
}

function getPlayerID(req) {
    return req.headers['x-player-id'] || req.query.pid || null;
}

function logAccess(req, action, success, details = {}) {
    const timestamp = new Date().toISOString();
    const log = { ip: getClientIP(req), hwid: getHWID(req), playerId: getPlayerID(req), action, success, timestamp, ...details };
    db.addLog(log);
    console.log(`[${timestamp}] ${success ? '✅' : '❌'} ${action} | IP: ${log.ip} | Path: ${req.path}`);
}

function isBrowser(req) {
    const accept = req.headers['accept'] || '';
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const executors = ['synapse', 'krnl', 'fluxus', 'delta', 'script-ware', 'sentinel', 'oxygen', 'evon', 'arceus', 'hydrogen', 'solara', 'wave', 'zorara', 'codex', 'celery', 'swift', 'executor', 'exploit', 'roblox', 'wininet'];
    if (executors.some(e => ua.includes(e))) return false;
    if (accept.includes('text/html') && (ua.includes('mozilla') || ua.includes('chrome') || ua.includes('safari')) && req.headers['accept-language']) return true;
    return false;
}

function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; }
}

function isScriptObfuscated(script) {
    if (!script || typeof script !== 'string') return false;
    const patterns = [/IronBrew/i, /Prometheus/i, /Moonsec/i, /Luraph/i, /PSU/i, /getfenv\s*\(\s*\d+\s*\)/, /string\.char\s*\(\s*\d+/];
    for (const p of patterns) if (p.test(script)) return true;
    if ((script.match(/\\\d{1,3}/g) || []).length > 50 && script.length > 1000) return true;
    for (const line of script.split('\n')) if (line.length > 5000) return true;
    return false;
}

// ============================================================
// 🏠 ROOT & HEALTH
// ============================================================

app.get('/', (req, res) => {
    if (isBrowser(req)) { logAccess(req, 'BROWSER_ROOT', false); return res.status(403).type('text/html').send(UNAUTHORIZED_HTML); }
    res.json({ status: "online", version: "5.2.1" });
});

app.get('/health', (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

app.get('/debug', (req, res) => {
    res.json({
        status: "ok", version: "5.2.1",
        config: { hasScriptUrl: !!config.SCRIPT_SOURCE_URL, scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED, whitelistCount: config.WHITELIST_USER_IDS.length, ownerCount: config.OWNER_USER_IDS.length, allowedGamesCount: config.ALLOWED_PLACE_IDS.length },
        stats: db.getStats()
    });
});

// ============================================================
// 🔐 AUTH ENDPOINTS
// ============================================================

app.post('/api/auth/challenge', async (req, res) => {
    if (isBrowser(req)) return res.status(403).json({ success: false, error: "Forbidden" });
    try {
        const { userId, hwid, placeId } = req.body;
        if (!userId || !hwid || !placeId) return res.status(400).json({ success: false, error: "Missing fields" });
        const userIdNum = parseInt(userId), placeIdNum = parseInt(placeId);
        const blockInfo = blockedDevices.isBlocked(hwid, getClientIP(req), userIdNum);
        if (blockInfo.blocked) { logAccess(req, 'CHALLENGE_BLOCKED', false, { userId: userIdNum }); return res.status(403).json({ success: false, error: "Access denied" }); }
        if (config.WHITELIST_USER_IDS.length > 0 && !config.WHITELIST_USER_IDS.includes(userIdNum)) { logAccess(req, 'NOT_WHITELISTED', false, { userId: userIdNum }); return res.status(403).json({ success: false, error: "Not whitelisted" }); }
        if (config.ALLOWED_PLACE_IDS.length > 0 && !config.ALLOWED_PLACE_IDS.includes(placeIdNum)) { logAccess(req, 'WRONG_GAME', false, { placeId: placeIdNum }); return res.status(403).json({ success: false, error: "Game not allowed" }); }
        const challenge = challenges.create(userIdNum, hwid, placeIdNum, getClientIP(req));
        logAccess(req, 'CHALLENGE_ISSUED', true, { userId: userIdNum });
        res.json({ success: true, challengeId: challenge.id, puzzle: challenge.puzzle, expiresIn: 60 });
    } catch (error) { console.error('Challenge error:', error); res.status(500).json({ success: false, error: "Server error" }); }
});

app.post('/api/auth/verify', async (req, res) => {
    if (isBrowser(req)) return res.status(403).json({ success: false, error: "Forbidden" });
    try {
        const { challengeId, solution, timestamp } = req.body;
        if (!challengeId || solution === undefined || !timestamp) return res.status(400).json({ success: false, error: "Missing fields" });
        const result = challenges.verify(challengeId, solution, getClientIP(req));
        if (!result.valid) { logAccess(req, 'VERIFY_FAILED', false, { error: result.error }); return res.status(403).json({ success: false, error: result.error }); }
        const challenge = result.challenge;
        let script = scriptCache.get('main_script');
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) return res.status(500).json({ success: false, error: "Server not configured" });
            try { const response = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000, headers: { 'User-Agent': 'Roblox/WinInet' } }); script = response.data; scriptCache.set('main_script', script); }
            catch (e) { return res.status(500).json({ success: false, error: "Failed to fetch script" }); }
        }
        const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);
        if (alreadyObfuscated) { logAccess(req, 'SCRIPT_SERVED_RAW', true, { userId: challenge.userId }); return res.json({ success: true, mode: 'raw', script, ownerIds: config.OWNER_USER_IDS, whitelistIds: config.WHITELIST_USER_IDS, banEndpoint: `${serverUrl}/api/ban` }); }
        const sessionKey = generateSessionKey(challenge.userId, challenge.hwid, timestamp, config.SECRET_KEY);
        const chunks = [];
        for (let i = 0; i < script.length; i += 2000) { const chunk = script.substring(i, i + 2000); const encrypted = []; for (let j = 0; j < chunk.length; j++) encrypted.push(chunk.charCodeAt(j) ^ sessionKey.charCodeAt(j % sessionKey.length)); chunks.push(encrypted); }
        logAccess(req, 'SCRIPT_SERVED_ENCRYPTED', true, { userId: challenge.userId });
        res.json({ success: true, mode: 'encrypted', key: sessionKey, chunks, ownerIds: config.OWNER_USER_IDS, whitelistIds: config.WHITELIST_USER_IDS, banEndpoint: `${serverUrl}/api/ban` });
    } catch (error) { console.error('Verify error:', error); res.status(500).json({ success: false, error: "Server error" }); }
});

// ============================================================
// 📜 LOADER ENDPOINT
// ============================================================

app.get('/loader', (req, res) => {
    if (isBrowser(req)) return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;

    const loaderScript = `--[[ Secure Loader v5.2.1 - Executor-Aware ]]
local SERVER="${serverUrl}"
local HttpService=game:GetService("HttpService")
local Players=game:GetService("Players")
local StarterGui=game:GetService("StarterGui")
local CoreGui=game:GetService("CoreGui")
local LP=Players.LocalPlayer

local _ACTIVE=true
local _TOOL_CHECK=true

local function notify(t,m,d) pcall(function() StarterGui:SetCore("SendNotification",{Title=t,Text=m,Duration=d or 3}) end) end
local function getHWID() local ok,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end return "FB_"..LP.UserId end) return ok and r or "UNK" end
local function getExecutor() local name="Unknown" pcall(function() if getexecutorname then name=getexecutorname() elseif identifyexecutor then name=identifyexecutor() end end) return name:lower() end

local function httpPost(url,data)
    local req=(syn and syn.request) or request or http_request
    if not req then return nil end
    local ok,res=pcall(function() return req({Url=url,Method="POST",Headers={["Content-Type"]="application/json"},Body=HttpService:JSONEncode(data)}) end)
    if not ok or res.StatusCode~=200 then return nil end
    local pok,parsed=pcall(function() return HttpService:JSONDecode(res.Body) end)
    return pok and parsed or nil
end

local function xorDecrypt(data,key) local r={} for i=1,#data do r[i]=string.char(bit32.bxor(data[i],string.byte(key,((i-1)%#key)+1))) end return table.concat(r) end

-- Executor built-in features to IGNORE
local EXECUTOR_BUILTINS={
    delta={"iy","infiniteyield","dex","remotespy","simplespy"},
    synapse={"dex","synspy"},
    krnl={"iy"},
    fluxus={"iy"},
    hydrogen={"iy"},
    solara={"iy"},
    ["script-ware"]={"dex"}
}

local currentExecutor=getExecutor()
local function isExecutorBuiltin(name)
    local nl=name:lower()
    local builtins=EXECUTOR_BUILTINS[currentExecutor] or {}
    for _,b in ipairs(builtins) do if nl==b or nl:find(b,1,true) then return true end end
    return false
end

-- Only detect MANUALLY LOADED tools (not executor built-ins)
local DANGEROUS_TOOLS={"hydroxide","scriptdumper","saveinstance","aimbot","esp hack","speed hack","fly hack"}

local function scanDangerousTools()
    local found={}
    pcall(function()
        for _,gui in pairs(CoreGui:GetChildren()) do
            if gui:IsA("ScreenGui") and gui.Name~="RobloxGui" and gui.Name~="PlayerList" then
                local nl=gui.Name:lower()
                if not isExecutorBuiltin(nl) then
                    for _,t in ipairs(DANGEROUS_TOOLS) do
                        if nl:find(t,1,true) then table.insert(found,gui.Name) break end
                    end
                end
            end
        end
    end)
    return found
end

local function kick(reason,tools,banEndpoint)
    _ACTIVE=false _TOOL_CHECK=false
    pcall(function()
        local req=(syn and syn.request) or request or http_request
        if req and banEndpoint then
            req({Url=banEndpoint,Method="POST",Headers={["Content-Type"]="application/json"},Body=HttpService:JSONEncode({hwid=getHWID(),playerId=LP.UserId,playerName=LP.Name,reason=reason,toolsDetected=tools or {}})})
        end
    end)
    notify("⛔ BANNED",reason,2)
    task.wait(0.5)
    LP:Kick("⛔ BANNED\\n\\n"..reason)
end

local function setupOwner(ids,wlIds)
    if not ids or #ids==0 then return true end
    local function isO(u) for _,id in ipairs(ids) do if u==id then return true end end return false end
    local function isWL() if not wlIds or #wlIds==0 then return true end for _,id in ipairs(wlIds) do if LP.UserId==id then return true end end return false end
    local function chk() for _,p in pairs(Players:GetPlayers()) do if isO(p.UserId) and p~=LP then return true end end return false end
    if chk() then notify("⚠️","Owner in server",3) return false end
    task.spawn(function() while _ACTIVE and task.wait(15) do if chk() then _ACTIVE=false notify("⚠️","Owner detected",3) break end end end)
    Players.PlayerAdded:Connect(function(p) task.wait(1) if _ACTIVE and isO(p.UserId) then _ACTIVE=false notify("⚠️","Owner joined",3) end end)
    return true,isWL()
end

local function main()
    notify("🔄","Connecting...",2)
    print("[LOADER] Executor:",currentExecutor)
    
    local ch=httpPost(SERVER.."/api/auth/challenge",{userId=LP.UserId,hwid=getHWID(),placeId=game.PlaceId})
    if not ch or not ch.success then notify("❌",ch and ch.error or "Failed",5) if ch and ch.error=="Not whitelisted" then task.wait(1) LP:Kick("⛔ Not Whitelisted") end return end
    
    local sol=0 for _,n in ipairs(ch.puzzle.numbers) do sol=sol+n end
    notify("🔄","Verifying...",2)
    
    local vf=httpPost(SERVER.."/api/auth/verify",{challengeId=ch.challengeId,solution=sol,timestamp=os.time()})
    if not vf or not vf.success then notify("❌","Verify failed",5) return end
    
    notify("✅","Loading...",2)
    local canRun,isWL=setupOwner(vf.ownerIds,vf.whitelistIds)
    if not canRun then return end
    
    if not isWL then
        local det=scanDangerousTools()
        if #det>0 then kick("Dangerous tools: "..det[1],det,vf.banEndpoint) return end
        
        CoreGui.ChildAdded:Connect(function(c)
            if not _TOOL_CHECK then return end
            if c:IsA("ScreenGui") and c.Name~="RobloxGui" then
                local nl=c.Name:lower()
                if not isExecutorBuiltin(nl) then
                    for _,t in ipairs(DANGEROUS_TOOLS) do
                        if nl:find(t,1,true) then kick("Tool: "..c.Name,{c.Name},vf.banEndpoint) return end
                    end
                end
            end
        end)
        
        task.spawn(function()
            local cnt=0
            while _TOOL_CHECK do
                task.wait(cnt<12 and 5 or 15)
                if not _TOOL_CHECK then break end
                local det=scanDangerousTools()
                if #det>0 then kick("Runtime: "..det[1],det,vf.banEndpoint) break end
                cnt=cnt+1
            end
        end)
    end
    
    local script
    if vf.mode=="raw" then script=vf.script else local p={} for i,c in ipairs(vf.chunks) do p[i]=xorDecrypt(c,vf.key) end script=table.concat(p) end
    local fn=loadstring(script) if fn then pcall(fn) end
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
    console.log('📥 [SCRIPT] Request received');
    if (isBrowser(req)) { logAccess(req, 'SCRIPT_BROWSER', false); return res.status(403).type('text/html').send(UNAUTHORIZED_HTML); }

    const playerIdHeader = getPlayerID(req);
    const hwidHeader = getHWID(req);
    let isWhitelisted = config.WHITELIST_USER_IDS.length === 0 || (playerIdHeader && config.WHITELIST_USER_IDS.includes(parseInt(playerIdHeader)));

    if (!isWhitelisted) {
        const blockInfo = blockedDevices.isBlocked(hwidHeader, getClientIP(req), playerIdHeader);
        if (blockInfo.blocked) { logAccess(req, 'SCRIPT_BLOCKED', false, { reason: blockInfo.reason }); return res.type('text/plain').send(`game:GetService("Players").LocalPlayer:Kick("⛔ BANNED\\n\\n${blockInfo.reason}")`); }
    }

    try {
        let script = scriptCache.get('main_script');
        if (!script) {
            if (!config.SCRIPT_SOURCE_URL) return res.type('text/plain').send(`game:GetService("StarterGui"):SetCore("SendNotification",{Title="⚠️",Text="Not configured",Duration=5})`);
            console.log(`🔄 [SCRIPT] Fetching from: ${config.SCRIPT_SOURCE_URL}`);
            const response = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 15000, headers: { 'User-Agent': 'Roblox/WinInet' } });
            script = response.data;
            scriptCache.set('main_script', script);
            console.log(`✅ [SCRIPT] Cached (${script.length} bytes)`);
        }

        const serverUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
        const banEndpoint = `${serverUrl}/api/ban`;
        const ownerStr = config.OWNER_USER_IDS.join(', ');
        const whitelistStr = config.WHITELIST_USER_IDS.join(', ');
        const alreadyObfuscated = config.SCRIPT_ALREADY_OBFUSCATED || isScriptObfuscated(script);

        if (alreadyObfuscated) {
            console.log('📦 [SCRIPT] RAW MODE - Executor-Aware Tool Detection');

            const wrappedScript = `-- Secure Loader v5.2.1 (Executor-Aware)
-- ============================================================
-- CONFIG
-- ============================================================
local _CFG={OWNERS={${ownerStr}},WHITELIST={${whitelistStr}},BAN_EP="${banEndpoint}"}

local Players=game:GetService("Players")
local StarterGui=game:GetService("StarterGui")
local CoreGui=game:GetService("CoreGui")
local HttpService=game:GetService("HttpService")
local LP=Players.LocalPlayer

local _ACTIVE=true
local _TOOL_CHECK=true
local _CONNS={}
local _THREADS={}

-- ============================================================
-- HELPERS
-- ============================================================
local function notify(t,m,d) pcall(function() StarterGui:SetCore("SendNotification",{Title=t,Text=m,Duration=d or 3}) end) end

local function getHWID()
    local h="UNK"
    pcall(function() if gethwid then h=gethwid() elseif get_hwid then h=get_hwid() elseif getexecutorname then h=getexecutorname().."_"..LP.UserId else h="FB_"..LP.UserId end end)
    return h
end

local function getExecutor()
    local name="unknown"
    pcall(function()
        if getexecutorname then name=getexecutorname():lower()
        elseif identifyexecutor then name=identifyexecutor():lower()
        elseif syn then name="synapse"
        elseif KRNL_LOADED then name="krnl"
        elseif fluxus then name="fluxus"
        elseif is_solara then name="solara"
        end
    end)
    return name
end

local function sendBan(reason,tools)
    pcall(function()
        local req=syn and syn.request or request or http_request
        if req and _CFG.BAN_EP~="" then
            req({Url=_CFG.BAN_EP,Method="POST",Headers={["Content-Type"]="application/json"},
                Body=HttpService:JSONEncode({hwid=getHWID(),playerId=LP.UserId,playerName=LP.Name,reason=reason,toolsDetected=tools or {},timestamp=os.time()})})
        end
    end)
end

local function kick(reason,tools)
    _ACTIVE=false _TOOL_CHECK=false
    for _,c in ipairs(_CONNS) do pcall(function() c:Disconnect() end) end
    for _,t in ipairs(_THREADS) do pcall(function() task.cancel(t) end) end
    sendBan(reason,tools)
    notify("⛔ BANNED",reason,2)
    task.wait(0.5)
    LP:Kick("⛔ BANNED\\n\\n"..reason.."\\n\\nAppeal: Contact admin")
end

-- ============================================================
-- OWNER CHECK
-- ============================================================
local function isOwner(uid) for _,id in ipairs(_CFG.OWNERS) do if uid==id then return true end end return false end
local function isWhitelisted() if #_CFG.WHITELIST==0 then return true end for _,id in ipairs(_CFG.WHITELIST) do if LP.UserId==id then return true end end return false end
local function checkOwner() if isOwner(LP.UserId) then return false end for _,p in pairs(Players:GetPlayers()) do if isOwner(p.UserId) and p~=LP then return true end end return false end

-- ============================================================
-- 🔥 EXECUTOR-AWARE TOOL DETECTION
-- ============================================================

-- Get current executor
local CURRENT_EXECUTOR=getExecutor()
print("[SECURITY] Executor detected:",CURRENT_EXECUTOR)

-- Executor built-in features to IGNORE (these are NOT cheats, they're executor features)
local EXECUTOR_BUILTINS={
    delta={"iy","infiniteyield","infinite yield","dex","dark dex","darkdex","remotespy","remote spy","simplespy","simple spy","httpspy","scriptdumper"},
    synapse={"dex","synspy","synapse spy","script hub"},
    ["synapse x"]={"dex","synspy"},
    krnl={"iy","infiniteyield"},
    fluxus={"iy","infiniteyield","script hub"},
    hydrogen={"iy","infiniteyield"},
    solara={"iy","infiniteyield"},
    oxygen={"iy","infiniteyield"},
    evon={"iy","infiniteyield"},
    arceus={"iy","infiniteyield","arceus x"},
    vegax={"iy","infiniteyield"},
    ["script-ware"]={"dex","script ware"},
    comet={"iy","infiniteyield"},
    trigon={"iy","infiniteyield"},
    wave={"iy","infiniteyield"},
    zorara={"iy","infiniteyield"},
    codex={"iy","infiniteyield"},
    celery={"iy","infiniteyield"},
    swift={"iy","infiniteyield"}
}

-- Check if a name is an executor built-in feature
local function isExecutorBuiltin(name)
    if not name then return false end
    local nameLower=name:lower()
    
    -- Get builtins for current executor
    local builtins=EXECUTOR_BUILTINS[CURRENT_EXECUTOR] or {}
    
    -- Also check generic patterns that are common executor features
    local genericBuiltins={"executor","script hub","lua","console","output"}
    
    for _,b in ipairs(builtins) do
        if nameLower==b or nameLower:find(b,1,true) then
            print("[SECURITY] Ignoring executor builtin:",name)
            return true
        end
    end
    
    for _,g in ipairs(genericBuiltins) do
        if nameLower:find(g,1,true) then
            return true
        end
    end
    
    return false
end

-- DANGEROUS tools that should ALWAYS be banned (these are cheat tools, not executor features)
local DANGEROUS_TOOLS={
    "hydroxide",       -- Advanced decompiler
    "scriptdumper",    -- Script stealer
    "saveinstance",    -- Game stealer
    "aimbot",          -- Cheat
    "esp hack",        -- Cheat
    "speed hack",      -- Cheat
    "fly hack",        -- Cheat
    "noclip hack",     -- Cheat
    "teleport hack",   -- Cheat
    "god mode",        -- Cheat
    "infinite jump"    -- Cheat
}

-- Scan for DANGEROUS tools only (not executor builtins)
local function scanDangerousTools()
    local found={}
    
    -- Scan CoreGui
    pcall(function()
        for _,gui in pairs(CoreGui:GetChildren()) do
            if (gui:IsA("ScreenGui") or gui:IsA("Folder")) and gui.Name~="RobloxGui" and gui.Name~="PlayerList" and gui.Name~="Chat" then
                local nameLower=gui.Name:lower()
                
                -- Skip if it's an executor builtin
                if isExecutorBuiltin(gui.Name) then
                    continue
                end
                
                -- Check against dangerous tools
                for _,t in ipairs(DANGEROUS_TOOLS) do
                    if nameLower:find(t,1,true) then
                        table.insert(found,gui.Name)
                        break
                    end
                end
            end
        end
    end)
    
    -- Scan _G for dangerous tools only
    pcall(function()
        local dangerousGlobals={"Hydroxide","ScriptDumper","Aimbot","ESPHack","SpeedHack"}
        for _,g in ipairs(dangerousGlobals) do
            if _G[g] then
                table.insert(found,g)
            end
        end
    end)
    
    return found
end

-- ============================================================
-- GUI MONITOR (only for dangerous tools)
-- ============================================================
local function startGUIMonitor()
    local c=CoreGui.ChildAdded:Connect(function(child)
        if not _TOOL_CHECK then return end
        task.wait(0.2)
        
        if child:IsA("ScreenGui") and child.Name~="RobloxGui" and child.Name~="PlayerList" and child.Name~="Chat" then
            -- Skip executor builtins
            if isExecutorBuiltin(child.Name) then
                print("[SECURITY] Allowed executor feature:",child.Name)
                return
            end
            
            local nameLower=child.Name:lower()
            for _,t in ipairs(DANGEROUS_TOOLS) do
                if nameLower:find(t,1,true) then
                    print("[SECURITY] 🚨 Dangerous tool:",child.Name)
                    kick("Dangerous tool: "..child.Name,{child.Name})
                    return
                end
            end
        end
    end)
    table.insert(_CONNS,c)
end

-- ============================================================
-- PERIODIC SCANNER
-- ============================================================
local function startScanner()
    local t=task.spawn(function()
        local cnt=0
        while _TOOL_CHECK do
            local interval=cnt<12 and 10 or 30  -- Slower scanning, less aggressive
            task.wait(interval)
            if not _TOOL_CHECK then break end
            
            local det=scanDangerousTools()
            if #det>0 then
                print("[SECURITY] 🚨 Detected:",table.concat(det,", "))
                kick("Dangerous tools: "..det[1],det)
                break
            end
            cnt=cnt+1
        end
    end)
    table.insert(_THREADS,t)
end

-- ============================================================
-- OWNER MONITOR
-- ============================================================
local function startOwnerMonitor()
    local t=task.spawn(function()
        while _ACTIVE do
            task.wait(15)
            if not _ACTIVE then break end
            for _,p in pairs(Players:GetPlayers()) do
                if p~=LP and isOwner(p.UserId) then
                    _ACTIVE=false _TOOL_CHECK=false
                    for _,c in ipairs(_CONNS) do pcall(function() c:Disconnect() end) end
                    for _,th in ipairs(_THREADS) do pcall(function() task.cancel(th) end) end
                    notify("⚠️ Stopped","Owner detected",3)
                    return
                end
            end
        end
    end)
    table.insert(_THREADS,t)
    
    local c=Players.PlayerAdded:Connect(function(p)
        task.wait(1)
        if _ACTIVE and isOwner(p.UserId) then
            _ACTIVE=false _TOOL_CHECK=false
            notify("⚠️ Stopped","Owner joined",3)
        end
    end)
    table.insert(_CONNS,c)
end

-- ============================================================
-- MAIN
-- ============================================================
if checkOwner() then
    notify("⚠️ Cannot Load","Owner in server",3)
    return
end

-- Tool detection only for non-whitelisted users
if not isWhitelisted() then
    print("[SECURITY] 🔍 Scanning for dangerous tools (executor features allowed)...")
    
    local det=scanDangerousTools()
    if #det>0 then
        print("[SECURITY] 🚨 Found dangerous tools:",table.concat(det,", "))
        kick("Dangerous tools: "..det[1],det)
        return
    end
    
    print("[SECURITY] ✅ Clean - starting monitors")
    startGUIMonitor()
    startScanner()
else
    print("[SECURITY] ✅ Whitelisted user - skip tool check")
end

startOwnerMonitor()
print("[LOADER] ✅ Executing script...")
print("[LOADER] Executor builtins allowed for:",CURRENT_EXECUTOR)

${script}
`;

            logAccess(req, 'SCRIPT_SERVED_RAW', true, { size: wrappedScript.length });
            return res.type('text/plain').send(wrappedScript);
        }

        // Not obfuscated
        console.log('📦 [SCRIPT] PROTECTED MODE');
        const timestamp = Date.now();
        let sessionKey = null;
        if (hwidHeader && playerIdHeader) sessionKey = generateSessionKey(playerIdHeader, hwidHeader, timestamp, config.SECRET_KEY);

        const protectedScript = generateProtectedScript(script, {
            banEndpoint, whitelistUserIds: config.WHITELIST_USER_IDS, ownerUserIds: config.OWNER_USER_IDS,
            allowedPlaceIds: config.ALLOWED_PLACE_IDS, sessionKey
        });

        logAccess(req, 'SCRIPT_SERVED_PROTECTED', true, { size: protectedScript.length });
        return res.type('text/plain').send(protectedScript);

    } catch (error) {
        console.error('Script error:', error.message);
        return res.type('text/plain').send(`game:GetService("StarterGui"):SetCore("SendNotification",{Title="❌",Text="Error",Duration=5})`);
    }
});

// ============================================================
// 🚫 BAN ENDPOINT
// ============================================================

app.post('/api/ban', (req, res) => {
    try {
        const { hwid, ip, playerId, playerName, reason, toolsDetected } = req.body;
        if (!hwid && !ip && !playerId) return res.status(400).json({ error: "Missing identifier" });
        const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
        blockedDevices.addBlock({ hwid, ip: ip || getClientIP(req), playerId, playerName, reason: reason || 'Banned', toolsDetected: toolsDetected || [], banId, timestamp: new Date().toISOString() });
        console.log(`🔨 [BAN] ${playerName || playerId} | Reason: ${reason} | Tools: ${(toolsDetected || []).join(', ')}`);
        logAccess(req, 'BANNED', true, { playerId, reason, banId, tools: toolsDetected });
        res.json({ success: true, banId });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// 👑 ADMIN ROUTES
// ============================================================

function adminAuth(req, res, next) {
    const key = req.headers['x-admin-key'] || req.query.key;
    if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: "Unauthorized" });
    next();
}

app.get('/api/admin/stats', adminAuth, (req, res) => res.json({ success: true, stats: db.getStats() }));
app.get('/api/admin/logs', adminAuth, (req, res) => res.json({ success: true, logs: db.getLogs(parseInt(req.query.limit) || 50) }));
app.get('/api/admin/bans', adminAuth, (req, res) => res.json({ success: true, bans: blockedDevices.getAll() }));
app.delete('/api/admin/bans/:banId', adminAuth, (req, res) => res.json({ success: blockedDevices.removeByBanId(req.params.banId) }));
app.post('/api/admin/cache/clear', adminAuth, (req, res) => { scriptCache.flushAll(); res.json({ success: true, message: "Cache cleared" }); });
app.post('/api/admin/bans/clear', adminAuth, (req, res) => { blockedDevices.clearAll(); res.json({ success: true, message: "All bans cleared" }); });

// ============================================================
// 🚫 404
// ============================================================

app.use('*', (req, res) => {
    if (isBrowser(req)) return res.status(404).type('text/html').send(UNAUTHORIZED_HTML);
    res.status(404).json({ error: "Not found", path: req.originalUrl });
});

// ============================================================
// 🚀 START
// ============================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║      🛡️  PREMIUM LOADER v5.2.1 - EXECUTOR-AWARE           ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  🌐 Port: ${PORT}                                              ║`);
    console.log(`║  📅 Started: ${new Date().toISOString()}      ║`);
    console.log('║                                                            ║');
    console.log('║  ⚙️  Configuration:                                        ║');
    console.log(`║     ${config.SCRIPT_SOURCE_URL ? '✅' : '❌'} SCRIPT_SOURCE_URL: ${config.SCRIPT_SOURCE_URL ? 'Configured' : 'NOT SET!'}                      ║`);
    console.log(`║     ✅ OBFUSCATED MODE: ${config.SCRIPT_ALREADY_OBFUSCATED}                            ║`);
    console.log(`║     👥 Whitelist: ${config.WHITELIST_USER_IDS.length} users                                 ║`);
    console.log(`║     👑 Owners: ${config.OWNER_USER_IDS.length} users                                    ║`);
    console.log('║                                                            ║');
    console.log('║  🛡️  Security (Executor-Aware):                            ║');
    console.log('║     ✅ Executor built-ins ALLOWED (IY, Dex, etc)           ║');
    console.log('║     ✅ Only DANGEROUS tools banned                         ║');
    console.log('║     ✅ Supports: Delta, Synapse, KRNL, Fluxus, etc         ║');
    console.log('║                                                            ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');
    console.log('🚀 Server ready!');
    console.log('');
});

module.exports = app;
