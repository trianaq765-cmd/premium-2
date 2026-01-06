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

const UNAUTHORIZED_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Unauthorized</title><style>*{margin:0;padding:0;box-sizing:border-box}body{width:100%;height:100vh;background:#000;font-family:sans-serif;color:#fff;display:flex;justify-content:center;align-items:center;flex-direction:column}.shield{font-size:4rem;margin-bottom:20px}h1{color:#ef4444;font-size:1.5rem;margin-bottom:10px}p{color:rgba(255,255,255,0.5)}</style></head><body><div class="shield">🛡️</div><h1>⛔ Access Denied ⛔</h1><p>Error Code: 403 | Forbidden</p></body></html>`;

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'PUT', 'PATCH'], allowedHeaders: ['Content-Type', 'x-admin-key', 'Authorization', 'x-hwid', 'x-player-id'] }));
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
function isBrowser(req) { const accept = req.headers['accept'] || ''; const ua = (req.headers['user-agent'] || '').toLowerCase(); const executors = ['roblox','synapse','krnl','fluxus','delta','electron','script-ware','sentinel','coco','oxygen','evon','arceus','hydrogen','vegax','trigon','comet','jjsploit','wearedevs','executor','exploit','wininet','solara','wave','zorara','codex','nihon','celery','swift','scriptware','sirhurt','temple','valyse']; if (executors.some(k => ua.includes(k))) return false; if (accept.includes('text/html') && (ua.includes('mozilla') || ua.includes('chrome') || ua.includes('safari') || ua.includes('firefox')) && req.headers['accept-language']) return true; return false; }
function secureCompare(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }
function isScriptObfuscated(script) { if (!script || typeof script !== 'string') return false; const patterns = [/IronBrew/i, /Prometheus/i, /Moonsec/i, /Luraph/i, /PSU|PaidScriptUploader/i, /Aztup/i, /Synapse Xen/i, /-- Obfuscated/i, /-- Protected/i]; for (const p of patterns) if (p.test(script.substring(0, 500))) return true; const code = [/^local \w{1,3}=\{/, /getfenv\s*\(\s*\d+\s*\)/, /string\.char\s*\(\s*\d+/, /loadstring\s*\(\s*['"]\\x/, /\[\[.{100,}\]\]/]; for (const p of code) if (p.test(script)) return true; if ((script.match(/\\\d{1,3}/g) || []).length > 100 && script.length > 2000) return true; for (const line of script.split('\n')) if (line.length > 10000) return true; if ((script.match(/[a-zA-Z]/g) || []).length / script.length < 0.3 && script.length > 1000) return true; return false; }
function isDeviceBlocked(req) { return blockedDevices.isBlocked(getHWID(req), getClientIP(req), getPlayerID(req)); }

async function verifyRobloxUser(userId) { try { const r = await axios.get(`https://users.roblox.com/v1/users/${userId}`, { timeout: 5000 }); if (r.data?.id) return { valid: true, id: r.data.id, username: r.data.name, displayName: r.data.displayName }; return { valid: false }; } catch { return { valid: true, fallback: true }; } }

app.get('/', (req, res) => { if (isBrowser(req)) return res.status(403).type('text/html').send(UNAUTHORIZED_HTML); res.json({ status: "online", version: "5.4.0", protected: true }); });
app.get('/health', (req, res) => { res.json({ status: "ok", uptime: Math.floor(process.uptime()) }); });
app.get('/api/health', (req, res) => { if (isBrowser(req)) return res.status(403).type('text/html').send(UNAUTHORIZED_HTML); res.json({ status: "healthy", cached: scriptCache.has('main_script'), stats: db.getStats() }); });
app.get('/debug', (req, res) => { res.json({ status: "ok", version: "5.4.0", config: { hasScriptUrl: !!config.SCRIPT_SOURCE_URL, scriptAlreadyObfuscated: config.SCRIPT_ALREADY_OBFUSCATED, whitelistCount: config.WHITELIST_USER_IDS.length, ownerCount: config.OWNER_USER_IDS.length, allowedGamesCount: config.ALLOWED_PLACE_IDS.length }, stats: db.getStats() }); });

app.post('/api/auth/challenge', async (req, res) => {
    if (isBrowser(req)) return res.status(403).json({ success: false, error: "Forbidden" });
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
    if (isBrowser(req)) return res.status(403).json({ success: false, error: "Forbidden" });
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

app.get('/loader', (req, res) => {
    if (isBrowser(req)) return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    const serverUrl = process.env.RENDER_EXTERNAL_URL || process.env.SERVER_URL || `${req.protocol}://${req.get('host')}`;
    const loaderScript = `local SERVER="${serverUrl}" local HttpService=game:GetService("HttpService") local Players=game:GetService("Players") local StarterGui=game:GetService("StarterGui") local CoreGui=game:GetService("CoreGui") local LocalPlayer=Players.LocalPlayer local _ACTIVE=true
local function notify(t,x,d) pcall(function() StarterGui:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function getHWID() local s,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end if getexecutorname then return getexecutorname().."_"..tostring(LocalPlayer.UserId) end return "FB_"..tostring(LocalPlayer.UserId) end) return s and r or "UNK" end
local function httpPost(url,data) local req=(syn and syn.request) or request or http_request or (http and http.request) if not req then return nil,"No HTTP" end local s,r=pcall(function() return req({Url=url,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="RobloxExecutor/5.4"},Body=HttpService:JSONEncode(data)}) end) if not s then return nil,tostring(r) end if r.StatusCode~=200 then local e=nil pcall(function() e=HttpService:JSONDecode(r.Body) end) return e,"HTTP "..r.StatusCode end local ps,pd=pcall(function() return HttpService:JSONDecode(r.Body) end) return ps and pd or nil end
local function xorDecrypt(d,k) local r={} for i=1,#d do r[i]=string.char(bit32.bxor(d[i],string.byte(k,((i-1)%#k)+1))) end return table.concat(r) end
local function setupOwnerProtection(oIds,wIds) if not oIds or #oIds==0 then return true,true end local function isOwner(uid) for _,id in ipairs(oIds) do if uid==id then return true end end return false end local function isWL() if not wIds or #wIds==0 then return true end for _,id in ipairs(wIds) do if LocalPlayer.UserId==id then return true end end return false end local function checkOwner() for _,p in pairs(Players:GetPlayers()) do if isOwner(p.UserId) and p~=LocalPlayer then return true,p.Name end end return false,nil end local op,on=checkOwner() if op then notify("⚠️ Cannot Load","Owner ("..on..") in server",5) return false,isWL() end task.spawn(function() while _ACTIVE and task.wait(15) do local pr,nm=checkOwner() if pr then _ACTIVE=false if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end notify("⚠️ Script Stopped","Owner ("..nm..") detected",3) break end end end) Players.PlayerAdded:Connect(function(p) task.wait(1) if _ACTIVE and isOwner(p.UserId) then _ACTIVE=false if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end notify("⚠️ Script Stopped","Owner ("..p.Name..") joined",3) end end) return true,isWL() end
local function main() notify("🔄 Loading","Connecting...",2) local cData,e1=httpPost(SERVER.."/api/auth/challenge",{userId=LocalPlayer.UserId,hwid=getHWID(),placeId=game.PlaceId}) if not cData then notify("❌ Error","Connection failed",5) return false end if not cData.success then notify("❌ Denied",cData.error or "Error",5) if cData.error=="Not whitelisted" then task.wait(2) LocalPlayer:Kick("⛔ Not whitelisted") end return false end local puzzle=cData.puzzle local solution=0 if puzzle and puzzle.numbers then for _,n in ipairs(puzzle.numbers) do solution=solution+n end end notify("🔄 Loading","Verifying...",2) local vData,e2=httpPost(SERVER.."/api/auth/verify",{challengeId=cData.challengeId,solution=solution,timestamp=os.time()}) if not vData or not vData.success then notify("❌ Error",vData and vData.error or "Verify failed",5) return false end notify("✅ Verified","Loading script...",2) local canRun=setupOwnerProtection(vData.ownerIds,vData.whitelistIds) if not canRun then return false end local fullScript if vData.mode=="raw" then fullScript=vData.script else local parts={} for i,chunk in ipairs(vData.chunks) do parts[i]=xorDecrypt(chunk,vData.key) end fullScript=table.concat(parts) end local fn,err=loadstring(fullScript) if fn then pcall(fn) return true end return false end
pcall(main)`;
    logAccess(req, 'LOADER_SERVED', true, { size: loaderScript.length });
    res.type('text/plain').send(loaderScript);
});

app.get('/script', async (req, res) => {
    if (isBrowser(req)) return res.status(403).type('text/html').send(UNAUTHORIZED_HTML);
    const playerIdHeader = getPlayerID(req), hwidHeader = getHWID(req);
    let isWhitelisted = config.WHITELIST_USER_IDS.length === 0 || (playerIdHeader && config.WHITELIST_USER_IDS.includes(parseInt(playerIdHeader)));
    if (!isWhitelisted) { const blockInfo = isDeviceBlocked(req); if (blockInfo.blocked) return res.type('text/plain').send(`game:GetService("Players").LocalPlayer:Kick("⛔ Banned\\n\\nReason: ${blockInfo.reason}\\nBan ID: ${blockInfo.banId}")`); }
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
local _TOOL_SIGS={iy={"IY_LOADED","iy_loaded","InfiniteYield","Infinite Yield","IYaliases"},dex={"Dex","DexExplorer","DEX_EXPLORER","dexv4","DexV4"},spy={"SimpleSpy","SimpleSpyGui","RemoteSpy","RemoteSpyGui","remote_spy_hook"},dec={"decompile","Decompiler","DecompilerGui","saveinstance"}}
local _TOOL_GUI_NAMES={"infiniteyield","infinite yield","iy_","dex","dexexplorer","simplespy","simple_spy","remotespy","remote spy","httpspy","http spy","scriptdumper","decompiler"}
local function _checkToolsExecuted()
    for _,g in ipairs(getgenv and {getgenv()} or {_G,shared}) do for cat,sigs in pairs(_TOOL_SIGS) do for _,sig in ipairs(sigs) do if rawget(g,sig)~=nil then return true,cat:upper(),sig end end end end
    for _,loc in ipairs({_CORE,_PGUI}) do pcall(function() for _,gui in pairs(loc:GetDescendants()) do if gui:IsA("ScreenGui") or gui:IsA("Frame") or gui:IsA("TextLabel") or gui:IsA("TextButton") then local name=gui.Name:lower() for _,pattern in ipairs(_TOOL_GUI_NAMES) do if name:find(pattern,1,true) then return true,"GUI",gui.Name end end end end end) end
    if hookfunction or replaceclosure then local _hf=rawget(getgenv and getgenv() or _G,"_iy_hooked") or rawget(getgenv and getgenv() or _G,"_spy_hooked") if _hf then return true,"HOOK","function_hook" end end
    return false,nil,nil
end
local function _startToolMonitor()
    local monitor=task.spawn(function()
        task.wait(5)
        while _ACTIVE do
            task.wait(3)
            if not _ACTIVE then break end
            local detected,category,signature=_checkToolsExecuted()
            if detected then
                _ACTIVE=false
                _notify("🚨 Tool Detected",category.." tool executed",3)
                task.wait(1)
                _cleanup()
                _banPlayer("External tool detected: "..category,{category,signature})
                break
            end
        end
    end)
    table.insert(_THREADS,monitor)
    local function onDescendant(d)
        if not _ACTIVE then return end
        if d:IsA("ScreenGui") or d:IsA("Frame") then
            local name=d.Name:lower()
            for _,pattern in ipairs(_TOOL_GUI_NAMES) do
                if name:find(pattern,1,true) then
                    _ACTIVE=false
                    _notify("🚨 Tool Detected","Malicious GUI: "..d.Name,3)
                    task.wait(1)
                    _cleanup()
                    _banPlayer("Malicious tool GUI detected",{"GUI",d.Name})
                    return
                end
            end
        end
    end
    local c1=_CORE.DescendantAdded:Connect(onDescendant) table.insert(_CONNS,c1)
    local c2=_PGUI.DescendantAdded:Connect(onDescendant) table.insert(_CONNS,c2)
end
local function _checkOwner() for _,p in pairs(_PLAYERS:GetPlayers()) do if _isOwner(p.UserId) and p~=_LOCAL then return true end end return false end
if _checkOwner() then _notify("⚠️ Cannot Load","Owner in server",3) return end
local ownerMon=task.spawn(function() while _ACTIVE do task.wait(15) if not _ACTIVE then break end if _checkOwner() then _cleanup() return end end end) table.insert(_THREADS,ownerMon)
local pconn=_PLAYERS.PlayerAdded:Connect(function(p) if not _ACTIVE then return end task.wait(1) if _isOwner(p.UserId) then _cleanup() end end) table.insert(_CONNS,pconn)
_G._OWNER_PROTECTION={active=function() return _ACTIVE end,stop=_cleanup,tag=_TAG}
_startToolMonitor()
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

app.use('*', (req, res) => { if (isBrowser(req)) return res.status(404).type('text/html').send(UNAUTHORIZED_HTML); res.status(404).json({ error: "Not found", endpoints: ["GET /", "GET /loader", "GET /script", "POST /api/auth/challenge", "POST /api/auth/verify", "POST /api/ban"] }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => { console.log(`🛡️ Premium Loader v5.4.0 | Port: ${PORT} | ${new Date().toISOString()}`); console.log(`📍 Whitelist: ${config.WHITELIST_USER_IDS.length} | Owners: ${config.OWNER_USER_IDS.length} | Games: ${config.ALLOWED_PLACE_IDS.length || 'ALL'}`); console.log(`🔧 Script URL: ${config.SCRIPT_SOURCE_URL ? 'Configured' : 'NOT SET'} | Obfuscated: ${config.SCRIPT_ALREADY_OBFUSCATED}`); });
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
module.exports = app;
