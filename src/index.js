const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const config = require('./config');
const db = require('./lib/database');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONSTANTS ====================
const UNAUTHORIZED_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>403</title><style>*{margin:0;padding:0}body{background:#000;color:#fff;font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh}.c{text-align:center}.s{font-size:4rem;margin-bottom:1rem}h1{color:#ef4444}p{color:#666}</style></head><body><div class="c"><div class="s">🛡️</div><h1>403 Forbidden</h1><p>Access Denied</p></div></body></html>`;

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Trust proxy untuk mendapatkan IP yang benar di Render
app.set('trust proxy', true);

// CORS Middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type,x-admin-key,x-hwid,x-player-id,x-executor-token,x-roblox-id,x-place-id,x-job-id');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// ==================== HELPER FUNCTIONS ====================
function generateFakeScript() {
    const r = (l) => { let s = ''; const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'; for (let i = 0; i < l; i++) s += c[Math.floor(Math.random() * c.length)]; return s; };
    const n = () => Math.floor(Math.random() * 99999);
    const h = () => { let x = ''; for (let i = 0; i < Math.floor(Math.random() * 15) + 5; i++) x += '\\' + Math.floor(Math.random() * 255); return x; };
    const v = Array.from({length: 20}, () => r(Math.floor(Math.random() * 4) + 2));
    const f = Array.from({length: 80}, () => `"${h()}"`).join(',');
    const t = Array.from({length: 40}, () => `[${n()}]="${r(10)}"`).join(',');
    return `local ${v[0]}=(function()local ${v[1]}={${f}};local ${v[2]}={${t}};local ${v[3]}=0;for ${v[4]}=1,#${v[1]} do ${v[3]}=${v[3]}+((string.byte(${v[1]}[${v[4]}]:sub(1,1))or 0)%256)end;return ${v[3]} end)();local ${v[5]}=coroutine.wrap(function()for ${v[6]}=1,${n()} do local ${v[7]}=bit32.bxor(${v[6]},${n()})coroutine.yield(${v[7]})end end);local ${v[8]}=setmetatable({${t}},{__index=function(t,k)return rawget(t,k)or"${r(16)}"end,__newindex=function()end});(function()local ${v[9]}={}for ${v[10]}=1,math.random(50,150)do ${v[9]}[${v[10]}]=string.rep("${r(4)}",math.random(5,20)):reverse()end;for _,${v[11]} in pairs(${v[9]})do local ${v[12]}=string.char(table.unpack({${Array.from({length:10},()=>Math.floor(Math.random()*90)+32).join(',')}}))end end)();local ${v[13]}=function(${v[14]})local ${v[15]}=${v[14]} or 0;for ${v[16]}=1,${n()}do ${v[15]}=${v[15]}+math.sin(${v[16]})*math.cos(${v[16]}/2)end;return ${v[15]}end;pcall(function()local ${v[17]}=0 while ${v[17]}<100 do local ${v[18]}=${v[5]}()if not ${v[18]} then break end;${v[17]}=${v[17]}+1;${v[13]}(${v[18]})end end);local ${v[19]}=(function()return game and game:GetService("RunService"):IsClient()end)()or false;`;
}

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.headers['cf-connecting-ip'] ||
           req.ip ||
           req.connection?.remoteAddress || 
           'unknown';
}

function getHWID(req) { return req.headers['x-hwid'] || null; }
function getPlayerID(req) { return req.headers['x-player-id'] || null; }

async function logAccess(req, action, success, details = {}) {
    const log = { 
        ip: getClientIP(req), 
        hwid: getHWID(req), 
        playerId: getPlayerID(req), 
        ua: req.headers['user-agent']?.substring(0, 80) || 'unknown', 
        action, 
        success, 
        path: req.path, 
        ts: new Date().toISOString(), 
        ...details 
    };
    await db.addLog(log);
}

function isValidExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const validExecutors = [
        'roblox', 'synapse', 'krnl', 'fluxus', 'delta', 'electron',
        'script-ware', 'scriptware', 'sentinel', 'oxygen', 'evon',
        'arceus', 'hydrogen', 'vegax', 'trigon', 'comet', 'solara',
        'wave', 'zorara', 'codex', 'celery', 'swift', 'sirhurt',
        'wininet', 'executor', 'exploit', 'coco', 'temple', 'valyse',
        'jjsploit', 'wearedevs', 'nihon'
    ];
    
    const hasValidUA = validExecutors.some(e => ua.includes(e));
    const hasRobloxHeaders = req.headers['x-roblox-id'] && req.headers['x-place-id'] && req.headers['x-job-id'];
    const hasExecutorToken = req.headers['x-executor-token'];
    const hasHWID = req.headers['x-hwid'];
    
    return hasValidUA || hasRobloxHeaders || hasExecutorToken || hasHWID;
}

function isBrowser(req) {
    const accept = req.headers['accept'] || '';
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    
    if (isValidExecutor(req)) return false;
    
    const hasBrowserHeaders = req.headers['accept-language'] && 
                              (req.headers['sec-fetch-dest'] || 
                               req.headers['sec-fetch-mode'] || 
                               req.headers['sec-ch-ua']);
    
    const hasBrowserUA = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera'].some(b => ua.includes(b));
    
    return (accept.includes('text/html') && hasBrowserUA) || hasBrowserHeaders;
}

function isBot(req) {
    if (isValidExecutor(req)) return false;
    
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    
    const botPatterns = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
        'node', 'axios', 'fetch', 'http', 'request', 'postman', 'insomnia',
        'discord', 'telegram', 'slack', 'whatsapp', 'facebook', 'twitter',
        'java', 'okhttp', 'apache', 'libwww', 'perl', 'ruby', 'php',
        'go-http', 'aiohttp', 'httpx', 'got/', 'undici'
    ];
    
    const hasBotUA = botPatterns.some(p => ua.includes(p));
    const hasEmptyUA = !ua || ua.length < 10;
    const hasBrowserUA = ['mozilla', 'chrome', 'safari', 'firefox', 'edge'].some(b => ua.includes(b));
    const hasRobloxUA = ['roblox', 'wininet', 'executor', 'exploit'].some(r => ua.includes(r));
    
    const hasSecurityHeaders = req.headers['sec-fetch-dest'] || req.headers['sec-fetch-mode'] || req.headers['sec-ch-ua'];
    const hasReferer = req.headers['referer'] || req.headers['origin'];
    const hasCookie = req.headers['cookie'];
    const acceptsHTML = accept.includes('text/html') && !hasRobloxUA;
    
    if (hasBotUA || hasEmptyUA) return true;
    if (hasSecurityHeaders || hasReferer && !hasRobloxUA) return true;
    if (hasCookie || acceptsHTML) return true;
    if (!hasRobloxUA && hasBrowserUA) return true;
    
    return false;
}

function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; }
}

function generateSessionKey(userId, hwid, timestamp, secret) {
    return crypto.createHmac('sha256', secret).update(`${userId}:${hwid}:${timestamp}`).digest('hex').substring(0, 32);
}

function isObfuscated(script) {
    if (!script) return false;
    return [/IronBrew/i, /Prometheus/i, /Moonsec/i, /Luraph/i, /PSU/i, /-- Obfuscated/i].some(r => r.test(script.substring(0, 500)));
}

async function getScript() {
    const cached = await db.getCachedScript();
    if (cached) return cached;
    if (!config.SCRIPT_SOURCE_URL) return null;
    try {
        const res = await axios.get(config.SCRIPT_SOURCE_URL, { 
            timeout: 8000, 
            headers: { 'User-Agent': 'Roblox/WinInet' } 
        });
        if (typeof res.data === 'string' && res.data.length > 10) {
            await db.setCachedScript(res.data, config.SCRIPT_CACHE_TTL);
            return res.data;
        }
    } catch (err) {
        console.error('Failed to fetch script:', err.message);
    }
    return null;
}

function getServerUrl(req) {
    const protocol = req.headers['x-forwarded-proto'] || 'https';
    const host = req.headers['host'];
    return `${protocol}://${host}`;
}

function wrapScript(script, serverUrl) {
    const o = config.OWNER_USER_IDS.join(',');
    const w = config.WHITELIST_USER_IDS.join(',');
    const b = `${serverUrl}/api/ban`;
    return `local _O={${o}} local _W={${w}} local _B="${b}" local _P=game:GetService("Players") local _L=_P.LocalPlayer local _S=game:GetService("StarterGui") local _C=game:GetService("CoreGui") local _PG=_L:WaitForChild("PlayerGui") local _H=game:GetService("HttpService") local _A=true local _SD=false local _CON={} local _THR={}
local _IT={g={},m={}}
local function _isW(u) for _,i in ipairs(_W) do if u==i then return true end end return false end
local function _isO(u) for _,i in ipairs(_O) do if u==i then return true end end return false end
local function _n(t,x,d) pcall(function() _S:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function _hw() local s,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end return "FB_"..tostring(_L.UserId) end) return s and r or "UNK" end
local function _hp(u,d) local r=(syn and syn.request) or request or http_request if not r then return end pcall(function() r({Url=u,Method="POST",Headers={["Content-Type"]="application/json"},Body=_H:JSONEncode(d)}) end) end
local function _ban(rs,t) _hp(_B,{hwid=_hw(),playerId=_L.UserId,playerName=_L.Name,reason=rs,toolsDetected=t or {}}) task.wait(0.5) _L:Kick("⛔ Banned\\n\\n"..rs) end
local function _cl() if _SD then return end _SD=true _A=false for i=#_THR,1,-1 do pcall(function() task.cancel(_THR[i]) end) end for i=#_CON,1,-1 do pcall(function() _CON[i]:Disconnect() end) end _G._SCRIPT_CLEANUP=nil end
_G._SCRIPT_CLEANUP=_cl
local _TP={"simplespy","httpspy","remotespy","hydroxide","dex","infiniteyield","infinite_yield","serverspy","scriptdumper","saveinstance","iy_","hookspy"}
local _TM={"SimpleSpy","HttpSpy","RemoteSpy","Hydroxide","Dex","DexExplorer","InfiniteYield","IY_LOADED","SimpleSpyExecuted"}
local function _snap()
    if _isW(_L.UserId) then return end
    local e=getgenv and getgenv() or _G
    for _,m in ipairs(_TM) do if rawget(e,m)~=nil then _IT.m[m]=true end end
    for _,l in ipairs({_C,_PG}) do pcall(function() for _,g in pairs(l:GetChildren()) do if g:IsA("ScreenGui") then _IT.g[g.Name:lower()]=true end end end) end
end
local function _isNew(n,im) if im then return not _IT.m[n] else return not _IT.g[n:lower()] end end
local function _det()
    if _isW(_L.UserId) then return false end
    local e=getgenv and getgenv() or _G
    for _,m in ipairs(_TM) do local v=rawget(e,m) if v~=nil and _isNew(m,true) then if type(v)=="boolean" or type(v)=="table" then return true,"MARKER",m end end end
    for _,l in ipairs({_C,_PG}) do local d,c,s pcall(function() for _,g in pairs(l:GetChildren()) do if g:IsA("ScreenGui") then local nm=g.Name:lower() if _isNew(nm,false) then for _,p in ipairs(_TP) do if nm:find(p,1,true) then d=true c="GUI" s=g.Name return end end end end end end) if d then return true,c,s end end
    return false
end
local function _mon()
    if _isW(_L.UserId) then return end
    local m=task.spawn(function() task.wait(8) while _A do task.wait(10) if not _A then break end local d,c,s=_det() if d then _A=false _n("🚨 Detected",s or c,3) task.wait(1) _cl() _ban("Tool: "..(s or c),{c,s}) break end end end)
    table.insert(_THR,m)
    local function og(d) if not _A or _isW(_L.UserId) then return end if d:IsA("ScreenGui") then task.defer(function() task.wait(0.5) if not _A then return end local nm=d.Name:lower() if _isNew(nm,false) then for _,p in ipairs(_TP) do if nm:find(p,1,true) then _A=false _n("🚨 Detected",d.Name,3) task.wait(1) _cl() _ban("Tool: "..d.Name,{"GUI",d.Name}) return end end end end) end end
    table.insert(_CON,_C.ChildAdded:Connect(og))
    table.insert(_CON,_PG.ChildAdded:Connect(og))
end
local function _co() for _,p in pairs(_P:GetPlayers()) do if _isO(p.UserId) and p~=_L then return true end end return false end
if _co() then _n("⚠️","Owner in server",3) return end
table.insert(_THR,task.spawn(function() while _A do task.wait(20) if not _A then break end if _co() then _cl() return end end end))
table.insert(_CON,_P.PlayerAdded:Connect(function(p) if not _A then return end task.wait(1) if _isO(p.UserId) then _cl() end end))
_snap() task.wait(1) _mon()
${script}`;
}

function getLoader(serverUrl) {
    return `local S="${serverUrl}" local H=game:GetService("HttpService") local P=game:GetService("Players") local G=game:GetService("StarterGui") local L=P.LocalPlayer local A=true
local function n(t,x,d) pcall(function() G:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function hw() local s,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end return "FB_"..tostring(L.UserId) end) return s and r or "UNK" end
local function ex() local s,r=pcall(function() if identifyexecutor then return (identifyexecutor()) end if getexecutorname then return getexecutorname() end return "Unknown" end) return s and r or "Unknown" end
local function hp(u,d,h) local r=(syn and syn.request) or request or http_request if not r then return nil end h=h or {} h["Content-Type"]="application/json" h["User-Agent"]="RobloxExecutor/5.4" local s,res=pcall(function() return r({Url=u,Method="POST",Headers=h,Body=H:JSONEncode(d)}) end) if not s then return nil end if res.StatusCode~=200 then local e pcall(function() e=H:JSONDecode(res.Body) end) return e end local ps,pd=pcall(function() return H:JSONDecode(res.Body) end) return ps and pd or nil end
local function xd(d,k) local r={} for i=1,#d do r[i]=string.char(bit32.bxor(d[i],string.byte(k,((i-1)%#k)+1))) end return table.concat(r) end
local T=nil
local function reg() local r=hp(S.."/api/executor/register",{robloxId=L.UserId,placeId=game.PlaceId,jobId=game.JobId,hwid=hw(),executor=ex()}) if r and r.success then T=r.token end end
local function op(o) if not o or #o==0 then return true end local function io(u) for _,i in ipairs(o) do if u==i then return true end end return false end local function co() for _,p in pairs(P:GetPlayers()) do if io(p.UserId) and p~=L then return true,p.Name end end return false end local op,on=co() if op then n("⚠️","Owner ("..on..") here",5) return false end task.spawn(function() while A and task.wait(15) do local pr,nm=co() if pr then A=false if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end n("⚠️","Owner detected",3) break end end end) P.PlayerAdded:Connect(function(p) task.wait(1) if A and io(p.UserId) then A=false if _G._SCRIPT_CLEANUP then pcall(_G._SCRIPT_CLEANUP) end n("⚠️","Owner joined",3) end end) return true end
local function m() reg() n("🔄","Connecting...",2) local h={} if T then h["x-executor-token"]=T end h["x-roblox-id"]=tostring(L.UserId) h["x-place-id"]=tostring(game.PlaceId) h["x-job-id"]=game.JobId local c=hp(S.."/api/auth/challenge",{userId=L.UserId,hwid=hw(),placeId=game.PlaceId},h) if not c then n("❌","Connection failed",5) return end if not c.success then n("❌",c.error or "Error",5) if c.error and c.error:find("Banned") then task.wait(2) L:Kick("⛔ Banned") end return end local sol=0 if c.puzzle and c.puzzle.numbers then for _,x in ipairs(c.puzzle.numbers) do sol=sol+x end end n("🔄","Verifying...",2) local v=hp(S.."/api/auth/verify",{challengeId=c.challengeId,solution=sol,timestamp=os.time()},h) if not v or not v.success then n("❌",v and v.error or "Failed",5) return end n("✅","Loading...",2) if not op(v.ownerIds) then return end local fs if v.mode=="raw" then fs=v.script else local p={} for i,ch in ipairs(v.chunks) do p[i]=xd(ch,v.key) end fs=table.concat(p) end local fn=loadstring(fs) if fn then pcall(fn) end end
pcall(m)`;
}

// ==================== ROUTES ====================

// Root endpoint
app.get('/', async (req, res) => {
    if (isBrowser(req)) return res.status(403).type('html').send(UNAUTHORIZED_HTML);
    if (isBot(req)) {
        await logAccess(req, 'BOT_ROOT', false);
        return res.type('text/plain').send(generateFakeScript());
    }
    return res.json({ status: "online", version: "5.4.6" });
});

// Health check
app.get('/health', async (req, res) => {
    const stats = await db.getStats();
    res.json({ status: "ok", uptime: stats.uptime, bans: stats.totalBans });
});

// Loader endpoints
app.get(['/loader', '/api/loader.lua'], async (req, res) => {
    if (isBrowser(req)) return res.status(403).type('html').send(UNAUTHORIZED_HTML);
    if (isBot(req)) {
        await logAccess(req, 'BOT_LOADER', false);
        return res.type('text/plain').send(generateFakeScript());
    }
    if (!isValidExecutor(req)) {
        await logAccess(req, 'INVALID_EXECUTOR', false);
        return res.type('text/plain').send(generateFakeScript());
    }
    await logAccess(req, 'LOADER', true);
    return res.type('text/plain').send(getLoader(getServerUrl(req)));
});

// Executor registration
app.post('/api/executor/register', async (req, res) => {
    const body = req.body || {};
    if (!body.robloxId || !body.placeId || !body.jobId) {
        return res.status(400).json({ success: false, error: "Missing fields" });
    }
    const token = crypto.randomBytes(32).toString('hex');
    await db.setToken(token, { ...body, ip: getClientIP(req), created: Date.now() }, 300);
    await logAccess(req, 'REGISTER', true, { robloxId: body.robloxId });
    return res.json({ success: true, token, expiresIn: 300 });
});

// Auth challenge
app.post('/api/auth/challenge', async (req, res) => {
    if (isBrowser(req)) return res.status(403).json({ success: false, error: "Forbidden" });
    if (isBot(req) && !req.headers['x-executor-token']) {
        await logAccess(req, 'BOT_CHALLENGE', false);
        return res.status(403).json({ success: false, error: "Invalid client" });
    }
    
    const body = req.body || {};
    if (!body.userId || !body.hwid || !body.placeId) {
        return res.status(400).json({ success: false, error: "Missing fields" });
    }
    
    const uid = parseInt(body.userId), pid = parseInt(body.placeId);
    if (isNaN(uid) || isNaN(pid)) {
        return res.status(400).json({ success: false, error: "Invalid format" });
    }
    
    const ban = await db.isBanned(body.hwid, getClientIP(req), uid);
    if (ban.blocked) {
        return res.status(403).json({ success: false, error: "Banned", reason: ban.reason, banId: ban.banId });
    }
    
    if (config.ALLOWED_PLACE_IDS.length > 0 && !config.ALLOWED_PLACE_IDS.includes(pid)) {
        return res.status(403).json({ success: false, error: "Game not allowed" });
    }
    
    const id = crypto.randomBytes(16).toString('hex');
    const nums = Array.from({length: 5}, () => Math.floor(Math.random() * 50) + 1);
    const challenge = { 
        id, userId: uid, hwid: body.hwid, placeId: pid, 
        ip: getClientIP(req), 
        puzzle: { numbers: nums, operation: 'sum' }, 
        answer: nums.reduce((a, b) => a + b, 0) 
    };
    
    await db.setChallenge(id, challenge, 60);
    await logAccess(req, 'CHALLENGE', true, { id, userId: uid });
    
    return res.json({ success: true, challengeId: id, puzzle: challenge.puzzle, expiresIn: 60 });
});

// Auth verify
app.post('/api/auth/verify', async (req, res) => {
    if (isBrowser(req)) return res.status(403).json({ success: false, error: "Forbidden" });
    if (isBot(req) && !req.headers['x-executor-token']) {
        await logAccess(req, 'BOT_VERIFY', false);
        return res.status(403).json({ success: false, error: "Invalid client" });
    }
    
    const body = req.body || {};
    if (!body.challengeId || body.solution === undefined || !body.timestamp) {
        return res.status(400).json({ success: false, error: "Missing fields" });
    }
    
    const challenge = await db.getChallenge(body.challengeId);
    if (!challenge) return res.status(403).json({ success: false, error: "Expired" });
    if (challenge.ip !== getClientIP(req)) return res.status(403).json({ success: false, error: "IP mismatch" });
    if (parseInt(body.solution) !== challenge.answer) return res.status(403).json({ success: false, error: "Wrong" });
    
    await db.deleteChallenge(body.challengeId);
    
    const script = await getScript();
    if (!script) return res.status(500).json({ success: false, error: "Script not configured" });
    
    const serverUrl = getServerUrl(req);
    const wrapped = wrapScript(script, serverUrl);
    const isObf = config.SCRIPT_ALREADY_OBFUSCATED || isObfuscated(script);
    
    if (isObf) {
        await logAccess(req, 'SCRIPT_RAW', true, { userId: challenge.userId });
        return res.json({ 
            success: true, mode: 'raw', script: wrapped, 
            ownerIds: config.OWNER_USER_IDS, 
            whitelistIds: config.WHITELIST_USER_IDS, 
            banEndpoint: `${serverUrl}/api/ban`,
            meta: { userId: challenge.userId, placeId: challenge.placeId, timestamp: Date.now() } 
        });
    }
    
    const key = generateSessionKey(challenge.userId, challenge.hwid, body.timestamp, config.SECRET_KEY);
    const chunks = [];
    for (let i = 0; i < wrapped.length; i += 2000) {
        const chunk = wrapped.substring(i, i + 2000);
        const enc = [];
        for (let j = 0; j < chunk.length; j++) enc.push(chunk.charCodeAt(j) ^ key.charCodeAt(j % key.length));
        chunks.push(enc);
    }
    
    await logAccess(req, 'SCRIPT_ENC', true, { userId: challenge.userId });
    return res.json({ 
        success: true, mode: 'encrypted', key, chunks, 
        checksum: crypto.createHash('md5').update(wrapped).digest('hex'), 
        ownerIds: config.OWNER_USER_IDS, 
        whitelistIds: config.WHITELIST_USER_IDS, 
        banEndpoint: `${serverUrl}/api/ban`,
        meta: { userId: challenge.userId, placeId: challenge.placeId, timestamp: Date.now() } 
    });
});

// Ban endpoint
app.post('/api/ban', async (req, res) => {
    const body = req.body || {};
    if (!body.hwid && !body.playerId) {
        return res.status(400).json({ error: "Missing id" });
    }
    
    const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
    const data = { 
        hwid: body.hwid, ip: getClientIP(req), 
        playerId: body.playerId, playerName: body.playerName, 
        reason: body.reason || 'Auto-ban', 
        toolsDetected: body.toolsDetected || [], 
        banId, ts: new Date().toISOString() 
    };
    
    if (body.hwid) await db.addBan(body.hwid, data);
    if (body.playerId) await db.addBan(String(body.playerId), data);
    
    await logAccess(req, 'BAN', true, { playerId: body.playerId, reason: body.reason, banId });
    return res.json({ success: true, banId });
});

// ==================== ADMIN ROUTES ====================

app.get('/api/admin/stats', async (req, res) => {
    const key = req.headers['x-admin-key'] || req.query.key;
    if (!key || !secureCompare(key, config.ADMIN_KEY)) {
        return res.status(403).json({ error: "Invalid key" });
    }
    const stats = await db.getStats();
    return res.json({ 
        success: true, stats, 
        config: { owners: config.OWNER_USER_IDS.length, whitelist: config.WHITELIST_USER_IDS.length } 
    });
});

app.get('/api/admin/logs', async (req, res) => {
    const key = req.headers['x-admin-key'] || req.query.key;
    if (!key || !secureCompare(key, config.ADMIN_KEY)) {
        return res.status(403).json({ error: "Invalid key" });
    }
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const logs = await db.getLogs(limit);
    return res.json({ success: true, logs });
});

app.get('/api/admin/bans', async (req, res) => {
    const key = req.headers['x-admin-key'] || req.query.key;
    if (!key || !secureCompare(key, config.ADMIN_KEY)) {
        return res.status(403).json({ error: "Invalid key" });
    }
    const bans = await db.getAllBans();
    return res.json({ success: true, count: bans.length, bans });
});

app.delete('/api/admin/bans/:banId', async (req, res) => {
    const key = req.headers['x-admin-key'];
    if (!key || !secureCompare(key, config.ADMIN_KEY)) {
        return res.status(403).json({ error: "Invalid key" });
    }
    const bans = await db.getAllBans();
    const found = bans.find(b => b.banId === req.params.banId);
    if (found) {
        await db.removeBan(found.key);
        return res.json({ success: true });
    }
    return res.status(404).json({ success: false, error: "Not found" });
});

app.post('/api/admin/bans/clear', async (req, res) => {
    const key = req.headers['x-admin-key'];
    if (!key || !secureCompare(key, config.ADMIN_KEY)) {
        return res.status(403).json({ error: "Invalid key" });
    }
    const count = await db.clearBans();
    return res.json({ success: true, cleared: count });
});

app.post('/api/admin/cache/clear', async (req, res) => {
    const key = req.headers['x-admin-key'];
    if (!key || !secureCompare(key, config.ADMIN_KEY)) {
        return res.status(403).json({ error: "Invalid key" });
    }
    await db.setCachedScript(null);
    return res.json({ success: true, message: "Cache cleared" });
});

// ==================== 404 & ERROR HANDLERS ====================

app.use(async (req, res) => {
    if (isBrowser(req)) return res.status(404).type('html').send(UNAUTHORIZED_HTML);
    if (isBot(req) || !isValidExecutor(req)) {
        await logAccess(req, 'BOT_404', false);
        return res.type('text/plain').send(generateFakeScript());
    }
    return res.status(404).json({ error: "Not found" });
});

app.use((err, req, res, next) => {
    console.error('Server Error:', err);
    return res.status(500).json({ error: "Server error" });
});

// ==================== START SERVER ====================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`⚠️  Using In-Memory Database`);
});

module.exports = app;
