const axios = require('axios');
const crypto = require('crypto');
const config = require('../config');
const db = require('../lib/redis');

const UNAUTHORIZED_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>403</title><style>*{margin:0;padding:0}body{background:#000;color:#fff;font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh}.c{text-align:center}.s{font-size:4rem;margin-bottom:1rem}h1{color:#ef4444}p{color:#666}</style></head><body><div class="c"><div class="s">🛡️</div><h1>403 Forbidden</h1><p>Access Denied</p></div></body></html>`;

function generateFakeScript() {
    const r = (l) => { let s = ''; const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'; for (let i = 0; i < l; i++) s += c[Math.floor(Math.random() * c.length)]; return s; };
    const n = () => Math.floor(Math.random() * 99999);
    const h = () => { let x = ''; for (let i = 0; i < Math.floor(Math.random() * 15) + 5; i++) x += '\\' + Math.floor(Math.random() * 255); return x; };
    const v = Array.from({length: 20}, () => r(Math.floor(Math.random() * 4) + 2));
    const f = Array.from({length: 80}, () => `"${h()}"`).join(',');
    const t = Array.from({length: 40}, () => `[${n()}]="${r(10)}"`).join(',');
    return `local ${v[0]}=(function()local ${v[1]}={${f}};local ${v[2]}={${t}};local ${v[3]}=0;for ${v[4]}=1,#${v[1]} do ${v[3]}=${v[3]}+((string.byte(${v[1]}[${v[4]}]:sub(1,1))or 0)%256)end;return ${v[3]} end)();local ${v[5]}=coroutine.wrap(function()for ${v[6]}=1,${n()} do local ${v[7]}=bit32.bxor(${v[6]},${n()})coroutine.yield(${v[7]})end end);pcall(function()local ${v[8]}=0 while ${v[8]}<100 do local ${v[9]}=${v[5]}()if not ${v[9]} then break end;${v[8]}=${v[8]}+1 end end);`;
}

function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || 'unknown'; }

async function logAccess(req, action, success, details = {}) {
    await db.addLog({ ip: getIP(req), hwid: req.headers['x-hwid'], playerId: req.headers['x-player-id'], ua: req.headers['user-agent']?.substring(0, 80) || 'unknown', action, success, path: req.url, ts: new Date().toISOString(), ...details });
}

function isValidExecutor(headers) {
    const ua = (headers['user-agent'] || '').toLowerCase();
    const valid = ['roblox','synapse','krnl','fluxus','delta','electron','script-ware','scriptware','sentinel','oxygen','evon','arceus','hydrogen','vegax','trigon','comet','solara','wave','zorara','codex','celery','swift','sirhurt','wininet','executor','exploit','coco','temple','valyse','jjsploit','wearedevs','nihon'];
    return valid.some(e => ua.includes(e)) || headers['x-roblox-id'] || headers['x-executor-token'] || headers['x-hwid'];
}

function isBrowser(headers) {
    if (isValidExecutor(headers)) return false;
    const accept = headers['accept'] || '';
    const ua = (headers['user-agent'] || '').toLowerCase();
    return (accept.includes('text/html') && ['mozilla','chrome','safari','firefox','edge'].some(b => ua.includes(b))) || headers['sec-fetch-dest'];
}

function isBot(headers) {
    if (isValidExecutor(headers)) return false;
    const ua = (headers['user-agent'] || '').toLowerCase();
    const bots = ['bot','crawler','spider','curl','wget','python','node','axios','fetch','postman','discord','telegram','crypta','java','okhttp','php','go-http'];
    if (bots.some(p => ua.includes(p))) return true;
    if (!ua || ua.length < 10) return true;
    if (headers['sec-fetch-dest'] || headers['referer'] || headers['cookie']) return true;
    if (['mozilla','chrome','safari','firefox'].some(b => ua.includes(b)) && !['roblox','wininet'].some(r => ua.includes(r))) return true;
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
    return [/IronBrew/i,/Prometheus/i,/Moonsec/i,/Luraph/i,/PSU/i,/-- Obfuscated/i].some(r => r.test(script.substring(0, 500)));
}

async function getScript() {
    const cached = await db.getCachedScript();
    if (cached) return cached;
    if (!config.SCRIPT_SOURCE_URL) return null;
    try {
        const res = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 8000, headers: { 'User-Agent': 'Roblox/WinInet' } });
        if (typeof res.data === 'string' && res.data.length > 10) {
            await db.setCachedScript(res.data);
            return res.data;
        }
    } catch {}
    return null;
}

function wrapScript(script, serverUrl) {
    const o = config.OWNER_USER_IDS.join(',');
    const w = config.WHITELIST_USER_IDS.join(',');
    const b = `${serverUrl}/api/ban`;
    return `local _O={${o}} local _W={${w}} local _B="${b}" local _P=game:GetService("Players") local _L=_P.LocalPlayer local _S=game:GetService("StarterGui") local _C=game:GetService("CoreGui") local _H=game:GetService("HttpService") local _TS=game:GetService("TeleportService") local _A=true local _SD=false local _CON={} local _THR={} local _RDY=false
local _IT={g={},m={}}
local _PG pcall(function() _PG=_L:FindFirstChild("PlayerGui") end)
local function _isW(u) if #_W==0 then return false end for _,i in ipairs(_W) do if u==i then return true end end return false end
local function _isO(u) if #_O==0 then return false end for _,i in ipairs(_O) do if u==i then return true end end return false end
local function _n(t,x,d) pcall(function() _S:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function _hw() local s,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end return "FB_"..tostring(_L.UserId) end) return s and r or "UNK" end
local function _hp(u,d) local r=(syn and syn.request) or request or http_request if not r then return end pcall(function() r({Url=u,Method="POST",Headers={["Content-Type"]="application/json"},Body=_H:JSONEncode(d)}) end) end
local function _fd(rs)
    _A=false
    pcall(function()
        local s=Instance.new("ScreenGui") s.Name="B"..math.random(100000,999999) s.DisplayOrder=2147483647 s.Parent=_C
        local f=Instance.new("Frame") f.Size=UDim2.new(1,0,1,0) f.BackgroundColor3=Color3.new(0,0,0) f.Parent=s
        local t=Instance.new("TextLabel") t.Size=UDim2.new(1,0,1,0) t.BackgroundTransparency=1 t.Text="BANNED" t.TextColor3=Color3.new(1,0,0) t.TextSize=48 t.Font=Enum.Font.GothamBold t.Parent=f
    end)
    task.delay(1,function() pcall(function() _L:Kick(rs) end) task.wait(0.5) pcall(function() _TS:Teleport(9999999999) end) end)
end
local function _ban(rs,t) if _SD then return end _SD=true _A=false _hp(_B,{hwid=_hw(),playerId=_L.UserId,playerName=_L.Name,reason=rs,toolsDetected=t or {}}) _n("⛔",rs,5) _fd(rs) end
local function _cl() if _SD then return end _SD=true _A=false for i=#_THR,1,-1 do pcall(task.cancel,_THR[i]) end for i=#_CON,1,-1 do pcall(function() _CON[i]:Disconnect() end) end end
_G._SCRIPT_CLEANUP=_cl
local _TP={"simplespy","httpspy","remotespy","hydroxide","infiniteyield","infinite_yield","iy_topbar","iy_main","serverspy","scriptdumper","saveinstance","dex_explorer","darkdex"}
local _TM={"SimpleSpy","HttpSpy","RemoteSpy","Hydroxide","Dex","DexExplorer","InfiniteYield","IY_LOADED","SimpleSpyExecuted"}
local function _rec()
    local e=getgenv and getgenv() or _G
    for _,m in ipairs(_TM) do if rawget(e,m)~=nil then _IT.m[m]=true end end
    pcall(function() local g=rawget(e,"_G") if g then for _,k in ipairs({"SimpleSpy","RemoteSpy","HttpSpy","Dex","InfiniteYield","IY_LOADED"}) do if rawget(g,k) then _IT.m["G_"..k]=true end end end end)
    for _,loc in ipairs({_C,_PG}) do if loc then pcall(function() for _,gui in pairs(loc:GetChildren()) do if gui:IsA("ScreenGui") then _IT.g[gui.Name:lower()]=true end end end) end end
    if gethui then pcall(function() for _,gui in pairs(gethui():GetChildren()) do _IT.g[gui.Name:lower()]=true end end) end
end
local function _snap() if _isW(_L.UserId) then _RDY=true return end _rec() task.wait(2) _rec() task.wait(2) _rec() _RDY=true end
local function _new(n,im) if im then return not _IT.m[n] else return not _IT.g[n:lower()] end end
local function _det()
    if not _RDY or not _A or _isW(_L.UserId) then return false end
    local e=getgenv and getgenv() or _G
    for _,m in ipairs(_TM) do if rawget(e,m)~=nil and _new(m,true) then return true,"ENV",m end end
    pcall(function() local g=rawget(e,"_G") if g then for _,k in ipairs({"SimpleSpy","RemoteSpy","HttpSpy","Dex","InfiniteYield","IY_LOADED"}) do if rawget(g,k) and _new("G_"..k,true) then return true,"_G",k end end end end)
    for _,loc in ipairs({_C,_PG}) do if loc then local f,s pcall(function() for _,gui in pairs(loc:GetChildren()) do if gui:IsA("ScreenGui") then local nm=gui.Name:lower() if _new(nm,false) then for _,p in ipairs(_TP) do if nm:find(p,1,true) then f=true s=gui.Name return end end end end end end) if f then return true,"GUI",s end end end
    if gethui then local f,s pcall(function() for _,gui in pairs(gethui():GetChildren()) do local nm=gui.Name:lower() if _new(nm,false) then for _,p in ipairs(_TP) do if nm:find(p,1,true) then f=true s=gui.Name return end end end end end) if f then return true,"HUI",s end end
    return false
end
local function _mon()
    if _isW(_L.UserId) then return end
    table.insert(_THR,task.spawn(function() while not _RDY do task.wait(1) end task.wait(10) while _A and not _SD do task.wait(20) if not _A then break end local d,c,s=_det() if d then _ban("Tool: "..(s or c),{c,s}) break end end end))
end
local function _watch()
    if _isW(_L.UserId) then return end
    local function chk(g) if not _A or _SD or not _RDY or not g:IsA("ScreenGui") then return end task.delay(3,function() if not _A or _SD then return end local nm=g.Name:lower() if _new(nm,false) then for _,p in ipairs(_TP) do if nm:find(p,1,true) then _ban("Tool: "..g.Name,{"GUI",g.Name}) return end end end end) end
    if _C then table.insert(_CON,_C.ChildAdded:Connect(chk)) end
    if _PG then table.insert(_CON,_PG.ChildAdded:Connect(chk)) end
end
local function _ownOk() if #_O==0 then return true end for _,p in pairs(_P:GetPlayers()) do if _isO(p.UserId) and p~=_L then return false end end return true end
local function _ownMon()
    if #_O==0 then return end
    table.insert(_THR,task.spawn(function() while _A do task.wait(30) if not _ownOk() then _cl() return end end end))
    table.insert(_CON,_P.PlayerAdded:Connect(function(p) task.wait(2) if _isO(p.UserId) then _cl() end end))
end
if not _ownOk() then _n("⚠️","Owner here",3) return end
task.spawn(function() _snap() _mon() _watch() _ownMon() end)
${script}`;
}

function getLoader(serverUrl) {
    return `local S="${serverUrl}" local H=game:GetService("HttpService") local P=game:GetService("Players") local G=game:GetService("StarterGui") local L=P.LocalPlayer local A=true
local function n(t,x,d) pcall(function() G:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function hw() local s,r=pcall(function() if gethwid then return gethwid() end if get_hwid then return get_hwid() end return "FB_"..tostring(L.UserId) end) return s and r or "UNK" end
local function ex() local s,r=pcall(function() if identifyexecutor then return (identifyexecutor()) end return "Unknown" end) return s and r or "Unknown" end
local function hp(u,d,h) local r=(syn and syn.request) or request or http_request if not r then return nil end h=h or {} h["Content-Type"]="application/json" h["User-Agent"]="RobloxExecutor/5.4" local s,res=pcall(function() return r({Url=u,Method="POST",Headers=h,Body=H:JSONEncode(d)}) end) if not s then return nil end if res.StatusCode~=200 then local e pcall(function() e=H:JSONDecode(res.Body) end) return e end local ps,pd=pcall(function() return H:JSONDecode(res.Body) end) return ps and pd or nil end
local function xd(d,k) local r={} for i=1,#d do r[i]=string.char(bit32.bxor(d[i],string.byte(k,((i-1)%#k)+1))) end return table.concat(r) end
local T
local function reg() local r=hp(S.."/api/executor/register",{robloxId=L.UserId,placeId=game.PlaceId,jobId=game.JobId,hwid=hw(),executor=ex()}) if r and r.success then T=r.token end end
local function op(o) if not o or #o==0 then return true end for _,p in pairs(P:GetPlayers()) do for _,i in ipairs(o) do if p.UserId==i and p~=L then n("⚠️","Owner here",5) return false end end end return true end
local function m() reg() n("🔄","Connecting...",2) local h={} if T then h["x-executor-token"]=T end h["x-roblox-id"]=tostring(L.UserId) h["x-place-id"]=tostring(game.PlaceId) h["x-job-id"]=game.JobId local c=hp(S.."/api/auth/challenge",{userId=L.UserId,hwid=hw(),placeId=game.PlaceId},h) if not c or not c.success then n("❌",c and c.error or "Failed",5) if c and c.error and c.error:find("Banned") then task.wait(2) L:Kick("Banned") end return end local sol=0 if c.puzzle and c.puzzle.numbers then for _,x in ipairs(c.puzzle.numbers) do sol=sol+x end end n("🔄","Verifying...",2) local v=hp(S.."/api/auth/verify",{challengeId=c.challengeId,solution=sol,timestamp=os.time()},h) if not v or not v.success then n("❌",v and v.error or "Failed",5) return end n("✅","Loading...",2) if not op(v.ownerIds) then return end local fs if v.mode=="raw" then fs=v.script else local p={} for i,ch in ipairs(v.chunks) do p[i]=xd(ch,v.key) end fs=table.concat(p) end local fn=loadstring(fs) if fn then pcall(fn) end end
pcall(m)`;
}

module.exports = async (req, res) => {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const path = url.pathname;
    const method = req.method;
    const serverUrl = `https://${req.headers.host}`;
    const headers = req.headers;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-admin-key,x-hwid,x-player-id,x-executor-token,x-roblox-id,x-place-id,x-job-id');

    if (method === 'OPTIONS') return res.status(200).end();

    try {
        if ((path === '/' || path === '') && method === 'GET') {
            if (isBrowser(headers)) return res.status(403).setHeader('Content-Type','text/html').send(UNAUTHORIZED_HTML);
            if (isBot(headers)) { await logAccess(req, 'BOT', false); return res.setHeader('Content-Type','text/plain').send(generateFakeScript()); }
            return res.json({ status: 'online', version: '5.4.7' });
        }

        if (path === '/health') return res.json({ status: 'ok' });

        if ((path === '/loader' || path === '/api/loader.lua') && method === 'GET') {
            if (isBrowser(headers)) return res.status(403).setHeader('Content-Type','text/html').send(UNAUTHORIZED_HTML);
            if (isBot(headers) || !isValidExecutor(headers)) {
                await logAccess(req, 'BOT_LOADER', false);
                return res.setHeader('Content-Type','text/plain').send(generateFakeScript());
            }
            await logAccess(req, 'LOADER', true);
            return res.setHeader('Content-Type','text/plain').send(getLoader(serverUrl));
        }

        if (path === '/api/executor/register' && method === 'POST') {
            const body = req.body || {};
            if (!body.robloxId || !body.placeId || !body.jobId) return res.status(400).json({ success: false, error: 'Missing' });
            const token = crypto.randomBytes(32).toString('hex');
            await db.setToken(token, { ...body, ip: getIP(req), created: Date.now() }, 600);
            return res.json({ success: true, token, expiresIn: 600 });
        }

        if (path === '/api/auth/challenge' && method === 'POST') {
            if (isBrowser(headers)) return res.status(403).json({ success: false, error: 'Forbidden' });
            if (isBot(headers) && !headers['x-executor-token']) return res.status(403).json({ success: false, error: 'Invalid' });
            const body = req.body || {};
            if (!body.userId || !body.hwid || !body.placeId) return res.status(400).json({ success: false, error: 'Missing' });
            const uid = parseInt(body.userId), pid = parseInt(body.placeId);
            const ban = await db.isBanned(body.hwid, getIP(req), uid);
            if (ban.blocked) return res.status(403).json({ success: false, error: 'Banned', reason: ban.reason, banId: ban.banId });
            if (config.ALLOWED_PLACE_IDS.length > 0 && !config.ALLOWED_PLACE_IDS.includes(pid)) return res.status(403).json({ success: false, error: 'Game not allowed' });
            const id = crypto.randomBytes(16).toString('hex');
            const nums = Array.from({length:5}, () => Math.floor(Math.random()*50)+1);
            const challenge = { id, userId: uid, hwid: body.hwid, placeId: pid, ip: getIP(req), puzzle: { numbers: nums }, answer: nums.reduce((a,b)=>a+b,0) };
            await db.setChallenge(id, challenge, 180);
            await logAccess(req, 'CHALLENGE', true, { userId: uid });
            return res.json({ success: true, challengeId: id, puzzle: challenge.puzzle, expiresIn: 180 });
        }

        if (path === '/api/auth/verify' && method === 'POST') {
            if (isBrowser(headers)) return res.status(403).json({ success: false, error: 'Forbidden' });
            if (isBot(headers) && !headers['x-executor-token']) return res.status(403).json({ success: false, error: 'Invalid' });
            const body = req.body || {};
            if (!body.challengeId || body.solution === undefined || !body.timestamp) return res.status(400).json({ success: false, error: 'Missing' });
            const challenge = await db.getChallenge(body.challengeId);
            if (!challenge) return res.status(403).json({ success: false, error: 'Expired' });
            if (parseInt(body.solution) !== challenge.answer) return res.status(403).json({ success: false, error: 'Wrong' });
            await db.deleteChallenge(body.challengeId);
            const script = await getScript();
            if (!script) return res.status(500).json({ success: false, error: 'Not configured' });
            const wrapped = wrapScript(script, serverUrl);
            const isObf = config.SCRIPT_ALREADY_OBFUSCATED || isObfuscated(script);
            if (isObf) {
                await logAccess(req, 'SCRIPT', true, { userId: challenge.userId });
                return res.json({ success: true, mode: 'raw', script: wrapped, ownerIds: config.OWNER_USER_IDS, whitelistIds: config.WHITELIST_USER_IDS, banEndpoint: `${serverUrl}/api/ban`, meta: { userId: challenge.userId, placeId: challenge.placeId } });
            }
            const key = generateSessionKey(challenge.userId, challenge.hwid, body.timestamp, config.SECRET_KEY);
            const chunks = [];
            for (let i = 0; i < wrapped.length; i += 2000) {
                const chunk = wrapped.substring(i, i + 2000);
                const enc = [];
                for (let j = 0; j < chunk.length; j++) enc.push(chunk.charCodeAt(j) ^ key.charCodeAt(j % key.length));
                chunks.push(enc);
            }
            await logAccess(req, 'SCRIPT', true, { userId: challenge.userId });
            return res.json({ success: true, mode: 'encrypted', key, chunks, ownerIds: config.OWNER_USER_IDS, whitelistIds: config.WHITELIST_USER_IDS, banEndpoint: `${serverUrl}/api/ban` });
        }

        if (path === '/api/ban' && method === 'POST') {
            const body = req.body || {};
            if (!body.hwid && !body.playerId) return res.status(400).json({ error: 'Missing' });
            const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
            const data = { hwid: body.hwid, ip: getIP(req), playerId: body.playerId, playerName: body.playerName, reason: body.reason || 'Auto', toolsDetected: body.toolsDetected || [], banId, ts: new Date().toISOString() };
            if (body.hwid) await db.addBan(body.hwid, data);
            if (body.playerId) await db.addBan(String(body.playerId), data);
            await logAccess(req, 'BAN', true, { playerId: body.playerId, banId });
            return res.json({ success: true, banId });
        }

        if (path === '/api/admin/stats' && method === 'GET') {
            const key = headers['x-admin-key'] || url.searchParams.get('key');
            if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Invalid key' });
            return res.json({ success: true, stats: await db.getStats(), platform: 'vercel' });
        }

        if (path === '/api/admin/logs' && method === 'GET') {
            const key = headers['x-admin-key'] || url.searchParams.get('key');
            if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Invalid key' });
            return res.json({ success: true, logs: await db.getLogs(Math.min(parseInt(url.searchParams.get('limit')) || 50, 500)) });
        }

        if (path === '/api/admin/bans' && method === 'GET') {
            const key = headers['x-admin-key'] || url.searchParams.get('key');
            if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Invalid key' });
            const bans = await db.getAllBans();
            return res.json({ success: true, count: bans.length, bans });
        }

        if (path === '/api/admin/bans/clear' && method === 'POST') {
            const key = headers['x-admin-key'];
            if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Invalid key' });
            return res.json({ success: true, cleared: await db.clearBans() });
        }

        if (path === '/api/admin/cache/clear' && method === 'POST') {
            const key = headers['x-admin-key'];
            if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Invalid key' });
            await db.setCachedScript(null);
            return res.json({ success: true });
        }

        if (isBrowser(headers)) return res.status(404).setHeader('Content-Type','text/html').send(UNAUTHORIZED_HTML);
        if (isBot(headers)) return res.setHeader('Content-Type','text/plain').send(generateFakeScript());
        return res.status(404).json({ error: 'Not found' });

    } catch (e) {
        return res.status(500).json({ error: 'Server error' });
    }
};