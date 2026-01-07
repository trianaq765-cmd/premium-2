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
    return `local ${v[0]}=(function()local ${v[1]}={${f}};local ${v[2]}={${t}};local ${v[3]}=0;for ${v[4]}=1,#${v[1]} do ${v[3]}=${v[3]}+((string.byte(${v[1]}[${v[4]}]:sub(1,1))or 0)%256)end;return ${v[3]} end)();local ${v[5]}=coroutine.wrap(function()for ${v[6]}=1,${n()} do local ${v[7]}=bit32.bxor(${v[6]},${n()})coroutine.yield(${v[7]})end end);local ${v[8]}=setmetatable({${t}},{__index=function(t,k)return rawget(t,k)or"${r(16)}"end,__newindex=function()end});(function()local ${v[9]}={}for ${v[10]}=1,math.random(50,150)do ${v[9]}[${v[10]}]=string.rep("${r(4)}",math.random(5,20)):reverse()end end)();pcall(function()local ${v[11]}=0 while ${v[11]}<100 do local ${v[12]}=${v[5]}()if not ${v[12]} then break end;${v[11]}=${v[11]}+1 end end);`;
}

function isValidExecutor(headers) {
    const ua = (headers['user-agent'] || '').toLowerCase();
    const validExecutors = ['roblox','synapse','krnl','fluxus','delta','electron','script-ware','scriptware','sentinel','oxygen','evon','arceus','hydrogen','vegax','trigon','comet','solara','wave','zorara','codex','celery','swift','sirhurt','wininet','executor','exploit','coco','temple','valyse','jjsploit','wearedevs','nihon'];
    const hasValidUA = validExecutors.some(e => ua.includes(e));
    const hasRobloxHeaders = headers['x-roblox-id'] && headers['x-place-id'] && headers['x-job-id'];
    const hasExecutorToken = headers['x-executor-token'];
    const hasHWID = headers['x-hwid'];
    return hasValidUA || hasRobloxHeaders || hasExecutorToken || hasHWID;
}

function isBrowser(headers) {
    const accept = headers['accept'] || '';
    const ua = (headers['user-agent'] || '').toLowerCase();
    if (isValidExecutor(headers)) return false;
    const hasBrowserHeaders = headers['accept-language'] && (headers['sec-fetch-dest'] || headers['sec-fetch-mode'] || headers['sec-ch-ua']);
    const hasBrowserUA = ['mozilla','chrome','safari','firefox','edge','opera'].some(b => ua.includes(b));
    return (accept.includes('text/html') && hasBrowserUA) || hasBrowserHeaders;
}

function isBot(headers) {
    if (isValidExecutor(headers)) return false;
    const ua = (headers['user-agent'] || '').toLowerCase();
    const accept = headers['accept'] || '';
    const botPatterns = ['bot','crawler','spider','scraper','curl','wget','python','node','axios','fetch','http','request','postman','insomnia','discord','telegram','slack','whatsapp','facebook','twitter','crypta','mee6','dyno','carl','dank','java','okhttp','apache','libwww','perl','ruby','php','go-http','aiohttp','httpx','got/','undici','needle','superagent','guzzle'];
    if (botPatterns.some(p => ua.includes(p))) return true;
    if (!ua || ua.length < 10) return true;
    if (headers['sec-fetch-dest'] || headers['sec-fetch-mode'] || headers['sec-ch-ua']) return true;
    if (headers['referer'] || headers['origin']) return true;
    if (headers['cookie']) return true;
    if (accept.includes('text/html') && !ua.includes('roblox')) return true;
    const hasBrowserUA = ['mozilla','chrome','safari','firefox','edge'].some(b => ua.includes(b));
    const hasRobloxUA = ['roblox','wininet','executor','exploit'].some(r => ua.includes(r));
    if (hasBrowserUA && !hasRobloxUA) return true;
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
local function _snap() if _isW(_L.UserId) then return end local e=getgenv and getgenv() or _G for _,m in ipairs(_TM) do if rawget(e,m)~=nil then _IT.m[m]=true end end for _,l in ipairs({_C,_PG}) do pcall(function() for _,g in pairs(l:GetChildren()) do if g:IsA("ScreenGui") then _IT.g[g.Name:lower()]=true end end end) end end
local function _isNew(n,im) if im then return not _IT.m[n] else return not _IT.g[n:lower()] end end
local function _det() if _isW(_L.UserId) then return false end local e=getgenv and getgenv() or _G for _,m in ipairs(_TM) do local v=rawget(e,m) if v~=nil and _isNew(m,true) then if type(v)=="boolean" or type(v)=="table" then return true,"MARKER",m end end end for _,l in ipairs({_C,_PG}) do local d,c,s pcall(function() for _,g in pairs(l:GetChildren()) do if g:IsA("ScreenGui") then local nm=g.Name:lower() if _isNew(nm,false) then for _,p in ipairs(_TP) do if nm:find(p,1,true) then d=true c="GUI" s=g.Name return end end end end end end) if d then return true,c,s end end return false end
local function _mon() if _isW(_L.UserId) then return end local m=task.spawn(function() task.wait(8) while _A do task.wait(10) if not _A then break end local d,c,s=_det() if d then _A=false _n("🚨 Detected",s or c,3) task.wait(1) _cl() _ban("Tool: "..(s or c),{c,s}) break end end end) table.insert(_THR,m) local function og(d) if not _A or _isW(_L.UserId) then return end if d:IsA("ScreenGui") then task.defer(function() task.wait(0.5) if not _A then return end local nm=d.Name:lower() if _isNew(nm,false) then for _,p in ipairs(_TP) do if nm:find(p,1,true) then _A=false _n("🚨 Detected",d.Name,3) task.wait(1) _cl() _ban("Tool: "..d.Name,{"GUI",d.Name}) return end end end end) end end table.insert(_CON,_C.ChildAdded:Connect(og)) table.insert(_CON,_PG.ChildAdded:Connect(og)) end
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

module.exports = {
    UNAUTHORIZED_HTML,
    generateFakeScript,
    isValidExecutor,
    isBrowser,
    isBot,
    secureCompare,
    generateSessionKey,
    isObfuscated,
    getScript,
    wrapScript,
    getLoader,
    db,
    config
};
