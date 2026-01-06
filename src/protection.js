// ============================================================
// 🛡️ PROTECTION MODULE - v5.1.0
// ============================================================

const crypto = require('crypto');

function randomVar(prefix = '_') {
    return prefix + crypto.randomBytes(4).toString('hex');
}

function xorEncrypt(text, key) {
    const result = [];
    for (let i = 0; i < text.length; i++) {
        result.push(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
    }
    return result;
}

function generateSessionKey(userId, hwid, timestamp, secret) {
    const data = `${userId}-${hwid}-${timestamp}-${secret}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 32);
}

function generateProtectedScript(originalScript, options = {}) {
    const {
        banEndpoint = '',
        whitelistUserIds = [],
        ownerUserIds = [],
        allowedPlaceIds = [],
        sessionKey = null
    } = options;

    const v = {
        main: randomVar('_M'),
        tools: randomVar('_T'),
        detect: randomVar('_D'),
        kick: randomVar('_K'),
        decode: randomVar('_DC'),
        data: randomVar('_DT'),
        http: randomVar('_H'),
        hwid: randomVar('_HW'),
        run: randomVar('_R'),
        game: randomVar('_GM'),
        key: randomVar('_KY')
    };

    let scriptData;
    if (sessionKey) {
        const encrypted = xorEncrypt(originalScript, sessionKey);
        scriptData = `{${encrypted.join(',')}}`;
    } else {
        const chunks = [];
        const chunkSize = 400;
        for (let i = 0; i < originalScript.length; i += chunkSize) {
            const chunk = originalScript.substring(i, i + chunkSize);
            chunks.push(Buffer.from(chunk).toString('base64'));
        }
        scriptData = `{${chunks.map((c, i) => `[${i + 1}]="${c}"`).join(',')}}`;
    }

    const whitelistStr = whitelistUserIds.join(', ');
    const ownerStr = ownerUserIds.join(', ');
    const allowedGamesStr = allowedPlaceIds.join(', ');

    const protectionWrapper = `
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

local function _SHUTDOWN()
    if _SHUTTING_DOWN then return end
    _SHUTTING_DOWN = true
    _ACTIVE = false
    
    for i = #_THREADS, 1, -1 do
        pcall(function() task.cancel(_THREADS[i]) end)
        _THREADS[i] = nil
    end
    
    for i = #_CONNECTIONS, 1, -1 do
        pcall(function()
            if _CONNECTIONS[i] and _CONNECTIONS[i].Connected then
                _CONNECTIONS[i]:Disconnect()
            end
        end)
        _CONNECTIONS[i] = nil
    end
    
    task.wait()
    
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
    
    _G._OWNER_PROTECTION = nil
    _G._SCRIPT_CLEANUP = nil
    
    task.defer(function()
        pcall(function()
            _STAR_GUI:SetCore("SendNotification", {
                Title = "⚠️ Script Stopped",
                Text = "Owner detected",
                Duration = 3
            })
        end)
    end)
end

_G._SCRIPT_CLEANUP = _SHUTDOWN

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

local monitor = task.spawn(function()
    while _ACTIVE do
        task.wait(15)
        if not _ACTIVE then break end
        
        for _, p in pairs(_PLAYERS:GetPlayers()) do
            if p ~= _LOCAL and _IS_OWNER(p.UserId) then
                _SHUTDOWN()
                return
            end
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
`;

    const useEncryption = !!sessionKey;

    const protectedScript = `-- Protected v5.1
local ${v.main} = (function()
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local LocalPlayer = Players.LocalPlayer
    
    local BAN_ENDPOINT = "${banEndpoint}"
    local WHITELIST = {${whitelistStr}}
    local OWNER_IDS = {${ownerStr}}
    local ALLOWED_GAMES = {${allowedGamesStr}}
    local USE_ENCRYPTION = ${useEncryption}
    local SESSION_KEY = "${sessionKey || ''}"
    
    local ${v.data} = ${scriptData}
    
    local function ${v.game}()
        if #ALLOWED_GAMES == 0 then return true end
        for _, placeId in ipairs(ALLOWED_GAMES) do
            if game.PlaceId == placeId then return true end
        end
        return false
    end
    
    if not ${v.game}() then
        task.defer(function()
            pcall(function()
                StarterGui:SetCore("SendNotification", {
                    Title = "⛔ Wrong Game",
                    Text = "Script not allowed here",
                    Duration = 5
                })
            end)
        end)
        task.wait(1)
        LocalPlayer:Kick("⛔ WRONG GAME\\n\\nThis script only works in specific games.")
        return false
    end
    
    local function isWhitelisted()
        if #WHITELIST == 0 then return true end
        for _, uid in ipairs(WHITELIST) do
            if LocalPlayer.UserId == uid then return true end
        end
        return false
    end
    
    local function isOwner(uid)
        for _, id in ipairs(OWNER_IDS) do
            if uid == id then return true end
        end
        return false
    end
    
    local function checkOwnerPresence()
        if isOwner(LocalPlayer.UserId) then return false end
        for _, p in pairs(Players:GetPlayers()) do
            if isOwner(p.UserId) and p ~= LocalPlayer then
                return true
            end
        end
        return false
    end
    
    local function ${v.hwid}()
        local h = "U"
        pcall(function()
            h = gethwid and gethwid() or 
                get_hwid and get_hwid() or
                "U" .. tostring(LocalPlayer.UserId)
        end)
        return h
    end
    
    local function ${v.http}(url, data)
        task.defer(function()
            pcall(function()
                local req = syn and syn.request or request or http_request
                if req then
                    req({
                        Url = url,
                        Method = "POST",
                        Headers = {["Content-Type"] = "application/json"},
                        Body = HttpService:JSONEncode(data)
                    })
                end
            end)
        end)
    end
    
    local function ${v.kick}(reason, tools)
        ${v.http}(BAN_ENDPOINT, {
            hwid = ${v.hwid}(),
            playerId = LocalPlayer.UserId,
            playerName = LocalPlayer.Name,
            reason = reason,
            toolsDetected = tools or {}
        })
        
        task.defer(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⛔ BANNED",
                Text = reason,
                Duration = 2
            })
        end)
        
        task.wait(0.3)
        LocalPlayer:Kick("⛔ BANNED\\n\\n" .. reason)
    end
    
    local ${v.tools} = {
        "dex", "darkdex", "infiniteyield", "iy",
        "hydroxide", "simplespy", "remotespy",
        "btool", "f3x"
    }
    
    local function ${v.detect}()
        local found = {}
        
        for k, v in pairs(_G) do
            if type(v) == "table" or type(v) == "boolean" then
                local kl = tostring(k):lower()
                for _, t in ipairs(${v.tools}) do
                    if kl:find(t) then
                        table.insert(found, tostring(k))
                        break
                    end
                end
            end
        end
        
        if #found == 0 then
            pcall(function()
                if getgenv then
                    for k, v in pairs(getgenv()) do
                        if type(v) == "table" or type(v) == "boolean" then
                            local kl = tostring(k):lower()
                            for _, t in ipairs(${v.tools}) do
                                if kl:find(t) then
                                    table.insert(found, tostring(k))
                                    break
                                end
                            end
                        end
                    end
                end
            end)
        end
        
        return found
    end
    
    local function xorDecrypt(data, key)
        local result = {}
        for i = 1, #data do
            local byte = data[i]
            local keyByte = string.byte(key, ((i - 1) % #key) + 1)
            result[i] = string.char(bit32.bxor(byte, keyByte))
        end
        return table.concat(result)
    end
    
    local function base64Decode(data)
        local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        data = data:gsub('[^'..b..'=]', '')
        return (data:gsub('.', function(x)
            if x == '=' then return '' end
            local r, f = '', (b:find(x) - 1)
            for i = 6, 1, -1 do 
                r = r .. (f % 2^i - f % 2^(i-1) > 0 and '1' or '0') 
            end
            return r
        end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
            if #x ~= 8 then return '' end
            local c = 0
            for i = 1, 8 do 
                c = c + (x:sub(i,i) == '1' and 2^(8-i) or 0) 
            end
            return string.char(c)
        end))
    end
    
    local function ${v.decode}()
        if USE_ENCRYPTION and SESSION_KEY ~= "" then
            return xorDecrypt(${v.data}, SESSION_KEY)
        else
            local parts = {}
            for i, chunk in ipairs(${v.data}) do
                parts[i] = base64Decode(chunk)
            end
            return table.concat(parts)
        end
    end
    
    local function ${v.run}()
        if checkOwnerPresence() then return false end
        
        if not isWhitelisted() then
            local t = ${v.detect}()
            if #t > 0 then
                ${v.kick}("Tools: " .. t[1], t)
                return false
            end
            
            task.spawn(function()
                while task.wait(20) do
                    local x = ${v.detect}()
                    if #x > 0 then
                        ${v.kick}("Runtime: " .. x[1], x)
                        break
                    end
                end
            end)
        end
        
        local s = ${v.decode}()
        if not s or #s < 10 then return false end
        
        local protectionCode = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}]]
        local fullScript = protectionCode .. s
        
        local fn = loadstring(fullScript)
        if fn then
            return pcall(fn)
        end
        return false
    end
    
    return ${v.run}
end)()

if ${v.main} then ${v.main}() end
`;

    return protectedScript;
}

module.exports = {
    generateProtectedScript,
    randomVar,
    xorEncrypt,
    generateSessionKey
};
