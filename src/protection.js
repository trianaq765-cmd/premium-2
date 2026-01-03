// ============================================================
// 🛡️ PROTECTION MODULE v4.4.0 - OPTIMIZED PERFORMANCE
// Reduced lag, optimized monitoring, efficient tracking
// ============================================================

const crypto = require('crypto');

function randomVar(prefix = '_') {
    return prefix + crypto.randomBytes(4).toString('hex');
}

function generateProtectedScript(originalScript, options = {}) {
    const {
        banEndpoint = '',
        whitelistUserIds = [],
        ownerUserIds = []
    } = options;

    const v = {
        main: randomVar('_M'),
        tools: randomVar('_T'),
        detect: randomVar('_D'),
        kick: randomVar('_K'),
        decode: randomVar('_DC'),
        chunks: randomVar('_CH'),
        http: randomVar('_H'),
        hwid: randomVar('_HW'),
        run: randomVar('_R')
    };

    const scriptChunks = [];
    const chunkSize = 400;
    for (let i = 0; i < originalScript.length; i += chunkSize) {
        const chunk = originalScript.substring(i, i + chunkSize);
        scriptChunks.push(Buffer.from(chunk).toString('base64'));
    }

    const whitelistStr = whitelistUserIds.join(', ');
    const ownerStr = ownerUserIds.join(', ');

    // Optimized protection wrapper
    const protectionWrapper = `
-- ============================================================
-- OWNER PROTECTION v4.4.0 - PERFORMANCE OPTIMIZED
-- ============================================================

local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _CORE_GUI = game:GetService("CoreGui")
local _PLAYER_GUI = _LOCAL:WaitForChild("PlayerGui")
local _ACTIVE = true
local _TRACKED_GUIS = {}
local _CONNECTIONS = {}
local _SCRIPT_TAG = "LS_" .. tostring(math.random(100000, 999999))

-- Cached owner check
local _IS_OWNER_CACHED = {}
local function _IS_OWNER(uid)
    if _IS_OWNER_CACHED[uid] ~= nil then
        return _IS_OWNER_CACHED[uid]
    end
    
    for _, id in ipairs(_OWNER_IDS) do
        if uid == id then
            _IS_OWNER_CACHED[uid] = true
            return true
        end
    end
    
    _IS_OWNER_CACHED[uid] = false
    return false
end

-- Optimized GUI cleanup
local function _CLEANUP()
    if not _ACTIVE then return end
    _ACTIVE = false
    
    -- Disconnect connections first (stop events)
    for _, c in pairs(_CONNECTIONS) do
        pcall(function() if c.Connected then c:Disconnect() end end)
    end
    _CONNECTIONS = {}
    
    -- Destroy tracked GUIs
    local count = 0
    for _, gui in pairs(_TRACKED_GUIS) do
        pcall(function()
            if gui and gui.Parent then
                gui:Destroy()
                count = count + 1
            end
        end)
    end
    _TRACKED_GUIS = {}
    
    -- Find and destroy tagged GUIs (fallback)
    task.defer(function()
        pcall(function()
            for _, child in pairs(_CORE_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    child:Destroy()
                end
            end
        end)
        pcall(function()
            for _, child in pairs(_PLAYER_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    child:Destroy()
                end
            end
        end)
    end)
    
    -- Notification
    task.defer(function()
        pcall(function()
            _STAR_GUI:SetCore("SendNotification", {
                Title = "⚠️ Stopped",
                Text = "Owner detected",
                Duration = 3
            })
        end)
    end)
end

-- Lightweight GUI tracking (debounced)
local _last_track_time = 0
local function _TRACK_GUI(gui)
    local now = tick()
    if now - _last_track_time < 0.1 then return end -- Debounce 100ms
    _last_track_time = now
    
    task.defer(function()
        pcall(function()
            gui:SetAttribute(_SCRIPT_TAG, true)
            table.insert(_TRACKED_GUIS, gui)
        end)
    end)
end

-- Start tracking (optimized)
task.defer(function()
    local conn1 = _CORE_GUI.DescendantAdded:Connect(function(d)
        if d:IsA("ScreenGui") then
            _TRACK_GUI(d)
        end
    end)
    table.insert(_CONNECTIONS, conn1)
    
    local conn2 = _PLAYER_GUI.DescendantAdded:Connect(function(d)
        if d:IsA("ScreenGui") then
            _TRACK_GUI(d)
        end
    end)
    table.insert(_CONNECTIONS, conn2)
end)

-- Owner monitoring (reduced frequency)
task.spawn(function()
    while _ACTIVE do
        task.wait(15) -- Check every 15 seconds (reduced from 3)
        
        if not _ACTIVE then break end
        
        -- Quick check
        for _, p in pairs(_PLAYERS:GetPlayers()) do
            if p ~= _LOCAL and _IS_OWNER(p.UserId) then
                _CLEANUP()
                return
            end
        end
    end
end)

-- Player joined (instant response)
local pconn = _PLAYERS.PlayerAdded:Connect(function(p)
    if _IS_OWNER(p.UserId) then
        task.wait(1) -- Small delay for player to load
        _CLEANUP()
    end
end)
table.insert(_CONNECTIONS, pconn)

-- Global access
_G._OWNER_PROTECTION = {
    active = function() return _ACTIVE end,
    stop = _CLEANUP
}

-- ============================================================
-- USER SCRIPT BELOW
-- ============================================================
`;

    const protectedScript = `-- Protected v4.4.0 - Optimized
local ${v.main} = (function()
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local LocalPlayer = Players.LocalPlayer
    
    local BAN_ENDPOINT = "${banEndpoint}"
    local WHITELIST = {${whitelistStr}}
    local OWNER_IDS = {${ownerStr}}
    
    -- Cached checks
    local _is_whitelisted = nil
    local function isWhitelisted()
        if _is_whitelisted ~= nil then return _is_whitelisted end
        for _, uid in ipairs(WHITELIST) do
            if LocalPlayer.UserId == uid then
                _is_whitelisted = true
                return true
            end
        end
        _is_whitelisted = false
        return false
    end
    
    local _is_owner_cached = {}
    local function isOwner(userId)
        if _is_owner_cached[userId] ~= nil then
            return _is_owner_cached[userId]
        end
        for _, uid in ipairs(OWNER_IDS) do
            if userId == uid then
                _is_owner_cached[userId] = true
                return true
            end
        end
        _is_owner_cached[userId] = false
        return false
    end
    
    local function checkOwnerPresence()
        if isOwner(LocalPlayer.UserId) then
            return false
        end
        
        for _, player in pairs(Players:GetPlayers()) do
            if isOwner(player.UserId) and player ~= LocalPlayer then
                StarterGui:SetCore("SendNotification", {
                    Title = "⚠️ Cannot Load",
                    Text = "Owner is in server",
                    Duration = 3
                })
                return true
            end
        end
        
        return false
    end
    
    local function ${v.hwid}()
        local h = "UNKNOWN"
        pcall(function()
            h = gethwid and gethwid() or 
                get_hwid and get_hwid() or
                "U_" .. tostring(LocalPlayer.UserId)
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
        
        task.wait(0.5)
        LocalPlayer:Kick("⛔ BANNED\\n\\n" .. reason)
    end
    
    -- Optimized tool detection (reduced checks)
    local ${v.tools} = {
        "dex", "darkdex", "infiniteyield", "iy",
        "hydroxide", "simplespy", "remotespy",
        "btool", "f3x"
    }
    
    local function ${v.detect}()
        local found = {}
        
        -- Quick check _G (optimized)
        for key, value in pairs(_G) do
            if type(value) == "table" or type(value) == "boolean" then
                local keyLower = tostring(key):lower()
                for _, tool in ipairs(${v.tools}) do
                    if keyLower:find(tool) then
                        table.insert(found, tostring(key))
                        break
                    end
                end
            end
        end
        
        -- Check getgenv (if exists)
        if #found == 0 then
            pcall(function()
                if getgenv then
                    local genv = getgenv()
                    for key, value in pairs(genv) do
                        if type(value) == "table" or type(value) == "boolean" then
                            local keyLower = tostring(key):lower()
                            for _, tool in ipairs(${v.tools}) do
                                if keyLower:find(tool) then
                                    table.insert(found, tostring(key))
                                    break
                                end
                            end
                        end
                    end
                end
            end)
        end
        
        -- Check CoreGui (only if needed)
        if #found == 0 then
            pcall(function()
                for _, child in pairs(CoreGui:GetChildren()) do
                    if child:IsA("ScreenGui") then
                        local nameLower = child.Name:lower()
                        for _, tool in ipairs(${v.tools}) do
                            if nameLower:find(tool) then
                                table.insert(found, child.Name)
                                break
                            end
                        end
                    end
                end
            end)
        end
        
        return found
    end
    
    local ${v.chunks} = {${scriptChunks.map((c, i) => `[${i + 1}]="${c}"`).join(',')}}
    
    local function ${v.decode}()
        local parts = {}
        local b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        
        for i, chunk in ipairs(${v.chunks}) do
            pcall(function()
                chunk = chunk:gsub('[^'..b64..'=]', '')
                parts[i] = (chunk:gsub('.', function(x)
                    if x == '=' then return '' end
                    local r, f = '', (b64:find(x) - 1)
                    for j = 6, 1, -1 do 
                        r = r .. (f % 2^j - f % 2^(j-1) > 0 and '1' or '0') 
                    end
                    return r
                end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
                    if #x ~= 8 then return '' end
                    local c = 0
                    for j = 1, 8 do 
                        c = c + (x:sub(j,j) == '1' and 2^(8-j) or 0) 
                    end
                    return string.char(c)
                end))
            end)
        end
        
        return table.concat(parts)
    end
    
    local function ${v.run}()
        if checkOwnerPresence() then
            return false
        end
        
        if isWhitelisted() then
            -- Skip detection for whitelisted
        else
            local tools = ${v.detect}()
            if #tools > 0 then
                ${v.kick}("Tools: " .. tools[1], tools)
                return false
            end
            
            -- Background monitoring (reduced frequency)
            task.spawn(function()
                while task.wait(20) do -- Every 20 seconds (reduced from 5)
                    local t = ${v.detect}()
                    if #t > 0 then
                        ${v.kick}("Runtime: " .. t[1], t)
                        break
                    end
                end
            end)
        end
        
        local content = ${v.decode}()
        if not content or #content < 10 then
            return false
        end
        
        local finalScript = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}]] .. content
        
        local fn = loadstring(finalScript)
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
    randomVar
};
