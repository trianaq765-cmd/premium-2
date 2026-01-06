// ============================================================
// 🛡️ PROTECTION MODULE v4.5.1 - GAME-SPECIFIC LOCK
// Only works in whitelisted games
// ============================================================

const crypto = require('crypto');

function randomVar(prefix = '_') {
    return prefix + crypto.randomBytes(4).toString('hex');
}

function generateProtectedScript(originalScript, options = {}) {
    const {
        banEndpoint = '',
        whitelistUserIds = [],
        ownerUserIds = [],
        allowedPlaceIds = [] // NEW: Whitelist games
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
        run: randomVar('_R'),
        game: randomVar('_GM')
    };

    const scriptChunks = [];
    const chunkSize = 400;
    for (let i = 0; i < originalScript.length; i += chunkSize) {
        const chunk = originalScript.substring(i, i + chunkSize);
        scriptChunks.push(Buffer.from(chunk).toString('base64'));
    }

    const whitelistStr = whitelistUserIds.join(', ');
    const ownerStr = ownerUserIds.join(', ');
    const allowedGamesStr = allowedPlaceIds.join(', ');

    const protectionWrapper = `
-- ============================================================
-- OWNER PROTECTION v4.5.1 - GAME LOCK
-- ============================================================

local _OWNER_IDS = {${ownerStr}}
local _ALLOWED_GAMES = {${allowedGamesStr}}
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

-- Owner check (cached)
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

-- CLEAN SHUTDOWN
local function _SHUTDOWN()
    if _SHUTTING_DOWN then return end
    _SHUTTING_DOWN = true
    _ACTIVE = false
    
    print("[PROTECTION] Clean shutdown initiated...")
    
    for i = #_THREADS, 1, -1 do
        pcall(function() task.cancel(_THREADS[i]) end)
        _THREADS[i] = nil
    end
    _THREADS = {}
    
    for i = #_CONNECTIONS, 1, -1 do
        pcall(function()
            if _CONNECTIONS[i] and _CONNECTIONS[i].Connected then
                _CONNECTIONS[i]:Disconnect()
            end
        end)
        _CONNECTIONS[i] = nil
    end
    _CONNECTIONS = {}
    
    task.wait()
    
    local destroyed = 0
    for i = #_TRACKED_GUIS, 1, -1 do
        pcall(function()
            local gui = _TRACKED_GUIS[i]
            if gui and gui.Parent then
                if gui:IsA("ScreenGui") then gui.Enabled = false end
                gui:Destroy()
                destroyed = destroyed + 1
            end
        end)
        _TRACKED_GUIS[i] = nil
    end
    _TRACKED_GUIS = {}
    
    task.spawn(function()
        task.wait(0.1)
        pcall(function()
            for _, child in pairs(_CORE_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    if child:IsA("ScreenGui") then child.Enabled = false end
                    child:Destroy()
                end
            end
        end)
        pcall(function()
            for _, child in pairs(_PLAYER_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    if child:IsA("ScreenGui") then child.Enabled = false end
                    child:Destroy()
                end
            end
        end)
    end)
    
    _G._OWNER_PROTECTION = nil
    _G.LOADER_SCRIPT = nil
    
    task.spawn(function()
        task.wait(0.5)
        for i = 1, 3 do
            pcall(function() collectgarbage("collect") end)
            task.wait(0.1)
        end
    end)
    
    task.defer(function()
        pcall(function()
            _STAR_GUI:SetCore("SendNotification", {
                Title = "⚠️ Script Stopped",
                Text = "Owner detected",
                Duration = 3
            })
        end)
    end)
    
    print("[PROTECTION] Shutdown complete - Destroyed", destroyed, "GUIs")
end

-- Lightweight tracking
local _last_track = 0
local function _TRACK(gui)
    local now = tick()
    if now - _last_track < 0.05 then return end
    _last_track = now
    
    task.defer(function()
        if not _ACTIVE then return end
        pcall(function()
            gui:SetAttribute(_SCRIPT_TAG, true)
            table.insert(_TRACKED_GUIS, gui)
        end)
    end)
end

-- Start tracking
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

-- Owner monitoring
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

-- ============================================================
-- USER SCRIPT BELOW
-- ============================================================
`;

    const protectedScript = `-- Protected v4.5.1 - Game Lock
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
    
    -- ============================================================
    -- 🎮 GAME VERIFICATION - PRIORITY CHECK
    -- ============================================================
    
    local function ${v.game}()
        local currentPlaceId = game.PlaceId
        
        -- If no games whitelisted, allow all
        if #ALLOWED_GAMES == 0 then
            return true, "No game restriction"
        end
        
        -- Check if current game is allowed
        for _, placeId in ipairs(ALLOWED_GAMES) do
            if currentPlaceId == placeId then
                print("[GAME] ✅ Game verified:", currentPlaceId)
                return true, "Game allowed"
            end
        end
        
        -- Game not allowed
        print("[GAME] ❌ Unauthorized game:", currentPlaceId)
        return false, currentPlaceId
    end
    
    -- Check game FIRST (before anything else)
    local gameAllowed, gameInfo = ${v.game}()
    
    if not gameAllowed then
        -- Show notification
        task.defer(function()
            pcall(function()
                StarterGui:SetCore("SendNotification", {
                    Title = "⛔ Wrong Game",
                    Text = "This script doesn't work here",
                    Duration = 5
                })
            end)
        end)
        
        -- Wait then kick
        task.wait(1)
        
        LocalPlayer:Kick(
            "⛔ WRONG GAME\\n\\n" ..
            "This script only works in specific games.\\n\\n" ..
            "Current Game ID: " .. tostring(gameInfo) .. "\\n" ..
            "You cannot use this script here."
        )
        
        return false
    end
    
    -- ============================================================
    -- 🔒 CONTINUE WITH NORMAL PROTECTION
    -- ============================================================
    
    local _wl_cache = nil
    local function isWhitelisted()
        if _wl_cache ~= nil then return _wl_cache end
        for _, uid in ipairs(WHITELIST) do
            if LocalPlayer.UserId == uid then
                _wl_cache = true
                return true
            end
        end
        _wl_cache = false
        return false
    end
    
    local _owner_cache = {}
    local function isOwner(uid)
        if _owner_cache[uid] ~= nil then return _owner_cache[uid] end
        for _, id in ipairs(OWNER_IDS) do
            if uid == id then
                _owner_cache[uid] = true
                return true
            end
        end
        _owner_cache[uid] = false
        return false
    end
    
    local function checkOwnerPresence()
        if isOwner(LocalPlayer.UserId) then return false end
        
        for _, p in pairs(Players:GetPlayers()) do
            if isOwner(p.UserId) and p ~= LocalPlayer then
                task.defer(function()
                    StarterGui:SetCore("SendNotification", {
                        Title = "⚠️ Cannot Load",
                        Text = "Owner in server",
                        Duration = 3
                    })
                end)
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
        
        if #found == 0 then
            pcall(function()
                for _, c in pairs(CoreGui:GetChildren()) do
                    if c:IsA("ScreenGui") then
                        local nl = c.Name:lower()
                        for _, t in ipairs(${v.tools}) do
                            if nl:find(t) then
                                table.insert(found, c.Name)
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
        local p = {}
        local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        
        for i, c in ipairs(${v.chunks}) do
            pcall(function()
                c = c:gsub('[^'..b..'=]', '')
                p[i] = (c:gsub('.', function(x)
                    if x == '=' then return '' end
                    local r, f = '', (b:find(x) - 1)
                    for j = 6, 1, -1 do 
                        r = r .. (f % 2^j - f % 2^(j-1) > 0 and '1' or '0') 
                    end
                    return r
                end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
                    if #x ~= 8 then return '' end
                    local n = 0
                    for j = 1, 8 do 
                        n = n + (x:sub(j,j) == '1' and 2^(8-j) or 0) 
                    end
                    return string.char(n)
                end))
            end)
        end
        
        return table.concat(p)
    end
    
    local function ${v.run}()
        -- Game already verified above (kicked if wrong game)
        
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
        
        local fs = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}]] .. s
        
        local fn = loadstring(fs)
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
