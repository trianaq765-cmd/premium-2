// ============================================================
// 🛡️ PROTECTION MODULE v4.3.5 - COMPLETE FIX
// Fix: Clickable screen + Proper tool kick
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

    const protectionWrapper = `
-- ============================================================
-- OWNER PROTECTION v4.3.5 - FIXED
-- ============================================================

local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _CORE_GUI = game:GetService("CoreGui")
local _PLAYER_GUI = _LOCAL:WaitForChild("PlayerGui")
local _ACTIVE = true
local _CONNECTIONS = {}

local function _IS_OWNER(uid)
    for _, id in ipairs(_OWNER_IDS) do
        if uid == id then return true end
    end
    return false
end

local function _DESTROY_ALL_GUIS()
    print("[PROTECTION] Destroying all GUIs...")
    
    local destroyed = 0
    
    -- Destroy ALL children in CoreGui (aggressive)
    pcall(function()
        for _, child in pairs(_CORE_GUI:GetChildren()) do
            pcall(function() 
                child:Destroy() 
                destroyed = destroyed + 1
            end)
        end
    end)
    
    -- Destroy ALL ScreenGuis in PlayerGui
    pcall(function()
        for _, child in pairs(_PLAYER_GUI:GetChildren()) do
            if child:IsA("ScreenGui") or child:IsA("Frame") then
                pcall(function() 
                    child:Destroy() 
                    destroyed = destroyed + 1
                end)
            end
        end
    end)
    
    print("[PROTECTION] Destroyed", destroyed, "GUIs")
end

local function _STOP_SCRIPT(msg)
    if not _ACTIVE then return end
    _ACTIVE = false
    
    print("[PROTECTION] 🛑 STOPPING:", msg)
    
    -- Disconnect all connections
    for _, c in pairs(_CONNECTIONS) do
        pcall(function() 
            if c and c.Connected then 
                c:Disconnect() 
            end 
        end)
    end
    _CONNECTIONS = {}
    
    -- Destroy all GUIs
    _DESTROY_ALL_GUIS()
    
    -- Wait a bit then clean again (in case of delayed GUI creation)
    task.wait(0.5)
    _DESTROY_ALL_GUIS()
    
    -- Notification
    pcall(function()
        _STAR_GUI:SetCore("SendNotification", {
            Title = "⚠️ Script Stopped",
            Text = msg,
            Duration = 5
        })
    end)
    
    print("[PROTECTION] ✅ Script stopped successfully")
end

-- Background owner monitor (check every 3 seconds)
task.spawn(function()
    while _ACTIVE do
        task.wait(3)
        
        if not _ACTIVE then break end
        
        for _, p in pairs(_PLAYERS:GetPlayers()) do
            if _IS_OWNER(p.UserId) and p ~= _LOCAL then
                _STOP_SCRIPT("Owner (" .. p.Name .. ") is in the server")
                return
            end
        end
    end
end)

-- Monitor for owner joining
local conn = _PLAYERS.PlayerAdded:Connect(function(p)
    task.wait(0.5)
    if _IS_OWNER(p.UserId) then
        _STOP_SCRIPT("Owner (" .. p.Name .. ") joined the server")
    end
end)
table.insert(_CONNECTIONS, conn)

print("[PROTECTION] 🛡️ Active - Monitoring for owner")

-- Global access
_G._OWNER_PROTECTION = {
    active = function() return _ACTIVE end,
    stop = _STOP_SCRIPT
}

-- ============================================================
-- USER SCRIPT BELOW
-- ============================================================
`;

    const protectedScript = `-- Protected v4.3.5
local ${v.main} = (function()
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local LocalPlayer = Players.LocalPlayer
    
    local BAN_ENDPOINT = "${banEndpoint}"
    local WHITELIST = {${whitelistStr}}
    local OWNER_IDS = {${ownerStr}}
    
    local function isWhitelisted()
        for _, uid in ipairs(WHITELIST) do
            if LocalPlayer.UserId == uid then return true end
        end
        return false
    end
    
    local function isOwner(userId)
        for _, uid in ipairs(OWNER_IDS) do
            if userId == uid then return true end
        end
        return false
    end
    
    local function checkOwnerPresence()
        if isOwner(LocalPlayer.UserId) then
            print("[SCRIPT] You are the owner")
            return false
        end
        
        for _, player in pairs(Players:GetPlayers()) do
            if isOwner(player.UserId) and player ~= LocalPlayer then
                print("[SCRIPT] ⛔ Owner in server:", player.Name)
                StarterGui:SetCore("SendNotification", {
                    Title = "⚠️ Cannot Load",
                    Text = "Owner is in this server",
                    Duration = 5
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
                "USER_" .. tostring(LocalPlayer.UserId)
        end)
        return h
    end
    
    local function ${v.http}(url, data)
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
    end
    
    local function ${v.kick}(reason, tools)
        print("[SCRIPT] 🔨 KICKING:", reason)
        
        -- Send ban to server
        pcall(function()
            if BAN_ENDPOINT and BAN_ENDPOINT ~= "" then
                ${v.http}(BAN_ENDPOINT, {
                    hwid = ${v.hwid}(),
                    playerId = LocalPlayer.UserId,
                    playerName = LocalPlayer.Name,
                    reason = reason,
                    toolsDetected = tools or {}
                })
            end
        end)
        
        -- Show notification
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⛔ BANNED",
                Text = reason,
                Duration = 3
            })
        end)
        
        -- Wait then kick
        task.wait(0.5)
        
        -- Multiple kick methods
        pcall(function()
            LocalPlayer:Kick("⛔ BANNED\\n\\n" .. reason .. "\\n\\nYou have been permanently banned.")
        end)
        
        pcall(function()
            game:Shutdown()
        end)
    end
    
    -- Comprehensive tool list
    local ${v.tools} = {
        -- Dex variants
        "Dex", "DEX", "dex",
        "DexV2", "DexV3", "DexV4",
        "DexExplorer", "Dex_Explorer",
        "DarkDex", "DarkDexV3", "Dark_Dex",
        
        -- Infinite Yield
        "InfiniteYield", "Infinite_Yield", 
        "IY_LOADED", "IY", "infiniteyield",
        
        -- Hydroxide
        "Hydroxide", "HydroxideUI", 
        "HYDROXIDE_LOADED", "hydroxide",
        
        -- Spies
        "SimpleSpy", "SimpleSpyExecuted", 
        "SimpleSpy_Loaded", "simplespy",
        "RemoteSpy", "Remote_Spy", 
        "REMOTESPY_LOADED", "remotespy",
        
        -- Other tools
        "BTool", "BTool_Loaded", "BTools",
        "F3X", "F3X_Loaded", "F3XTOOLS",
        "UnnamedESP", "ESP_LOADED", "ESP"
    }
    
    local function ${v.detect}()
        local found = {}
        
        -- Check _G thoroughly
        for key, value in pairs(_G) do
            local keyLower = tostring(key):lower()
            
            -- Check against tool list
            for _, toolName in ipairs(${v.tools}) do
                if keyLower == toolName:lower() then
                    if type(value) == "table" or type(value) == "boolean" then
                        if not table.find(found, toolName) then
                            table.insert(found, toolName)
                            print("[DETECTION] Found in _G:", toolName)
                        end
                    end
                end
            end
            
            -- Pattern matching for common tools
            if keyLower:match("dex") or keyLower:match("infinite") or 
               keyLower:match("hydroxide") or keyLower:match("spy") or
               keyLower:match("btool") or keyLower:match("f3x") then
                if type(value) == "table" or type(value) == "boolean" then
                    if not table.find(found, key) then
                        table.insert(found, tostring(key))
                        print("[DETECTION] Pattern match in _G:", key)
                    end
                end
            end
        end
        
        -- Check getgenv
        pcall(function()
            if getgenv then
                local genv = getgenv()
                for key, value in pairs(genv) do
                    local keyLower = tostring(key):lower()
                    
                    for _, toolName in ipairs(${v.tools}) do
                        if keyLower == toolName:lower() then
                            if type(value) == "table" or type(value) == "boolean" then
                                if not table.find(found, toolName) then
                                    table.insert(found, toolName)
                                    print("[DETECTION] Found in getgenv:", toolName)
                                end
                            end
                        end
                    end
                    
                    if keyLower:match("dex") or keyLower:match("infinite") or 
                       keyLower:match("hydroxide") or keyLower:match("spy") then
                        if not table.find(found, key) then
                            table.insert(found, tostring(key))
                            print("[DETECTION] Pattern match in getgenv:", key)
                        end
                    end
                end
            end
        end)
        
        -- Check CoreGui for tool UIs
        pcall(function()
            for _, child in pairs(CoreGui:GetChildren()) do
                if child:IsA("ScreenGui") then
                    local name = child.Name
                    local nameLower = name:lower()
                    
                    -- Check against known tool UI names
                    if nameLower:match("dex") or nameLower:match("infinite") or
                       nameLower:match("yield") or nameLower:match("hydroxide") or
                       nameLower:match("spy") or nameLower:match("btool") or
                       nameLower:match("f3x") then
                        if not table.find(found, name .. "_UI") then
                            table.insert(found, name .. "_UI")
                            print("[DETECTION] Found UI in CoreGui:", name)
                        end
                    end
                end
            end
        end)
        
        -- Check PlayerGui
        pcall(function()
            if LocalPlayer.PlayerGui then
                for _, child in pairs(LocalPlayer.PlayerGui:GetChildren()) do
                    if child:IsA("ScreenGui") then
                        local name = child.Name
                        local nameLower = name:lower()
                        
                        if nameLower:match("dex") or nameLower:match("infinite") or
                           nameLower:match("hydroxide") or nameLower:match("spy") then
                            if not table.find(found, name .. "_GUI") then
                                table.insert(found, name .. "_GUI")
                                print("[DETECTION] Found UI in PlayerGui:", name)
                            end
                        end
                    end
                end
            end
        end)
        
        -- Check shared table
        pcall(function()
            if shared then
                if shared.IYPrefix or shared.InfiniteYield or shared.IY then
                    if not table.find(found, "IY_Shared") then
                        table.insert(found, "IY_Shared")
                        print("[DETECTION] Found IY in shared")
                    end
                end
                if shared.Hydroxide then
                    if not table.find(found, "Hydroxide_Shared") then
                        table.insert(found, "Hydroxide_Shared")
                        print("[DETECTION] Found Hydroxide in shared")
                    end
                end
            end
        end)
        
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
        print("[SCRIPT] 🔍 Starting security checks...")
        
        -- Check owner presence first
        if checkOwnerPresence() then
            print("[SCRIPT] Aborting - Owner present")
            return false
        end
        
        -- Tool detection or whitelist
        if isWhitelisted() then
            print("[SCRIPT] ✅ Whitelisted - Bypassing tool detection")
        else
            print("[SCRIPT] 🔍 Checking for malicious tools...")
            local tools = ${v.detect}()
            
            if #tools > 0 then
                local toolList = table.concat(tools, ", ")
                print("[SCRIPT] ❌ TOOLS DETECTED:", toolList)
                ${v.kick}("Malicious tools detected: " .. toolList, tools)
                return false
            end
            
            print("[SCRIPT] ✅ No tools detected")
            
            -- Runtime monitoring (aggressive - every 5 seconds)
            task.spawn(function()
                while task.wait(5) do
                    local t = ${v.detect}()
                    if #t > 0 then
                        local list = table.concat(t, ", ")
                        print("[SCRIPT] ❌ RUNTIME DETECTION:", list)
                        ${v.kick}("Runtime tool detection: " .. list, t)
                        break
                    end
                end
            end)
        end
        
        -- Decode and execute
        print("[SCRIPT] 📦 Decoding script...")
        local content = ${v.decode}()
        
        if not content or #content < 10 then
            warn("[SCRIPT] ❌ Failed to decode")
            return false
        end
        
        local finalScript = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}]] .. content
        
        print("[SCRIPT] 🚀 Executing with owner protection...")
        local fn, err = loadstring(finalScript)
        if not fn then
            warn("[SCRIPT] Compile error:", err)
            return false
        end
        
        local ok, msg = pcall(fn)
        if not ok then
            warn("[SCRIPT] Runtime error:", msg)
        else
            print("[SCRIPT] ✅ Script loaded successfully!")
        end
        
        return ok
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
