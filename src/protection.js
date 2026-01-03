// ============================================================
// 🛡️ PROTECTION MODULE v4.3.6 - TARGETED DESTROY
// Only destroy script-created GUIs, not game UI
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

    // Safe protection - tag and track script GUIs
    const protectionWrapper = `
-- ============================================================
-- OWNER PROTECTION v4.3.6 - TARGETED DESTROY
-- ============================================================

local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _CORE_GUI = game:GetService("CoreGui")
local _PLAYER_GUI = _LOCAL:WaitForChild("PlayerGui")
local _RUN_SERVICE = game:GetService("RunService")
local _ACTIVE = true
local _TRACKED_GUIS = {}
local _TRACKED_CONNECTIONS = {}
local _TRACKED_THREADS = {}
local _SCRIPT_TAG = "LOADER_SCRIPT_" .. tostring(tick())

local function _IS_OWNER(uid)
    for _, id in ipairs(_OWNER_IDS) do
        if uid == id then return true end
    end
    return false
end

local function _TAG_GUI(gui)
    -- Tag GUI as script-created
    pcall(function()
        gui:SetAttribute(_SCRIPT_TAG, true)
        table.insert(_TRACKED_GUIS, gui)
    end)
end

local function _DESTROY_SCRIPT_GUIS()
    print("[PROTECTION] Destroying script GUIs only...")
    
    local destroyed = 0
    
    -- Destroy tracked GUIs
    for _, gui in pairs(_TRACKED_GUIS) do
        pcall(function()
            if gui and gui.Parent then
                gui:Destroy()
                destroyed = destroyed + 1
            end
        end)
    end
    
    -- Find and destroy tagged GUIs in CoreGui
    pcall(function()
        for _, child in pairs(_CORE_GUI:GetChildren()) do
            if child:GetAttribute(_SCRIPT_TAG) == true then
                pcall(function()
                    child:Destroy()
                    destroyed = destroyed + 1
                end)
            end
        end
    end)
    
    -- Find and destroy tagged GUIs in PlayerGui
    pcall(function()
        for _, child in pairs(_PLAYER_GUI:GetChildren()) do
            if child:GetAttribute(_SCRIPT_TAG) == true then
                pcall(function()
                    child:Destroy()
                    destroyed = destroyed + 1
                end)
            end
        end
    end)
    
    _TRACKED_GUIS = {}
    
    print("[PROTECTION] Destroyed", destroyed, "script GUIs")
end

local function _STOP_ALL_THREADS()
    print("[PROTECTION] Stopping all script threads...")
    
    for _, thread in pairs(_TRACKED_THREADS) do
        pcall(function()
            if thread then
                task.cancel(thread)
            end
        end)
    end
    
    _TRACKED_THREADS = {}
end

local function _DISCONNECT_ALL()
    print("[PROTECTION] Disconnecting all connections...")
    
    for _, conn in pairs(_TRACKED_CONNECTIONS) do
        pcall(function()
            if conn and conn.Connected then
                conn:Disconnect()
            end
        end)
    end
    
    _TRACKED_CONNECTIONS = {}
end

local function _STOP_SCRIPT(msg)
    if not _ACTIVE then return end
    _ACTIVE = false
    
    print("[PROTECTION] 🛑 STOPPING:", msg)
    
    -- Stop in order
    _STOP_ALL_THREADS()
    _DISCONNECT_ALL()
    _DESTROY_SCRIPT_GUIS()
    
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

-- Track GUI creation via DescendantAdded
local function _START_TRACKING()
    -- Track CoreGui
    local coreConn = _CORE_GUI.DescendantAdded:Connect(function(desc)
        if desc:IsA("ScreenGui") or desc:IsA("Frame") or 
           desc:IsA("TextButton") or desc:IsA("TextLabel") or
           desc:IsA("ImageLabel") or desc:IsA("ImageButton") then
            -- Tag it as script-created
            _TAG_GUI(desc)
        end
    end)
    table.insert(_TRACKED_CONNECTIONS, coreConn)
    
    -- Track PlayerGui
    local playerConn = _PLAYER_GUI.DescendantAdded:Connect(function(desc)
        if desc:IsA("ScreenGui") or desc:IsA("Frame") or 
           desc:IsA("TextButton") or desc:IsA("TextLabel") or
           desc:IsA("ImageLabel") or desc:IsA("ImageButton") then
            _TAG_GUI(desc)
        end
    end)
    table.insert(_TRACKED_CONNECTIONS, playerConn)
end

-- Start tracking immediately
_START_TRACKING()

-- Background owner monitor
local monitorThread = task.spawn(function()
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
table.insert(_TRACKED_THREADS, monitorThread)

-- Monitor for owner joining
local playerConn = _PLAYERS.PlayerAdded:Connect(function(p)
    task.wait(0.5)
    if _IS_OWNER(p.UserId) then
        _STOP_SCRIPT("Owner (" .. p.Name .. ") joined the server")
    end
end)
table.insert(_TRACKED_CONNECTIONS, playerConn)

print("[PROTECTION] 🛡️ Active - Monitoring for owner")
print("[PROTECTION] Tagging script GUIs with:", _SCRIPT_TAG)

-- Global access
_G._OWNER_PROTECTION = {
    active = function() return _ACTIVE end,
    stop = _STOP_SCRIPT,
    tag = _SCRIPT_TAG
}

-- ============================================================
-- USER SCRIPT BELOW
-- ============================================================
`;

    const protectedScript = `-- Protected v4.3.6 - Targeted Destroy
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
        print("[SCRIPT] 🔨 BANNING:", reason)
        
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
        
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⛔ BANNED",
                Text = reason,
                Duration = 3
            })
        end)
        
        task.wait(0.5)
        LocalPlayer:Kick("⛔ BANNED\\n\\n" .. reason .. "\\n\\nYou have been permanently banned.")
    end
    
    local ${v.tools} = {
        "Dex", "DEX", "dex", "DexV2", "DexV3", "DexV4", "DexExplorer",
        "DarkDex", "DarkDexV3", "Dark_Dex",
        "InfiniteYield", "Infinite_Yield", "IY_LOADED", "IY", "infiniteyield",
        "Hydroxide", "HydroxideUI", "HYDROXIDE_LOADED", "hydroxide",
        "SimpleSpy", "SimpleSpyExecuted", "SimpleSpy_Loaded", "simplespy",
        "RemoteSpy", "Remote_Spy", "REMOTESPY_LOADED", "remotespy",
        "BTool", "BTool_Loaded", "BTools",
        "F3X", "F3X_Loaded", "F3XTOOLS",
        "UnnamedESP", "ESP_LOADED", "ESP"
    }
    
    local function ${v.detect}()
        local found = {}
        
        for key, value in pairs(_G) do
            local keyLower = tostring(key):lower()
            
            for _, toolName in ipairs(${v.tools}) do
                if keyLower == toolName:lower() then
                    if type(value) == "table" or type(value) == "boolean" then
                        if not table.find(found, toolName) then
                            table.insert(found, toolName)
                        end
                    end
                end
            end
            
            if keyLower:match("dex") or keyLower:match("infinite") or 
               keyLower:match("hydroxide") or keyLower:match("spy") or
               keyLower:match("btool") or keyLower:match("f3x") then
                if type(value) == "table" or type(value) == "boolean" then
                    if not table.find(found, key) then
                        table.insert(found, tostring(key))
                    end
                end
            end
        end
        
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
                                end
                            end
                        end
                    end
                    
                    if keyLower:match("dex") or keyLower:match("infinite") or 
                       keyLower:match("hydroxide") or keyLower:match("spy") then
                        if not table.find(found, key) then
                            table.insert(found, tostring(key))
                        end
                    end
                end
            end
        end)
        
        pcall(function()
            for _, child in pairs(CoreGui:GetChildren()) do
                if child:IsA("ScreenGui") then
                    local nameLower = child.Name:lower()
                    if nameLower:match("dex") or nameLower:match("infinite") or
                       nameLower:match("yield") or nameLower:match("hydroxide") or
                       nameLower:match("spy") or nameLower:match("btool") or
                       nameLower:match("f3x") then
                        if not table.find(found, child.Name .. "_UI") then
                            table.insert(found, child.Name .. "_UI")
                        end
                    end
                end
            end
        end)
        
        pcall(function()
            if shared then
                if shared.IYPrefix or shared.InfiniteYield or shared.IY then
                    table.insert(found, "IY_Shared")
                end
                if shared.Hydroxide then
                    table.insert(found, "Hydroxide_Shared")
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
        if checkOwnerPresence() then
            return false
        end
        
        if isWhitelisted() then
            print("[SCRIPT] ✅ Whitelisted")
        else
            local tools = ${v.detect}()
            if #tools > 0 then
                local toolList = table.concat(tools, ", ")
                ${v.kick}("Tools detected: " .. toolList, tools)
                return false
            end
            
            task.spawn(function()
                while task.wait(5) do
                    local t = ${v.detect}()
                    if #t > 0 then
                        ${v.kick}("Runtime: " .. table.concat(t, ", "), t)
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
        
        local fn, err = loadstring(finalScript)
        if not fn then
            warn("[SCRIPT] Error:", err)
            return false
        end
        
        local ok = pcall(fn)
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
