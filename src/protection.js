// ============================================================
// 🛡️ PROTECTION MODULE v4.3.4 - SAFE METHOD (NO HOOKS)
// Use DescendantAdded instead of hooking Instance.new
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

    // Safe protection wrapper (no hooks, no readonly modification)
    const protectionWrapper = `
-- ============================================================
-- OWNER PROTECTION v4.3.4 - SAFE METHOD
-- ============================================================

local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _CORE_GUI = game:GetService("CoreGui")
local _ACTIVE = true
local _GUIS_CREATED = {}
local _CONNECTIONS = {}

local function _IS_OWNER(uid)
    for _, id in ipairs(_OWNER_IDS) do
        if uid == id then return true end
    end
    return false
end

local function _DESTROY_ALL()
    if not _ACTIVE then return end
    _ACTIVE = false
    
    print("[PROTECTION] Destroying all GUIs...")
    
    -- Destroy tracked GUIs
    for _, g in pairs(_GUIS_CREATED) do
        pcall(function() 
            if g and g.Parent then 
                g:Destroy() 
            end 
        end)
    end
    
    -- Destroy all ScreenGuis in CoreGui
    pcall(function()
        for _, child in pairs(_CORE_GUI:GetChildren()) do
            if child:IsA("ScreenGui") then
                pcall(function() child:Destroy() end)
            end
        end
    end)
    
    -- Destroy all ScreenGuis in PlayerGui
    pcall(function()
        if _LOCAL.PlayerGui then
            for _, child in pairs(_LOCAL.PlayerGui:GetChildren()) do
                if child:IsA("ScreenGui") then
                    pcall(function() child:Destroy() end)
                end
            end
        end
    end)
    
    -- Disconnect all connections
    for _, c in pairs(_CONNECTIONS) do
        pcall(function() 
            if c and c.Connected then 
                c:Disconnect() 
            end 
        end)
    end
    
    _GUIS_CREATED = {}
    _CONNECTIONS = {}
    
    print("[PROTECTION] ✅ All GUIs destroyed")
end

local function _STOP_SCRIPT(msg)
    print("[PROTECTION] Stopping:", msg)
    
    _DESTROY_ALL()
    
    -- Notification
    pcall(function()
        _STAR_GUI:SetCore("SendNotification", {
            Title = "⚠️ Script Stopped",
            Text = msg,
            Duration = 5
        })
    end)
end

-- Track GUIs using DescendantAdded (SAFE - no hook needed)
local function _TRACK_GUIS()
    -- Track CoreGui descendants
    local coreConn = _CORE_GUI.DescendantAdded:Connect(function(desc)
        if desc:IsA("ScreenGui") or desc:IsA("Frame") or 
           desc:IsA("TextLabel") or desc:IsA("TextButton") then
            table.insert(_GUIS_CREATED, desc)
        end
    end)
    table.insert(_CONNECTIONS, coreConn)
    
    -- Track PlayerGui descendants
    if _LOCAL.PlayerGui then
        local playerConn = _LOCAL.PlayerGui.DescendantAdded:Connect(function(desc)
            if desc:IsA("ScreenGui") or desc:IsA("Frame") or 
               desc:IsA("TextLabel") or desc:IsA("TextButton") then
                table.insert(_GUIS_CREATED, desc)
            end
        end)
        table.insert(_CONNECTIONS, playerConn)
    end
end

-- Start tracking
_TRACK_GUIS()

-- Background owner monitor
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
local playerConn = _PLAYERS.PlayerAdded:Connect(function(p)
    task.wait(0.5)
    if _IS_OWNER(p.UserId) then
        _STOP_SCRIPT("Owner (" .. p.Name .. ") joined the server")
    end
end)
table.insert(_CONNECTIONS, playerConn)

print("[PROTECTION] 🛡️ Active - Monitoring for owner")

-- Store in global for manual control
_G._OWNER_PROTECTION = {
    active = function() return _ACTIVE end,
    stop = _STOP_SCRIPT,
    destroy = _DESTROY_ALL
}

-- ============================================================
-- USER SCRIPT STARTS BELOW
-- ============================================================
`;

    const protectedScript = `-- Protected v4.3.4 - Safe Method
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
            print("[SCRIPT] You are the owner - Full access")
            return false
        end
        
        for _, player in pairs(Players:GetPlayers()) do
            if isOwner(player.UserId) and player ~= LocalPlayer then
                print("[SCRIPT] ⛔ Owner detected in server:", player.Name)
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
        
        task.wait(0.3)
        LocalPlayer:Kick("⛔ BANNED\\n\\n" .. reason)
    end
    
    local ${v.tools} = {
        "Dex", "DEX", "DarkDex", "InfiniteYield", "IY",
        "Hydroxide", "SimpleSpy", "RemoteSpy", "BTool", "F3X"
    }
    
    local function ${v.detect}()
        local found = {}
        
        for _, name in ipairs(${v.tools}) do
            if rawget(_G, name) then table.insert(found, name) end
        end
        
        pcall(function()
            if getgenv then
                for _, name in ipairs(${v.tools}) do
                    if rawget(getgenv(), name) and not table.find(found, name) then
                        table.insert(found, name)
                    end
                end
            end
        end)
        
        pcall(function()
            for _, name in ipairs(${v.tools}) do
                if CoreGui:FindFirstChild(name) then
                    table.insert(found, name .. "_UI")
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
        -- Check if owner already in server
        if checkOwnerPresence() then
            print("[SCRIPT] Aborting - Owner present")
            return false
        end
        
        -- Whitelist or tool detection
        if isWhitelisted() then
            print("[SCRIPT] ✅ Whitelisted user")
        else
            local tools = ${v.detect}()
            if #tools > 0 then
                ${v.kick}("Tools detected: " .. table.concat(tools, ", "), tools)
                return false
            end
            
            -- Background monitoring
            task.spawn(function()
                while task.wait(10) do
                    local t = ${v.detect}()
                    if #t > 0 then
                        ${v.kick}("Runtime: " .. table.concat(t, ", "), t)
                        break
                    end
                end
            end)
        end
        
        -- Decode script
        print("[SCRIPT] 📦 Decoding...")
        local content = ${v.decode}()
        
        if not content or #content < 10 then
            warn("[SCRIPT] ❌ Failed to decode")
            return false
        end
        
        -- Prepend protection
        local finalScript = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}]] .. content
        
        print("[SCRIPT] 🚀 Executing with protection...")
        local fn, err = loadstring(finalScript)
        if not fn then
            warn("[SCRIPT] Compile error:", err)
            return false
        end
        
        local ok, msg = pcall(fn)
        if not ok then
            warn("[SCRIPT] Runtime error:", msg)
        else
            print("[SCRIPT] ✅ Loaded successfully")
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
