// ============================================================
// 🛡️ PROTECTION MODULE v4.3.2 - RUNTIME INJECTION
// Inject owner detection directly into user script
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
        run: randomVar('_R'),
        owner: randomVar('_OW'),
        guard: randomVar('_GD'),
        stop: randomVar('_ST'),
        active: randomVar('_AC')
    };

    const scriptChunks = [];
    const chunkSize = 400;
    for (let i = 0; i < originalScript.length; i += chunkSize) {
        const chunk = originalScript.substring(i, i + chunkSize);
        scriptChunks.push(Buffer.from(chunk).toString('base64'));
    }

    const whitelistStr = whitelistUserIds.join(', ');
    const ownerStr = ownerUserIds.join(', ');

    // Inject protection wrapper into user script
    const injectedScript = `
-- ============================================================
-- INJECTED OWNER PROTECTION - DO NOT REMOVE
-- ============================================================

local _SCRIPT_ACTIVE = true
local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL_PLAYER = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _ALL_GUIS = {}
local _ALL_CONNECTIONS = {}

local function _IS_OWNER(userId)
    for _, id in ipairs(_OWNER_IDS) do
        if userId == id then return true end
    end
    return false
end

local function _STOP_SCRIPT(reason)
    if not _SCRIPT_ACTIVE then return end
    _SCRIPT_ACTIVE = false
    
    print("[PROTECTION] 🛑 Stopping script:", reason)
    
    -- Destroy all tracked GUIs
    for _, gui in pairs(_ALL_GUIS) do
        pcall(function()
            if gui and gui.Parent then
                gui:Destroy()
            end
        end)
    end
    
    -- Disconnect all connections
    for _, conn in pairs(_ALL_CONNECTIONS) do
        pcall(function()
            if conn and conn.Connected then
                conn:Disconnect()
            end
        end)
    end
    
    -- Clear tables
    _ALL_GUIS = {}
    _ALL_CONNECTIONS = {}
    
    -- Notification
    pcall(function()
        _STAR_GUI:SetCore("SendNotification", {
            Title = "⚠️ Script Disabled",
            Text = reason,
            Duration = 5
        })
    end)
    
    -- Poison all major services to prevent further execution
    local function poison()
        error("[PROTECTION] Script has been stopped", 0)
    end
    
    -- Override critical functions
    task.wait = poison
    task.spawn = poison
    RunService = setmetatable({}, {__index = poison, __newindex = poison})
    
    print("[PROTECTION] ✅ Script stopped successfully")
end

-- Hook Instance.new to track GUIs
local _ORIGINAL_INSTANCE_NEW = Instance.new
Instance.new = function(className, parent)
    local obj = _ORIGINAL_INSTANCE_NEW(className, parent)
    
    if className:match("Gui") or className:match("Frame") or 
       className:match("Button") or className:match("Label") or
       className:match("Box") then
        table.insert(_ALL_GUIS, obj)
    end
    
    return obj
end

-- Monitor for owner in background (aggressive)
task.spawn(function()
    local checkInterval = 3 -- Check every 3 seconds
    
    while _SCRIPT_ACTIVE do
        task.wait(checkInterval)
        
        if not _SCRIPT_ACTIVE then break end
        
        -- Check all players in server
        for _, player in pairs(_PLAYERS:GetPlayers()) do
            if _IS_OWNER(player.UserId) and player ~= _LOCAL_PLAYER then
                print("[PROTECTION] 🚨 Owner detected:", player.Name)
                _STOP_SCRIPT("Owner (" .. player.Name .. ") is in the server")
                return
            end
        end
    end
end)

-- Monitor for new players joining
local _player_added_conn = _PLAYERS.PlayerAdded:Connect(function(player)
    if _IS_OWNER(player.UserId) then
        print("[PROTECTION] 🚨 Owner joined:", player.Name)
        task.wait(0.5)
        _STOP_SCRIPT("Owner (" .. player.Name .. ") joined the server")
    end
end)
table.insert(_ALL_CONNECTIONS, _player_added_conn)

-- Store in global for external access
_G._SCRIPT_GUARD = {
    active = function() return _SCRIPT_ACTIVE end,
    stop = _STOP_SCRIPT,
    isOwner = _IS_OWNER
}

print("[PROTECTION] 🛡️ Owner protection active")
print("[PROTECTION] Monitoring for owner presence...")

-- ============================================================
-- USER SCRIPT STARTS HERE
-- ============================================================

${originalScript}

-- ============================================================
-- USER SCRIPT ENDS HERE
-- ============================================================

print("[PROTECTION] Script execution completed")
`;

    const protectedScript = `-- Protected v4.3.2 - Runtime Injection
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
    
    -- Check if owner is already in server (BEFORE EXECUTION)
    local function checkOwnerPresence()
        if isOwner(LocalPlayer.UserId) then
            print("[SCRIPT] You are the owner - Full access")
            return false
        end
        
        for _, player in pairs(Players:GetPlayers()) do
            if isOwner(player.UserId) and player ~= LocalPlayer then
                print("[SCRIPT] ⛔ Owner already in server:", player.Name)
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
        -- PRIORITY 1: Check if owner already in server
        if checkOwnerPresence() then
            print("[SCRIPT] Aborting - Owner detected")
            return false
        end
        
        -- PRIORITY 2: Whitelist or tool detection
        if isWhitelisted() then
            print("[SCRIPT] Whitelisted")
        else
            local tools = ${v.detect}()
            if #tools > 0 then
                ${v.kick}("Tools: " .. table.concat(tools, ", "), tools)
                return false
            end
            
            -- Background tool monitoring
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
        
        -- PRIORITY 3: Decode script
        print("[SCRIPT] Decoding...")
        local content = ${v.decode}()
        
        if not content or #content < 10 then
            warn("[SCRIPT] Failed to decode")
            return false
        end
        
        -- INJECT PROTECTION WRAPPER
        local injectedContent = [[
${injectedScript.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}
]]
        
        print("[SCRIPT] Executing with runtime protection...")
        local fn, err = loadstring(injectedContent)
        if not fn then
            warn("[SCRIPT] Compile error:", err)
            return false
        end
        
        local ok, msg = pcall(fn)
        if not ok then
            warn("[SCRIPT] Runtime error:", msg)
        end
        
        return ok
    end
    
    return ${v.run}
end)()

if ${v.main} then
    ${v.main}()
end
`;

    return protectedScript;
}

module.exports = {
    generateProtectedScript,
    randomVar
};
