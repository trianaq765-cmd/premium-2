// ============================================================
// 🛡️ PROTECTION MODULE v4.3.3 - FIXED INJECTION
// Prepend protection code instead of template injection
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

    // Protection wrapper that will be prepended to user script
    const protectionWrapper = `
-- ============================================================
-- OWNER PROTECTION - AUTO INJECTED
-- ============================================================

local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _ACTIVE = true
local _TRACKED_GUIS = {}
local _TRACKED_CONNECTIONS = {}

local function _IS_OWNER(uid)
    for _, id in ipairs(_OWNER_IDS) do
        if uid == id then return true end
    end
    return false
end

local function _KILL_SCRIPT(msg)
    if not _ACTIVE then return end
    _ACTIVE = false
    
    print("[PROTECTION] Stopping:", msg)
    
    -- Destroy tracked GUIs
    for _, g in pairs(_TRACKED_GUIS) do
        pcall(function() if g then g:Destroy() end end)
    end
    
    -- Disconnect connections
    for _, c in pairs(_TRACKED_CONNECTIONS) do
        pcall(function() if c then c:Disconnect() end end)
    end
    
    _TRACKED_GUIS = {}
    _TRACKED_CONNECTIONS = {}
    
    -- Notification
    pcall(function()
        _STAR_GUI:SetCore("SendNotification", {
            Title = "⚠️ Stopped",
            Text = msg,
            Duration = 5
        })
    end)
    
    -- Find and destroy all ScreenGuis in CoreGui and PlayerGui
    pcall(function()
        for _, gui in pairs(game:GetService("CoreGui"):GetChildren()) do
            if gui:IsA("ScreenGui") then
                pcall(function() gui:Destroy() end)
            end
        end
    end)
    
    pcall(function()
        if _LOCAL.PlayerGui then
            for _, gui in pairs(_LOCAL.PlayerGui:GetChildren()) do
                if gui:IsA("ScreenGui") then
                    pcall(function() gui:Destroy() end)
                end
            end
        end
    end)
end

-- Hook Instance.new
local _OLD_INSTANCE = Instance.new
Instance.new = function(cls, ...)
    local obj = _OLD_INSTANCE(cls, ...)
    if cls:match("Gui") or cls:match("Frame") or cls:match("Button") or cls:match("Label") then
        table.insert(_TRACKED_GUIS, obj)
    end
    return obj
end

-- Background monitor
task.spawn(function()
    while _ACTIVE do
        task.wait(3)
        for _, p in pairs(_PLAYERS:GetPlayers()) do
            if _IS_OWNER(p.UserId) and p ~= _LOCAL then
                _KILL_SCRIPT("Owner (" .. p.Name .. ") in server")
                return
            end
        end
    end
end)

-- Player joined monitor
local conn = _PLAYERS.PlayerAdded:Connect(function(p)
    if _IS_OWNER(p.UserId) then
        task.wait(0.5)
        _KILL_SCRIPT("Owner (" .. p.Name .. ") joined")
    end
end)
table.insert(_TRACKED_CONNECTIONS, conn)

print("[PROTECTION] Active - Monitoring for owner")

-- ============================================================
-- USER SCRIPT BELOW
-- ============================================================
`;

    const protectedScript = `-- Protected v4.3.3
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
                print("[SCRIPT] Owner in server:", player.Name)
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
        if checkOwnerPresence() then
            print("[SCRIPT] Aborting")
            return false
        end
        
        if isWhitelisted() then
            print("[SCRIPT] Whitelisted")
        else
            local tools = ${v.detect}()
            if #tools > 0 then
                ${v.kick}("Tools: " .. table.concat(tools, ", "), tools)
                return false
            end
            
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
        
        print("[SCRIPT] Loading...")
        local content = ${v.decode}()
        
        if not content or #content < 10 then
            warn("[SCRIPT] Failed to decode")
            return false
        end
        
        -- PREPEND protection code to decoded script
        local protectedContent = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}]] .. content
        
        print("[SCRIPT] Executing with protection...")
        local fn, err = loadstring(protectedContent)
        if not fn then
            warn("[SCRIPT] Error:", err)
            return false
        end
        
        local ok, msg = pcall(fn)
        if not ok then
            warn("[SCRIPT] Runtime:", msg)
        else
            print("[SCRIPT] ✅ Loaded")
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
