// ============================================================
// 🛡️ PROTECTION MODULE v4.3.1 - AGGRESSIVE OWNER DETECTION
// Instant check + Force stop when owner detected
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
        kill: randomVar('_KL'),
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

    const protectedScript = `-- Protected v4.3.1 - Aggressive Owner Detection
local ${v.active} = true
local STOPPED = false

local ${v.main} = (function()
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local LocalPlayer = Players.LocalPlayer
    
    local BAN_ENDPOINT = "${banEndpoint}"
    local WHITELIST = {${whitelistStr}}
    local OWNER_IDS = {${ownerStr}}
    
    -- Storage for cleanup
    local ALL_GUIS = {}
    local ALL_CONNECTIONS = {}
    local ALL_THREADS = {}
    
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
    
    -- ============================================================
    -- 🔴 KILL FUNCTION - Force stop everything
    -- ============================================================
    
    local function ${v.kill}(reason)
        if STOPPED then return end
        STOPPED = true
        ${v.active} = false
        
        print("[SCRIPT] ⛔ FORCE STOP:", reason)
        
        -- Destroy all GUIs
        for _, gui in pairs(ALL_GUIS) do
            pcall(function() if gui then gui:Destroy() end end)
        end
        
        -- Disconnect all connections
        for _, conn in pairs(ALL_CONNECTIONS) do
            pcall(function() if conn then conn:Disconnect() end end)
        end
        
        -- Kill all threads
        for _, thread in pairs(ALL_THREADS) do
            pcall(function() if thread then coroutine.close(thread) end end)
        end
        
        -- Clean references
        ALL_GUIS = {}
        ALL_CONNECTIONS = {}
        ALL_THREADS = {}
        
        -- Notification
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⚠️ Script Stopped",
                Text = reason,
                Duration = 5
            })
        end)
        
        -- Clean global
        if _G.SCRIPT_LOADER then
            _G.SCRIPT_LOADER = nil
        end
        
        -- Force error to stop execution
        error("[SCRIPT] Stopped by owner detection", 0)
    end
    
    -- ============================================================
    -- 👑 OWNER DETECTION - INSTANT CHECK
    -- ============================================================
    
    local function ${v.owner}()
        -- If I am owner, skip check
        if isOwner(LocalPlayer.UserId) then
            print("[SCRIPT] You are the owner - Full control")
            return false
        end
        
        -- INSTANT CHECK - Check all players NOW
        for _, player in pairs(Players:GetPlayers()) do
            if isOwner(player.UserId) and player ~= LocalPlayer then
                print("[SCRIPT] ⛔ Owner detected:", player.Name)
                ${v.kill}("Owner (" .. player.Name .. ") is in this server")
                return true
            end
        end
        
        -- Monitor for owner joining
        local conn = Players.PlayerAdded:Connect(function(player)
            if isOwner(player.UserId) then
                print("[SCRIPT] ⛔ Owner joined:", player.Name)
                task.wait(0.1)
                ${v.kill}("Owner (" .. player.Name .. ") joined the server")
            end
        end)
        table.insert(ALL_CONNECTIONS, conn)
        
        -- Periodic check (every 5 seconds)
        local thread = task.spawn(function()
            while ${v.active} do
                task.wait(5)
                for _, player in pairs(Players:GetPlayers()) do
                    if isOwner(player.UserId) and player ~= LocalPlayer then
                        ${v.kill}("Owner (" .. player.Name .. ") detected in server")
                        return
                    end
                end
            end
        end)
        table.insert(ALL_THREADS, thread)
        
        return false
    end
    
    -- ============================================================
    -- 🔧 UTILITY FUNCTIONS
    -- ============================================================
    
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
    
    -- ============================================================
    -- 🔍 TOOL DETECTION
    -- ============================================================
    
    local ${v.tools} = {
        "Dex", "DEX", "DarkDex", "InfiniteYield", "IY",
        "Hydroxide", "SimpleSpy", "RemoteSpy", "BTool", "F3X"
    }
    
    local function ${v.detect}()
        local found = {}
        
        for _, name in ipairs(${v.tools}) do
            if rawget(_G, name) then
                table.insert(found, name)
            end
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
    
    -- ============================================================
    -- 📦 DECODE SCRIPT
    -- ============================================================
    
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
    
    -- ============================================================
    -- 🚀 MAIN EXECUTION
    -- ============================================================
    
    local function ${v.run}()
        -- PRIORITY 1: OWNER CHECK (BEFORE ANYTHING)
        print("[SCRIPT] Checking for owner presence...")
        if ${v.owner}() then
            print("[SCRIPT] Owner detected - Aborting execution")
            return false
        end
        
        -- PRIORITY 2: Whitelist check
        if isWhitelisted() then
            print("[SCRIPT] Whitelisted - Bypassing tool detection")
        else
            -- Tool detection
            local tools = ${v.detect}()
            if #tools > 0 then
                ${v.kick}("Tools: " .. table.concat(tools, ", "), tools)
                return false
            end
            
            -- Runtime monitoring
            task.spawn(function()
                while ${v.active} do
                    task.wait(10)
                    local t = ${v.detect}()
                    if #t > 0 then
                        ${v.kick}("Runtime: " .. table.concat(t, ", "), t)
                        break
                    end
                end
            end)
        end
        
        -- PRIORITY 3: Execute script
        print("[SCRIPT] Loading main script...")
        local content = ${v.decode}()
        
        if not content or #content < 10 then
            warn("[SCRIPT] Failed to decode")
            return false
        end
        
        local fn, err = loadstring(content)
        if not fn then
            warn("[SCRIPT] Compile error:", err)
            return false
        end
        
        -- Wrap execution with active check
        local wrappedFn = function()
            -- Check if still active before every major operation
            if not ${v.active} then
                error("[SCRIPT] Stopped", 0)
                return
            end
            
            -- Store in global for emergency stop
            _G.SCRIPT_LOADER = {
                active = ${v.active},
                stop = ${v.kill}
            }
            
            -- Execute original script
            return fn()
        end
        
        local ok, msg = pcall(wrappedFn)
        if not ok then
            warn("[SCRIPT] Runtime error:", msg)
        else
            print("[SCRIPT] ✅ Loaded successfully")
        end
        
        return ok
    end
    
    return ${v.run}
end)()

-- Execute with protection
local success, result = pcall(${v.main})
if not success then
    print("[SCRIPT] Execution failed:", result)
end

${v.main} = nil
`;

    return protectedScript;
}

module.exports = {
    generateProtectedScript,
    randomVar
};
