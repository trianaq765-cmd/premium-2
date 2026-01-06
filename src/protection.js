// ============================================================
// 🛡️ PROTECTION MODULE - v5.1.0 FULL FEATURES
// Complete script protection with all features
// ============================================================

const crypto = require('crypto');

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function randomVar(prefix = '_') {
    return prefix + crypto.randomBytes(4).toString('hex');
}

function randomString(length = 8) {
    return crypto.randomBytes(length).toString('hex');
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

function generateChecksum(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// ============================================================
// MAIN PROTECTION GENERATOR
// ============================================================

function generateProtectedScript(originalScript, options = {}) {
    const {
        banEndpoint = '',
        whitelistUserIds = [],
        ownerUserIds = [],
        allowedPlaceIds = [],
        sessionKey = null
    } = options;

    // Generate random variable names for obfuscation
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
        key: randomVar('_KY'),
        wl: randomVar('_WL'),
        owner: randomVar('_OW'),
        check: randomVar('_CK'),
        presence: randomVar('_PR'),
        cache: randomVar('_CC'),
        notify: randomVar('_NF')
    };

    // Prepare script data (encrypted or base64)
    let scriptData;
    let dataType;
    
    if (sessionKey) {
        const encrypted = xorEncrypt(originalScript, sessionKey);
        scriptData = `{${encrypted.join(',')}}`;
        dataType = 'encrypted';
    } else {
        const chunks = [];
        const chunkSize = 400;
        for (let i = 0; i < originalScript.length; i += chunkSize) {
            const chunk = originalScript.substring(i, i + chunkSize);
            chunks.push(Buffer.from(chunk).toString('base64'));
        }
        scriptData = `{${chunks.map((c, i) => `[${i + 1}]="${c}"`).join(',')}}`;
        dataType = 'base64';
    }

    const whitelistStr = whitelistUserIds.join(', ');
    const ownerStr = ownerUserIds.join(', ');
    const allowedGamesStr = allowedPlaceIds.join(', ');
    const scriptTag = randomString(12);

    // ============================================================
    // FULL PROTECTION WRAPPER
    // ============================================================
    const protectionWrapper = `
-- ============================================================
-- 🛡️ OWNER PROTECTION v5.1.0 - FULL FEATURES
-- Auto-cleanup when owner detected
-- ============================================================

local _OWNER_IDS = {${ownerStr}}
local _PLAYERS = game:GetService("Players")
local _LOCAL = _PLAYERS.LocalPlayer
local _STAR_GUI = game:GetService("StarterGui")
local _CORE_GUI = game:GetService("CoreGui")
local _PLAYER_GUI = _LOCAL:WaitForChild("PlayerGui")
local _RUN_SERVICE = game:GetService("RunService")
local _TWEEN_SERVICE = game:GetService("TweenService")
local _USER_INPUT = game:GetService("UserInputService")

-- State variables
local _ACTIVE = true
local _SHUTTING_DOWN = false
local _TRACKED_GUIS = {}
local _CONNECTIONS = {}
local _THREADS = {}
local _TWEENS = {}
local _SCRIPT_TAG = "${scriptTag}"
local _START_TIME = tick()

-- Performance: Owner cache
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

-- ============================================================
-- NOTIFICATION HELPER
-- ============================================================
local function _NOTIFY(title, text, duration)
    pcall(function()
        _STAR_GUI:SetCore("SendNotification", {
            Title = title or "Notice",
            Text = text or "",
            Duration = duration or 3
        })
    end)
end

-- ============================================================
-- FULL SHUTDOWN - Complete cleanup
-- ============================================================
local function _SHUTDOWN()
    if _SHUTTING_DOWN then return end
    _SHUTTING_DOWN = true
    _ACTIVE = false
    
    local startTime = tick()
    print("[PROTECTION] 🔄 Clean shutdown initiated...")
    
    -- Step 1: Cancel all tweens
    local tweensCancelled = 0
    for i = #_TWEENS, 1, -1 do
        pcall(function()
            if _TWEENS[i] then
                _TWEENS[i]:Cancel()
                tweensCancelled = tweensCancelled + 1
            end
        end)
        _TWEENS[i] = nil
    end
    _TWEENS = {}
    
    -- Step 2: Cancel all threads
    local threadsCancelled = 0
    for i = #_THREADS, 1, -1 do
        pcall(function() 
            if _THREADS[i] then
                task.cancel(_THREADS[i])
                threadsCancelled = threadsCancelled + 1
            end
        end)
        _THREADS[i] = nil
    end
    _THREADS = {}
    
    -- Step 3: Disconnect all connections
    local connectionsClosed = 0
    for i = #_CONNECTIONS, 1, -1 do
        pcall(function()
            if _CONNECTIONS[i] and _CONNECTIONS[i].Connected then
                _CONNECTIONS[i]:Disconnect()
                connectionsClosed = connectionsClosed + 1
            end
        end)
        _CONNECTIONS[i] = nil
    end
    _CONNECTIONS = {}
    
    -- Step 4: Wait for operations to complete
    task.wait(0.1)
    
    -- Step 5: Destroy tracked GUIs
    local guisDestroyed = 0
    for i = #_TRACKED_GUIS, 1, -1 do
        pcall(function()
            local gui = _TRACKED_GUIS[i]
            if gui and gui.Parent then
                if gui:IsA("ScreenGui") then 
                    gui.Enabled = false 
                end
                gui:Destroy()
                guisDestroyed = guisDestroyed + 1
            end
        end)
        _TRACKED_GUIS[i] = nil
    end
    _TRACKED_GUIS = {}
    
    -- Step 6: Cleanup GUIs by tag (backup method)
    task.spawn(function()
        task.wait(0.1)
        
        -- Clean CoreGui
        pcall(function()
            for _, child in pairs(_CORE_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    if child:IsA("ScreenGui") then 
                        child.Enabled = false 
                    end
                    child:Destroy()
                    guisDestroyed = guisDestroyed + 1
                end
            end
        end)
        
        -- Clean PlayerGui
        pcall(function()
            for _, child in pairs(_PLAYER_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    if child:IsA("ScreenGui") then 
                        child.Enabled = false 
                    end
                    child:Destroy()
                    guisDestroyed = guisDestroyed + 1
                end
            end
        end)
    end)
    
    -- Step 7: Clear global references
    _G._OWNER_PROTECTION = nil
    _G._SCRIPT_CLEANUP = nil
    _G.LOADER_SCRIPT = nil
    
    -- Step 8: Garbage collection
    task.spawn(function()
        task.wait(0.5)
        for i = 1, 3 do
            pcall(function() 
                collectgarbage("collect") 
            end)
            task.wait(0.1)
        end
    end)
    
    local elapsed = math.floor((tick() - startTime) * 1000)
    print(string.format(
        "[PROTECTION] ✅ Shutdown complete in %dms | Threads: %d | Connections: %d | GUIs: %d | Tweens: %d",
        elapsed, threadsCancelled, connectionsClosed, guisDestroyed, tweensCancelled
    ))
    
    -- Step 9: Notify user
    task.defer(function()
        _NOTIFY("⚠️ Script Stopped", "Owner detected - cleaned up", 3)
    end)
end

-- Global cleanup function
_G._SCRIPT_CLEANUP = _SHUTDOWN

-- ============================================================
-- GUI TRACKING - Full tracking with attributes
-- ============================================================
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

-- Track new GUIs
task.defer(function()
    if not _ACTIVE then return end
    
    -- Track CoreGui additions
    local c1 = _CORE_GUI.DescendantAdded:Connect(function(descendant)
        if _ACTIVE and descendant:IsA("ScreenGui") then 
            _TRACK(descendant) 
        end
    end)
    table.insert(_CONNECTIONS, c1)
    
    -- Track PlayerGui additions
    local c2 = _PLAYER_GUI.DescendantAdded:Connect(function(descendant)
        if _ACTIVE and descendant:IsA("ScreenGui") then 
            _TRACK(descendant) 
        end
    end)
    table.insert(_CONNECTIONS, c2)
    
    -- Track existing GUIs in CoreGui
    for _, gui in pairs(_CORE_GUI:GetChildren()) do
        if gui:IsA("ScreenGui") then
            _TRACK(gui)
        end
    end
    
    -- Track existing GUIs in PlayerGui
    for _, gui in pairs(_PLAYER_GUI:GetChildren()) do
        if gui:IsA("ScreenGui") then
            _TRACK(gui)
        end
    end
end)

-- ============================================================
-- OWNER MONITORING - Interval check + PlayerAdded
-- ============================================================

-- Periodic check
local monitor = task.spawn(function()
    while _ACTIVE do
        task.wait(15)
        if not _ACTIVE then break end
        
        for _, player in pairs(_PLAYERS:GetPlayers()) do
            if player ~= _LOCAL and _IS_OWNER(player.UserId) then
                print("[PROTECTION] ⚠️ Owner detected in server:", player.Name)
                _SHUTDOWN()
                return
            end
        end
    end
end)
table.insert(_THREADS, monitor)

-- PlayerAdded listener
local playerAddedConnection = _PLAYERS.PlayerAdded:Connect(function(player)
    if not _ACTIVE then return end
    
    -- Wait for UserId to be available
    task.wait(1)
    
    if _IS_OWNER(player.UserId) then
        print("[PROTECTION] ⚠️ Owner joined:", player.Name)
        _SHUTDOWN()
    end
end)
table.insert(_CONNECTIONS, playerAddedConnection)

-- ============================================================
-- UTILITY FUNCTIONS FOR SCRIPT
-- ============================================================

-- Helper to add connection to tracking
local function _ADD_CONNECTION(conn)
    if conn then
        table.insert(_CONNECTIONS, conn)
    end
    return conn
end

-- Helper to add thread to tracking
local function _ADD_THREAD(thread)
    if thread then
        table.insert(_THREADS, thread)
    end
    return thread
end

-- Helper to add tween to tracking
local function _ADD_TWEEN(tween)
    if tween then
        table.insert(_TWEENS, tween)
    end
    return tween
end

-- ============================================================
-- GLOBAL PROTECTION OBJECT
-- ============================================================
_G._OWNER_PROTECTION = {
    active = function() return _ACTIVE end,
    stop = _SHUTDOWN,
    tag = _SCRIPT_TAG,
    uptime = function() return tick() - _START_TIME end,
    stats = function()
        return {
            active = _ACTIVE,
            uptime = tick() - _START_TIME,
            trackedGuis = #_TRACKED_GUIS,
            connections = #_CONNECTIONS,
            threads = #_THREADS,
            tweens = #_TWEENS
        }
    end,
    addConnection = _ADD_CONNECTION,
    addThread = _ADD_THREAD,
    addTween = _ADD_TWEEN,
    notify = _NOTIFY
}

-- ============================================================
-- USER SCRIPT EXECUTION BELOW
-- ============================================================
`;

    const useEncryption = !!sessionKey;

    // ============================================================
    // MAIN PROTECTED SCRIPT
    // ============================================================
    const protectedScript = `-- 🛡️ Protected Script v5.1.0 - Full Features
-- Generated: ${new Date().toISOString()}
-- Type: ${dataType}

local ${v.main} = (function()
    -- ============================================================
    -- SERVICES
    -- ============================================================
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local RunService = game:GetService("RunService")
    local LocalPlayer = Players.LocalPlayer
    
    -- ============================================================
    -- CONFIGURATION
    -- ============================================================
    local BAN_ENDPOINT = "${banEndpoint}"
    local WHITELIST = {${whitelistStr}}
    local OWNER_IDS = {${ownerStr}}
    local ALLOWED_GAMES = {${allowedGamesStr}}
    local USE_ENCRYPTION = ${useEncryption}
    local SESSION_KEY = "${sessionKey || ''}"
    
    -- Encrypted/encoded data
    local ${v.data} = ${scriptData}
    
    -- ============================================================
    -- CACHES FOR PERFORMANCE
    -- ============================================================
    local ${v.cache} = {
        whitelist = nil,
        owner = {}
    }
    
    -- ============================================================
    -- NOTIFICATION HELPER
    -- ============================================================
    local function ${v.notify}(title, text, duration)
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = title or "Notice",
                Text = text or "",
                Duration = duration or 3
            })
        end)
    end
    
    -- ============================================================
    -- GAME VERIFICATION
    -- ============================================================
    local function ${v.game}()
        local currentPlaceId = game.PlaceId
        
        -- No restriction if list is empty
        if #ALLOWED_GAMES == 0 then
            return true, "No restriction"
        end
        
        -- Check if current game is allowed
        for _, placeId in ipairs(ALLOWED_GAMES) do
            if currentPlaceId == placeId then
                print("[GAME] ✅ Verified:", currentPlaceId)
                return true, "Allowed"
            end
        end
        
        print("[GAME] ❌ Unauthorized:", currentPlaceId)
        return false, currentPlaceId
    end
    
    -- Check game FIRST (before anything else)
    local gameAllowed, gameInfo = ${v.game}()
    
    if not gameAllowed then
        task.defer(function()
            ${v.notify}("⛔ Wrong Game", "This script doesn't work here", 5)
        end)
        
        task.wait(1)
        LocalPlayer:Kick(
            "⛔ WRONG GAME\\n\\n" ..
            "This script only works in specific games.\\n\\n" ..
            "Current Game ID: " .. tostring(gameInfo) .. "\\n" ..
            "Contact admin for access."
        )
        return false
    end
    
    -- ============================================================
    -- WHITELIST CHECK (with cache)
    -- ============================================================
    local function ${v.wl}()
        if ${v.cache}.whitelist ~= nil then 
            return ${v.cache}.whitelist 
        end
        
        -- No whitelist = allow all
        if #WHITELIST == 0 then
            ${v.cache}.whitelist = true
            return true
        end
        
        -- Check if user is in whitelist
        for _, uid in ipairs(WHITELIST) do
            if LocalPlayer.UserId == uid then
                ${v.cache}.whitelist = true
                return true
            end
        end
        
        ${v.cache}.whitelist = false
        return false
    end
    
    -- ============================================================
    -- OWNER CHECK (with cache)
    -- ============================================================
    local function ${v.owner}(uid)
        if ${v.cache}.owner[uid] ~= nil then 
            return ${v.cache}.owner[uid] 
        end
        
        for _, id in ipairs(OWNER_IDS) do
            if uid == id then
                ${v.cache}.owner[uid] = true
                return true
            end
        end
        
        ${v.cache}.owner[uid] = false
        return false
    end
    
    local function ${v.presence}()
        -- Owner can run their own script
        if ${v.owner}(LocalPlayer.UserId) then 
            return false 
        end
        
        -- Check if any owner is in server
        for _, player in pairs(Players:GetPlayers()) do
            if ${v.owner}(player.UserId) and player ~= LocalPlayer then
                task.defer(function()
                    ${v.notify}("⚠️ Cannot Load", "Owner (" .. player.Name .. ") in server", 3)
                end)
                return true
            end
        end
        return false
    end
    
    -- ============================================================
    -- HWID FUNCTION
    -- ============================================================
    local function ${v.hwid}()
        local hwid = "UNKNOWN"
        
        pcall(function()
            if gethwid then
                hwid = gethwid()
            elseif get_hwid then
                hwid = get_hwid()
            elseif getexecutorname then
                hwid = getexecutorname() .. "_" .. tostring(LocalPlayer.UserId) .. "_" .. tostring(os.time())
            else
                hwid = "FALLBACK_" .. tostring(LocalPlayer.UserId) .. "_" .. tostring(tick())
            end
        end)
        
        return hwid
    end
    
    -- ============================================================
    -- HTTP FUNCTION
    -- ============================================================
    local function ${v.http}(url, data)
        task.defer(function()
            pcall(function()
                local httpRequest = syn and syn.request or request or http_request
                
                if httpRequest then
                    httpRequest({
                        Url = url,
                        Method = "POST",
                        Headers = {
                            ["Content-Type"] = "application/json",
                            ["User-Agent"] = "RobloxProtection/5.1.0"
                        },
                        Body = HttpService:JSONEncode(data)
                    })
                end
            end)
        end)
    end
    
    -- ============================================================
    -- KICK/BAN FUNCTION
    -- ============================================================
    local function ${v.kick}(reason, tools)
        -- Send ban report to server
        if BAN_ENDPOINT and BAN_ENDPOINT ~= "" then
            ${v.http}(BAN_ENDPOINT, {
                hwid = ${v.hwid}(),
                playerId = LocalPlayer.UserId,
                playerName = LocalPlayer.Name,
                reason = reason,
                toolsDetected = tools or {},
                timestamp = os.time(),
                placeId = game.PlaceId
            })
        end
        
        -- Notify user
        task.defer(function()
            ${v.notify}("⛔ BANNED", reason, 2)
        end)
        
        -- Wait and kick
        task.wait(0.5)
        LocalPlayer:Kick(
            "⛔ BANNED\\n\\n" .. 
            "Reason: " .. reason .. "\\n\\n" ..
            "Appeal: Contact admin"
        )
    end
    
    -- ============================================================
    -- TOOL DETECTION (Extended list)
    -- ============================================================
    local ${v.tools} = {
        -- Explorers
        "dex", "darkdex", "dexv4", "dex4", "dexexplorer", "remdex",
        -- Command tools
        "infiniteyield", "iy", "infinite yield", "cmd", "commands",
        -- Spy tools
        "hydroxide", "simplespy", "remotespy", "spy", "networkspy",
        -- Building tools
        "btool", "f3x", "building", "buildtools",
        -- Dump tools
        "scriptdumper", "dumper", "saveinstance", "unlocker",
        -- Other
        "aimbot", "esp", "noclip", "fly", "speed"
    }
    
    local function ${v.detect}()
        local found = {}
        
        -- Check _G table
        for key, value in pairs(_G) do
            if type(key) == "string" then
                local keyLower = key:lower()
                for _, tool in ipairs(${v.tools}) do
                    if keyLower:find(tool) then
                        table.insert(found, tostring(key))
                        break
                    end
                end
            end
        end
        
        -- Check getgenv if available
        if #found == 0 then
            pcall(function()
                if getgenv then
                    for key, value in pairs(getgenv()) do
                        if type(key) == "string" then
                            local keyLower = key:lower()
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
        
        -- Check CoreGui for suspicious GUIs
        if #found == 0 then
            pcall(function()
                for _, gui in pairs(CoreGui:GetChildren()) do
                    if gui:IsA("ScreenGui") then
                        local nameLower = gui.Name:lower()
                        for _, tool in ipairs(${v.tools}) do
                            if nameLower:find(tool) then
                                table.insert(found, gui.Name)
                                break
                            end
                        end
                    end
                end
            end)
        end
        
        return found
    end
    
    -- ============================================================
    -- DECRYPTION FUNCTIONS
    -- ============================================================
    
    -- XOR Decrypt
    local function xorDecrypt(data, key)
        local result = {}
        for i = 1, #data do
            local byte = data[i]
            local keyByte = string.byte(key, ((i - 1) % #key) + 1)
            result[i] = string.char(bit32.bxor(byte, keyByte))
        end
        return table.concat(result)
    end
    
    -- Base64 Decode
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
    
    -- Main decode function
    local function ${v.decode}()
        if USE_ENCRYPTION and SESSION_KEY ~= "" then
            -- XOR decrypt
            print("[DECODE] Using XOR decryption")
            return xorDecrypt(${v.data}, SESSION_KEY)
        else
            -- Base64 decode chunks
            print("[DECODE] Using Base64 decoding")
            local parts = {}
            for i, chunk in ipairs(${v.data}) do
                parts[i] = base64Decode(chunk)
            end
            return table.concat(parts)
        end
    end
    
    -- ============================================================
    -- MAIN RUN FUNCTION
    -- ============================================================
    local function ${v.run}()
        print("[LOADER] 🔄 Starting protection checks...")
        
        -- Check 1: Owner presence
        if ${v.presence}() then 
            print("[LOADER] ❌ Owner detected, stopping")
            return false 
        end
        print("[LOADER] ✅ Owner check passed")
        
        -- Check 2: Tool detection (for non-whitelisted users only)
        if not ${v.wl}() then
            -- Initial tool check
            local tools = ${v.detect}()
            if #tools > 0 then
                print("[LOADER] ❌ Tools detected:", table.concat(tools, ", "))
                ${v.kick}("Malicious tools detected: " .. tools[1], tools)
                return false
            end
            print("[LOADER] ✅ Tool check passed")
            
            -- Runtime monitoring
            task.spawn(function()
                while task.wait(20) do
                    local detected = ${v.detect}()
                    if #detected > 0 then
                        print("[LOADER] ❌ Runtime tools detected:", table.concat(detected, ", "))
                        ${v.kick}("Runtime tool detected: " .. detected[1], detected)
                        break
                    end
                end
            end)
        else
            print("[LOADER] ✅ User is whitelisted, skipping tool check")
        end
        
        -- Decode script
        print("[LOADER] 🔄 Decoding script...")
        local script = ${v.decode}()
        
        if not script or #script < 10 then 
            print("[LOADER] ❌ Failed to decode script")
            ${v.notify}("❌ Error", "Failed to decode script", 5)
            return false 
        end
        
        print("[LOADER] ✅ Script decoded (" .. #script .. " bytes)")
        
        -- Combine protection wrapper + user script
        local protectionCode = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/\[\[/g, '[\\[').replace(/\]\]/g, ']\\]').replace(/'/g, "\\'")}]]
        local fullScript = protectionCode .. script
        
        -- Execute
        print("[LOADER] 🔄 Executing script...")
        
        local loadFunc, loadErr = loadstring(fullScript)
        
        if loadFunc then
            local success, execErr = pcall(loadFunc)
            
            if success then
                print("[LOADER] ✅ Script executed successfully!")
                return true
            else
                print("[LOADER] ❌ Execution error:", tostring(execErr))
                warn("[LOADER] Execution Error:", execErr)
                return false
            end
        else
            print("[LOADER] ❌ Loadstring error:", tostring(loadErr))
            warn("[LOADER] Loadstring Error:", loadErr)
            return false
        end
    end
    
    return ${v.run}
end)()

-- Execute main function
if ${v.main} then 
    ${v.main}() 
end
`;

    return protectedScript;
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
    generateProtectedScript,
    randomVar,
    randomString,
    xorEncrypt,
    generateSessionKey,
    generateChecksum
};
