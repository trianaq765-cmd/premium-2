// ============================================================
// 🛡️ PROTECTION MODULE - v5.2.0 ENHANCED TOOL DETECTION
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

    // Generate random variable names
    const v = {
        main: randomVar('_M'),
        detect: randomVar('_D'),
        kick: randomVar('_K'),
        decode: randomVar('_DC'),
        data: randomVar('_DT'),
        http: randomVar('_H'),
        hwid: randomVar('_HW'),
        run: randomVar('_R'),
        game: randomVar('_GM'),
        wl: randomVar('_WL'),
        owner: randomVar('_OW'),
        presence: randomVar('_PR'),
        cache: randomVar('_CC'),
        notify: randomVar('_NF'),
        scan: randomVar('_SC'),
        monitor: randomVar('_MN')
    };

    // Prepare script data
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
    // PROTECTION WRAPPER - FULL
    // ============================================================
    const protectionWrapper = `
-- ============================================================
-- 🛡️ OWNER PROTECTION v5.2.0 - ENHANCED
-- ============================================================

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
local _SCRIPT_TAG = "${scriptTag}"

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

local function _NOTIFY(title, text, duration)
    pcall(function()
        _STAR_GUI:SetCore("SendNotification", {
            Title = title or "Notice",
            Text = text or "",
            Duration = duration or 3
        })
    end)
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
    
    task.wait(0.1)
    
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
    
    task.spawn(function()
        task.wait(0.1)
        pcall(function()
            for _, child in pairs(_CORE_GUI:GetChildren()) do
                if child:GetAttribute(_SCRIPT_TAG) then
                    child:Destroy()
                end
            end
        end)
    end)
    
    _G._OWNER_PROTECTION = nil
    _G._SCRIPT_CLEANUP = nil
    
    task.spawn(function()
        task.wait(0.5)
        for i = 1, 3 do
            pcall(function() collectgarbage("collect") end)
            task.wait(0.1)
        end
    end)
    
    _NOTIFY("⚠️ Script Stopped", "Owner detected", 3)
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

    // ============================================================
    // MAIN SCRIPT WITH ENHANCED DETECTION
    // ============================================================
    const protectedScript = `-- 🛡️ Protected Script v5.2.0 - Enhanced Tool Detection
local ${v.main} = (function()
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local RunService = game:GetService("RunService")
    local LocalPlayer = Players.LocalPlayer
    
    local BAN_ENDPOINT = "${banEndpoint}"
    local WHITELIST = {${whitelistStr}}
    local OWNER_IDS = {${ownerStr}}
    local ALLOWED_GAMES = {${allowedGamesStr}}
    local USE_ENCRYPTION = ${useEncryption}
    local SESSION_KEY = "${sessionKey || ''}"
    local ${v.data} = ${scriptData}
    
    local ${v.cache} = { whitelist = nil, owner = {} }
    local _DETECTED_TOOLS = {}
    local _TOOL_CHECK_ACTIVE = true
    
    -- ============================================================
    -- NOTIFICATION
    -- ============================================================
    local function ${v.notify}(title, text, duration)
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = title, Text = text, Duration = duration or 3
            })
        end)
    end
    
    -- ============================================================
    -- GAME CHECK
    -- ============================================================
    local function ${v.game}()
        if #ALLOWED_GAMES == 0 then return true end
        for _, placeId in ipairs(ALLOWED_GAMES) do
            if game.PlaceId == placeId then return true end
        end
        return false
    end
    
    if not ${v.game}() then
        ${v.notify}("⛔ Wrong Game", "Script not allowed here", 5)
        task.wait(1)
        LocalPlayer:Kick("⛔ WRONG GAME\\n\\nThis script only works in specific games.")
        return false
    end
    
    -- ============================================================
    -- WHITELIST & OWNER CHECK
    -- ============================================================
    local function ${v.wl}()
        if ${v.cache}.whitelist ~= nil then return ${v.cache}.whitelist end
        if #WHITELIST == 0 then ${v.cache}.whitelist = true return true end
        for _, uid in ipairs(WHITELIST) do
            if LocalPlayer.UserId == uid then
                ${v.cache}.whitelist = true
                return true
            end
        end
        ${v.cache}.whitelist = false
        return false
    end
    
    local function ${v.owner}(uid)
        if ${v.cache}.owner[uid] ~= nil then return ${v.cache}.owner[uid] end
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
        if ${v.owner}(LocalPlayer.UserId) then return false end
        for _, p in pairs(Players:GetPlayers()) do
            if ${v.owner}(p.UserId) and p ~= LocalPlayer then
                ${v.notify}("⚠️ Cannot Load", "Owner in server", 3)
                return true
            end
        end
        return false
    end
    
    -- ============================================================
    -- HWID
    -- ============================================================
    local function ${v.hwid}()
        local h = "UNKNOWN"
        pcall(function()
            if gethwid then h = gethwid()
            elseif get_hwid then h = get_hwid()
            elseif getexecutorname then h = getexecutorname() .. "_" .. LocalPlayer.UserId
            else h = "FB_" .. LocalPlayer.UserId end
        end)
        return h
    end
    
    -- ============================================================
    -- HTTP BAN REPORT
    -- ============================================================
    local function ${v.http}(url, data)
        task.spawn(function()
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
    
    -- ============================================================
    -- KICK/BAN
    -- ============================================================
    local function ${v.kick}(reason, tools)
        _TOOL_CHECK_ACTIVE = false
        
        if BAN_ENDPOINT ~= "" then
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
        
        ${v.notify}("⛔ BANNED", reason, 2)
        task.wait(0.5)
        LocalPlayer:Kick("⛔ BANNED\\n\\n" .. reason .. "\\n\\nAppeal: Contact admin")
    end
    
    -- ============================================================
    -- 🔥 ENHANCED TOOL DETECTION - MULTI-LAYER
    -- ============================================================
    
    -- Tool signatures database
    local TOOL_SIGNATURES = {
        -- Names to detect
        names = {
            -- Explorers
            "dex", "dexv2", "dexv3", "dexv4", "dark dex", "darkdex",
            "remote spy", "remotespy", "simple spy", "simplespy",
            "hydroxide", "synspy",
            -- Commands
            "infinite yield", "infiniteyield", "iy", "cmd", "admin",
            -- Building
            "f3x", "building tools", "btool", "btools",
            -- Other
            "script dumper", "scriptdumper", "saveinstance",
            "aimbot", "esp", "noclip", "fly hack", "speed hack"
        },
        
        -- Partial matches (GUI yang mencurigakan)
        partials = {
            "spy", "exploit", "hack", "cheat", "inject", "dump",
            "executor", "script hub", "hub", "admin", "cmd"
        },
        
        -- Global variable names
        globals = {
            "Dex", "DexV4", "DarkDex", "RemoteSpy", "SimpleSpy",
            "Hydroxide", "InfiniteYield", "IY", "IYaliases",
            "F3X", "BTools", "Aimbot", "ESP", "Noclip"
        }
    }
    
    -- Method 1: Check _G table
    local function ${v.scan}_G()
        local found = {}
        pcall(function()
            for key, value in pairs(_G) do
                if type(key) == "string" then
                    local keyLower = string.lower(key)
                    
                    -- Check exact globals
                    for _, g in ipairs(TOOL_SIGNATURES.globals) do
                        if key == g or keyLower == string.lower(g) then
                            table.insert(found, {source = "_G", name = key, type = "exact"})
                        end
                    end
                    
                    -- Check name patterns
                    for _, name in ipairs(TOOL_SIGNATURES.names) do
                        if string.find(keyLower, string.lower(name), 1, true) then
                            table.insert(found, {source = "_G", name = key, type = "pattern"})
                        end
                    end
                end
            end
        end)
        return found
    end
    
    -- Method 2: Check getgenv
    local function ${v.scan}_getgenv()
        local found = {}
        pcall(function()
            if getgenv then
                for key, value in pairs(getgenv()) do
                    if type(key) == "string" then
                        local keyLower = string.lower(key)
                        
                        for _, g in ipairs(TOOL_SIGNATURES.globals) do
                            if key == g or keyLower == string.lower(g) then
                                table.insert(found, {source = "getgenv", name = key, type = "exact"})
                            end
                        end
                        
                        for _, name in ipairs(TOOL_SIGNATURES.names) do
                            if string.find(keyLower, string.lower(name), 1, true) then
                                table.insert(found, {source = "getgenv", name = key, type = "pattern"})
                            end
                        end
                    end
                end
            end
        end)
        return found
    end
    
    -- Method 3: Check CoreGui for suspicious GUIs
    local function ${v.scan}_CoreGui()
        local found = {}
        pcall(function()
            for _, gui in pairs(CoreGui:GetChildren()) do
                if gui:IsA("ScreenGui") or gui:IsA("Folder") then
                    local nameLower = string.lower(gui.Name)
                    
                    -- Skip Roblox default GUIs
                    if gui.Name == "RobloxGui" or gui.Name == "PlayerList" then
                        continue
                    end
                    
                    -- Check exact names
                    for _, name in ipairs(TOOL_SIGNATURES.names) do
                        if string.find(nameLower, string.lower(name), 1, true) then
                            table.insert(found, {source = "CoreGui", name = gui.Name, type = "gui"})
                            break
                        end
                    end
                    
                    -- Check partial matches
                    for _, partial in ipairs(TOOL_SIGNATURES.partials) do
                        if string.find(nameLower, partial, 1, true) then
                            table.insert(found, {source = "CoreGui", name = gui.Name, type = "partial"})
                            break
                        end
                    end
                    
                    -- Check descendants for suspicious names
                    pcall(function()
                        for _, desc in pairs(gui:GetDescendants()) do
                            if desc:IsA("TextLabel") or desc:IsA("TextButton") then
                                local textLower = string.lower(desc.Text or "")
                                for _, name in ipairs(TOOL_SIGNATURES.names) do
                                    if string.find(textLower, string.lower(name), 1, true) then
                                        table.insert(found, {
                                            source = "CoreGui", 
                                            name = gui.Name .. "/" .. desc.Name,
                                            type = "text_content"
                                        })
                                        break
                                    end
                                end
                            end
                        end
                    end)
                end
            end
        end)
        return found
    end
    
    -- Method 4: Check PlayerGui
    local function ${v.scan}_PlayerGui()
        local found = {}
        pcall(function()
            local playerGui = LocalPlayer:FindFirstChild("PlayerGui")
            if playerGui then
                for _, gui in pairs(playerGui:GetChildren()) do
                    if gui:IsA("ScreenGui") then
                        local nameLower = string.lower(gui.Name)
                        
                        for _, name in ipairs(TOOL_SIGNATURES.names) do
                            if string.find(nameLower, string.lower(name), 1, true) then
                                table.insert(found, {source = "PlayerGui", name = gui.Name, type = "gui"})
                                break
                            end
                        end
                    end
                end
            end
        end)
        return found
    end
    
    -- Method 5: Check for executor-specific functions that tools use
    local function ${v.scan}_Functions()
        local found = {}
        pcall(function()
            -- Check if certain functions exist that tools commonly create
            local suspiciousFuncs = {
                "Spy", "StartSpy", "StopSpy", "RemoteSpy",
                "DexExplore", "OpenDex", "CloseDex",
                "IYExecute", "RunCommand"
            }
            
            for _, funcName in ipairs(suspiciousFuncs) do
                if _G[funcName] or (getgenv and getgenv()[funcName]) then
                    table.insert(found, {source = "function", name = funcName, type = "func"})
                end
            end
        end)
        return found
    end
    
    -- Method 6: Monitor new GUIs being added (real-time detection)
    local function ${v.monitor}_NewGuis()
        pcall(function()
            CoreGui.ChildAdded:Connect(function(child)
                if not _TOOL_CHECK_ACTIVE then return end
                
                if child:IsA("ScreenGui") then
                    local nameLower = string.lower(child.Name)
                    
                    -- Skip known safe GUIs
                    if child.Name == "RobloxGui" or child.Name == "PlayerList" then
                        return
                    end
                    
                    -- Check against signatures
                    for _, name in ipairs(TOOL_SIGNATURES.names) do
                        if string.find(nameLower, string.lower(name), 1, true) then
                            print("[SECURITY] 🚨 Tool GUI detected:", child.Name)
                            ${v.kick}("Malicious tool detected: " .. child.Name, {child.Name})
                            return
                        end
                    end
                    
                    -- Check partials
                    for _, partial in ipairs(TOOL_SIGNATURES.partials) do
                        if string.find(nameLower, partial, 1, true) then
                            -- Give a small delay to check if it's legitimate
                            task.delay(0.5, function()
                                if not _TOOL_CHECK_ACTIVE then return end
                                if child.Parent then
                                    print("[SECURITY] 🚨 Suspicious GUI detected:", child.Name)
                                    ${v.kick}("Suspicious tool detected: " .. child.Name, {child.Name})
                                end
                            end)
                            return
                        end
                    end
                end
            end)
        end)
    end
    
    -- Method 7: Check for common tool tables/modules
    local function ${v.scan}_Tables()
        local found = {}
        pcall(function()
            -- Dex specific
            if _G.Dex or _G.DexV4 or _G.DarkDex then
                table.insert(found, {source = "table", name = "Dex", type = "tool_table"})
            end
            
            -- Infinite Yield specific
            if _G.IY or _G.InfiniteYield or _G.IYaliases then
                table.insert(found, {source = "table", name = "InfiniteYield", type = "tool_table"})
            end
            
            -- Remote Spy specific
            if _G.RemoteSpy or _G.SimpleSpy or _G.Hydroxide then
                table.insert(found, {source = "table", name = "Spy", type = "tool_table"})
            end
            
            -- Check shared table
            if shared then
                for key, _ in pairs(shared) do
                    if type(key) == "string" then
                        local keyLower = string.lower(key)
                        for _, name in ipairs(TOOL_SIGNATURES.names) do
                            if string.find(keyLower, string.lower(name), 1, true) then
                                table.insert(found, {source = "shared", name = key, type = "shared"})
                            end
                        end
                    end
                end
            end
        end)
        return found
    end
    
    -- MAIN DETECTION FUNCTION - Combines all methods
    local function ${v.detect}()
        local allFound = {}
        
        -- Run all scans
        for _, result in ipairs(${v.scan}_G()) do
            table.insert(allFound, result)
        end
        
        for _, result in ipairs(${v.scan}_getgenv()) do
            table.insert(allFound, result)
        end
        
        for _, result in ipairs(${v.scan}_CoreGui()) do
            table.insert(allFound, result)
        end
        
        for _, result in ipairs(${v.scan}_PlayerGui()) do
            table.insert(allFound, result)
        end
        
        for _, result in ipairs(${v.scan}_Functions()) do
            table.insert(allFound, result)
        end
        
        for _, result in ipairs(${v.scan}_Tables()) do
            table.insert(allFound, result)
        end
        
        -- Remove duplicates
        local seen = {}
        local unique = {}
        for _, item in ipairs(allFound) do
            local key = item.source .. "_" .. item.name
            if not seen[key] then
                seen[key] = true
                table.insert(unique, item)
            end
        end
        
        return unique
    end
    
    -- ============================================================
    -- DECRYPTION
    -- ============================================================
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
    
    -- ============================================================
    -- MAIN RUN
    -- ============================================================
    local function ${v.run}()
        -- Check owner presence
        if ${v.presence}() then return false end
        
        -- Skip tool detection for whitelisted users
        if not ${v.wl}() then
            -- Initial deep scan
            print("[SECURITY] 🔍 Running initial tool scan...")
            local detected = ${v.detect}()
            
            if #detected > 0 then
                local toolNames = {}
                for _, d in ipairs(detected) do
                    table.insert(toolNames, d.name)
                end
                print("[SECURITY] 🚨 Detected:", table.concat(toolNames, ", "))
                ${v.kick}("Tools detected: " .. detected[1].name, toolNames)
                return false
            end
            print("[SECURITY] ✅ Initial scan passed")
            
            -- Start real-time GUI monitoring
            ${v.monitor}_NewGuis()
            
            -- Periodic deep scan (every 5 seconds for first minute, then every 15 seconds)
            task.spawn(function()
                local scanCount = 0
                while _TOOL_CHECK_ACTIVE do
                    local interval = scanCount < 12 and 5 or 15
                    task.wait(interval)
                    
                    if not _TOOL_CHECK_ACTIVE then break end
                    
                    local detected = ${v.detect}()
                    if #detected > 0 then
                        local toolNames = {}
                        for _, d in ipairs(detected) do
                            table.insert(toolNames, d.name)
                        end
                        print("[SECURITY] 🚨 Runtime detection:", table.concat(toolNames, ", "))
                        ${v.kick}("Runtime tool: " .. detected[1].name, toolNames)
                        break
                    end
                    
                    scanCount = scanCount + 1
                end
            end)
        else
            print("[SECURITY] ✅ Whitelisted user, skipping tool checks")
        end
        
        -- Decode and execute
        local script = ${v.decode}()
        if not script or #script < 10 then
            ${v.notify}("❌ Error", "Failed to decode", 5)
            return false
        end
        
        local code = [[${protectionWrapper.replace(/\\/g, '\\\\').replace(/\[\[/g, '[\\[').replace(/\]\]/g, ']\\]').replace(/'/g, "\\'")}]] .. script
        
        local fn, err = loadstring(code)
        if fn then
            return pcall(fn)
        else
            warn("[LOADER] Error:", err)
            return false
        end
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
    randomString,
    xorEncrypt,
    generateSessionKey,
    generateChecksum
};
