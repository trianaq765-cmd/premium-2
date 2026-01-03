// ============================================================
// 🛡️ PROTECTION MODULE v4.3.0 - OWNER DETECTION
// ============================================================

const crypto = require('crypto');

function randomVar(prefix = '_') {
    return prefix + crypto.randomBytes(4).toString('hex');
}

function generateChecksum(script) {
    return crypto.createHash('sha256').update(script).digest('hex').substring(0, 16);
}

function generateProtectedScript(originalScript, options = {}) {
    const {
        sessionToken = crypto.randomBytes(16).toString('hex'),
        timestamp = Date.now(),
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
        loop: randomVar('_LP'),
        run: randomVar('_R'),
        owner: randomVar('_OW'),
        destroy: randomVar('_DS'),
        check: randomVar('_CK'),
        result: randomVar('_RS')
    };

    const scriptChunks = [];
    const chunkSize = 400;
    for (let i = 0; i < originalScript.length; i += chunkSize) {
        const chunk = originalScript.substring(i, i + chunkSize);
        const encoded = Buffer.from(chunk).toString('base64');
        scriptChunks.push(encoded);
    }

    const whitelistStr = whitelistUserIds.join(', ');
    const ownerStr = ownerUserIds.join(', ');

    const protectedScript = `-- Protected Script v4.3.0
local ${v.main} = (function()
    local game = game
    local pcall = pcall
    local type = type
    local table = table
    local string = string
    local tick = tick
    local wait = task and task.wait or wait
    local spawn = task and task.spawn or spawn
    local pairs = pairs
    local ipairs = ipairs
    local loadstring = loadstring
    local rawget = rawget
    
    local Players = game:GetService("Players")
    local HttpService = game:GetService("HttpService")
    local StarterGui = game:GetService("StarterGui")
    local CoreGui = game:GetService("CoreGui")
    local RunService = game:GetService("RunService")
    
    local LocalPlayer = Players.LocalPlayer
    local BAN_ENDPOINT = "${banEndpoint}"
    local HWID = nil
    
    local WHITELIST = {${whitelistStr}}
    local OWNER_IDS = {${ownerStr}}
    
    local SCRIPT_GUIS = {}
    local SCRIPT_CONNECTIONS = {}
    local SCRIPT_ACTIVE = true
    
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
    
    -- Destroy Function
    local function ${v.destroy}(reason)
        if not SCRIPT_ACTIVE then return end
        SCRIPT_ACTIVE = false
        
        print("[Script] Auto-destroying:", reason)
        
        for _, gui in pairs(SCRIPT_GUIS) do
            pcall(function()
                if gui and gui.Parent then gui:Destroy() end
            end)
        end
        
        for _, connection in pairs(SCRIPT_CONNECTIONS) do
            pcall(function()
                if connection then connection:Disconnect() end
            end)
        end
        
        SCRIPT_GUIS = {}
        SCRIPT_CONNECTIONS = {}
        
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⚠️ Script Disabled",
                Text = reason,
                Duration = 5
            })
        end)
        
        return "DESTROYED"
    end
    
    -- Owner Detection
    local function ${v.owner}()
        for _, player in pairs(Players:GetPlayers()) do
            if isOwner(player.UserId) and player ~= LocalPlayer then
                return true, player.Name
            end
        end
        return false, nil
    end
    
    local function ${v.check}()
        if isOwner(LocalPlayer.UserId) then
            print("[Script] You are the owner - Full access")
            return
        end
        
        spawn(function()
            local ownerPresent, ownerName = ${v.owner}()
            if ownerPresent then
                ${v.destroy}("Owner (" .. ownerName .. ") is in the server")
                return
            end
            
            local connection = Players.PlayerAdded:Connect(function(player)
                if isOwner(player.UserId) then
                    ${v.destroy}("Owner (" .. player.Name .. ") joined the server")
                end
            end)
            
            table.insert(SCRIPT_CONNECTIONS, connection)
            
            spawn(function()
                while SCRIPT_ACTIVE do
                    wait(10)
                    local present, name = ${v.owner}()
                    if present then
                        ${v.destroy}("Owner (" .. name .. ") detected")
                        break
                    end
                end
            end)
        end)
    end
    
    local function ${v.hwid}()
        if HWID then return HWID end
        pcall(function()
            HWID = (gethwid and gethwid()) or
                   (get_hwid and get_hwid()) or
                   ("EX_" .. tostring(LocalPlayer.UserId))
        end)
        return HWID or "UNKNOWN"
    end
    
    local function ${v.http}(url, data)
        pcall(function()
            local request = (syn and syn.request) or 
                           (http and http.request) or 
                           request or http_request
            if request then
                request({
                    Url = url,
                    Method = "POST",
                    Headers = {["Content-Type"] = "application/json"},
                    Body = HttpService:JSONEncode(data)
                })
            end
        end)
    end
    
    local function ${v.kick}(reason, toolsFound)
        pcall(function()
            if BAN_ENDPOINT and BAN_ENDPOINT ~= "" then
                ${v.http}(BAN_ENDPOINT, {
                    hwid = ${v.hwid}(),
                    playerId = LocalPlayer.UserId,
                    playerName = LocalPlayer.Name,
                    reason = reason,
                    toolsDetected = toolsFound or {}
                })
            end
        end)
        
        pcall(function()
            StarterGui:SetCore("SendNotification", {
                Title = "⛔ Banned",
                Text = reason,
                Duration = 5
            })
        end)
        
        wait(0.3)
        pcall(function()
            LocalPlayer:Kick("⛔ BANNED\\n\\n" .. reason)
        end)
    end
    
    local ${v.tools} = {
        _G_check = {
            "Dex", "DEX", "DexV2", "DexV3", "DexV4",
            "DarkDex", "DarkDexV3",
            "InfiniteYield", "Infinite_Yield", "IY_LOADED", "IY",
            "Hydroxide", "HydroxideUI",
            "SimpleSpy", "RemoteSpy",
            "BTool", "F3X"
        },
        gui_check = {
            "Dex", "DexV3", "DarkDex",
            "InfiniteYield", "IY",
            "Hydroxide", "SimpleSpy", "RemoteSpy",
            "BTool", "F3X"
        }
    }
    
    local function ${v.detect}()
        local detected = {}
        
        for _, name in ipairs(${v.tools}._G_check) do
            pcall(function()
                local val = rawget(_G, name)
                if val ~= nil and (type(val) == "table" or type(val) == "boolean") then
                    table.insert(detected, name)
                end
            end)
        end
        
        pcall(function()
            if getgenv then
                local genv = getgenv()
                for _, name in ipairs(${v.tools}._G_check) do
                    local val = rawget(genv, name)
                    if val ~= nil and (type(val) == "table" or type(val) == "boolean") then
                        if not table.find(detected, name) then
                            table.insert(detected, name)
                        end
                    end
                end
            end
        end)
        
        pcall(function()
            for _, guiName in ipairs(${v.tools}.gui_check) do
                if CoreGui:FindFirstChild(guiName) or CoreGui:FindFirstChild(guiName, true) then
                    local n = guiName .. "_UI"
                    if not table.find(detected, n) then
                        table.insert(detected, n)
                    end
                end
            end
        end)
        
        pcall(function()
            if LocalPlayer and LocalPlayer.PlayerGui then
                for _, guiName in ipairs(${v.tools}.gui_check) do
                    if LocalPlayer.PlayerGui:FindFirstChild(guiName, true) then
                        local n = guiName .. "_GUI"
                        if not table.find(detected, n) then
                            table.insert(detected, n)
                        end
                    end
                end
            end
        end)
        
        pcall(function()
            if shared then
                if shared.IYPrefix or shared.InfiniteYield or shared.IY then
                    table.insert(detected, "IY_Shared")
                end
                if shared.Hydroxide then
                    table.insert(detected, "Hydroxide_Shared")
                end
            end
        end)
        
        return detected
    end
    
    local ${v.chunks} = {
        ${scriptChunks.map((chunk, i) => `[${i + 1}] = "${chunk}"`).join(',\n        ')}
    }
    
    local function ${v.decode}()
        local decoded = {}
        local b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        
        for i, chunk in ipairs(${v.chunks}) do
            pcall(function()
                chunk = string.gsub(chunk, '[^'..b64..'=]', '')
                decoded[i] = (chunk:gsub('.', function(x)
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
        
        return table.concat(decoded)
    end
    
    local function ${v.run}()
        if isWhitelisted() then
            print("[Script] Whitelisted - Bypassing protection")
        else
            local toolsFound = ${v.detect}()
            if #toolsFound > 0 then
                local toolList = table.concat(toolsFound, ", ")
                ${v.kick}("Tools detected: " .. toolList, toolsFound)
                return false
            end
        end
        
        ${v.check}()
        
        local scriptContent = ${v.decode}()
        
        if scriptContent and #scriptContent > 0 then
            local loader = loadstring or load
            if not loader then return false end
            
            local fn, err = loader(scriptContent)
            if not fn then
                warn("[Protection] Compile error:", err)
                return false
            end
            
            local success, result = pcall(fn)
            if not success then
                warn("[Protection] Runtime error:", result)
            end
            
            return success
        end
        
        return false
    end
    
    local function ${v.loop}()
        if isWhitelisted() then return end
        spawn(function()
            while SCRIPT_ACTIVE do
                wait(10)
                local toolsFound = ${v.detect}()
                if #toolsFound > 0 then
                    ${v.kick}("Runtime: " .. table.concat(toolsFound, ", "), toolsFound)
                    break
                end
            end
        end)
    end
    
    ${v.loop}()
    return ${v.run}
end)()

local ${v.result} = ${v.main} and ${v.main}()
${v.main} = nil
pcall(function() collectgarbage("count") end)
`;

    return protectedScript;
}

module.exports = {
    generateProtectedScript,
    generateChecksum,
    randomVar
};
