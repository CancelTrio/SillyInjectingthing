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

-- Categories
local CATEGORIES = {
    MALICIOUS = "MALICIOUS",
    SUSPICIOUS = "SUSPICIOUS", 
    BACKDOORED_FUNC = "BACKDOORED_FUNC",
    INFECTED_SCRIPT = "INFECTED_SCRIPT",
    NORMAL = "NORMAL"
}

-- Logging
local function _log(msg, level)
    level = level or "INFO"
    print(string.format("[PanScript %s] %s", level, msg))
end

-- Get color for category
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

-- Malicious patterns
local MALICIOUS_PATTERNS = {
    "loadstring", "game:HttpGet", "http.request", "syn.request",
    "setclipboard", "keylogger", "steal", "grab", "webhook",
    "getgenv", "getrawmetatable", "hookfunction", "replaceclosure",
    "writefile", "appendfile", "makefolder", "delfile",
    "islclosure", "checkcaller", "getconnections", "firesignal"
}

-- Suspicious patterns
local SUSPICIOUS_PATTERNS = {
    "require", "spawn", "pcall", "xpcall", "coroutine",
    "while true do", "repeat until", "for.*do.*end"
}

-- Get script source
local function _getSource(obj)
    if not obj then return nil end
    local s, r = pcall(function()
        if obj:IsA("LocalScript") or obj:IsA("ModuleScript") then
            -- Try to get source
            if obj.Source then return obj.Source end
        end
        return nil
    end)
    if s then return r end
    return nil
end

-- Analyze script for backdoors
local function _analyzeScript(obj)
    local source = _getSource(obj)
    if not source then 
        return {Category = CATEGORIES.NORMAL, Confidence = 0, Path = obj:GetFullName()}
    end
    
    local score = 0
    local reasons = {}
    
    -- Check malicious patterns
    if _hasPattern(source, MALICIOUS_PATTERNS) then
        score = score + 40
        table.insert(reasons, "Malicious patterns detected")
    end
    
    -- Check suspicious patterns
    if _hasPattern(source, SUSPICIOUS_PATTERNS) then
        score = score + 20
        table.insert(reasons, "Suspicious patterns detected")
    end
    
    -- Check for obfuscation
    if string.len(source) > 5000 and string.find(source, "[%z\001-\008\011-\012\014-\031]") then
        score = score + 30
        table.insert(reasons, "Possible obfuscation")
    end
    
    -- Network activity
    if string.find(source, "http") or string.find(source, "request") then
        score = score + 25
        table.insert(reasons, "Network activity")
    end
    
    -- Determine category
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

-- Scan all scripts
function _bs.Scan()
    _log("Starting backdoor scan...", "SCAN")
    local found = {}
    local normalCount = 0
    
    local function scanContainer(container, depth)
        if depth > 10 then return end -- Prevent infinite recursion
        
        for _, child in ipairs(container:GetChildren()) do
            if child:IsA("LocalScript") or child:IsA("ModuleScript") then
                local result = _analyzeScript(child)
                
                if result.Category ~= CATEGORIES.NORMAL then
                    table.insert(found, result)
                    _storage.detectedBackdoors[result.Path] = result
                    _log(string.format("Found %s: %s (%d%% confidence)", result.Category, result.Path, result.Confidence), "DETECT")
                else
                    normalCount = normalCount + 1
                end
            end
            
            -- Scan children
            if #child:GetChildren() > 0 then
                scanContainer(child, depth + 1)
            end
            
            -- Scan descendants that are scripts
            for _, desc in ipairs(child:GetDescendants()) do
                if desc:IsA("LocalScript") or desc:IsA("ModuleScript") then
                    local result = _analyzeScript(desc)
                    if result.Category ~= CATEGORIES.NORMAL then
                        table.insert(found, result)
                        _storage.detectedBackdoors[result.Path] = result
                    else
                        normalCount = normalCount + 1
                    end
                end
            end
        end
    end
    
    -- Scan common locations
    local locations = {
        game:GetService("Players"),
        game:GetService("ReplicatedStorage"),
        game:GetService("StarterPlayer"),
        game:GetService("StarterGui"),
        game:GetService("StarterPack"),
        game:GetService("Workspace")
    }
    
    for _, loc in ipairs(locations) do
        pcall(function() scanContainer(loc, 0) end)
    end
    
    _log(string.format("Scan complete. Found %d suspicious items, %d normal", #found, normalCount), "SCAN")
    return #found > 0, normalCount, found
end

-- Get all detected backdoors
function _bs.GetAllDetected()
    local all = {}
    for _, bd in pairs(_storage.detectedBackdoors) do
        table.insert(all, bd)
    end
    
    -- Sort by confidence (highest first)
    table.sort(all, function(a, b) return a.Confidence > b.Confidence end)
    
    return all
end

-- Execute backdoor
function _bs.ActivateSpecific(path, category)
    _log(string.format("Activating backdoor: %s [%s]", path, category), "EXEC")
    
    local bd = _storage.detectedBackdoors[path]
    if not bd then
        return false, "Backdoor not found in storage"
    end
    
    -- Try to get the actual object
    local obj = bd.Object
    if not obj or not obj.Parent then
        -- Try to find it again
        local parts = string.split(path, ".")
        obj = game
        for _, part in ipairs(parts) do
            if obj then
                obj = obj:FindFirstChild(part)
            end
        end
    end
    
    if not obj then
        return false, "Object no longer exists"
    end
    
    -- Execute based on type
    local success, result = pcall(function()
        if category == CATEGORIES.MALICIOUS or category == CATEGORIES.BACKDOORED_FUNC then
            -- Try to require if it's a module
            if obj:IsA("ModuleScript") then
                local mod = require(obj)
                if type(mod) == "function" then
                    return mod()
                elseif type(mod) == "table" then
                    -- Look for common backdoor function names
                    for name, func in pairs(mod) do
                        if type(func) == "function" and (
                            string.find(name:lower(), "backdoor") or
                            string.find(name:lower(), "exec") or
                            string.find(name:lower(), "run") or
                            string.find(name:lower(), "load")
                        ) then
                            return func()
                        end
                    end
                end
            end
            
            -- Try to get source and loadstring
            local source = _getSource(obj)
            if source and string.len(source) > 0 then
                local fn, err = loadstring(source)
                if fn then
                    return fn()
                else
                    error("Loadstring failed: " .. tostring(err))
                end
            end
            
        elseif category == CATEGORIES.SUSPICIOUS then
            -- Safer execution for suspicious items
            _log("Suspicious item - manual review recommended", "WARN")
            return "Suspicious - manual execution required"
            
        elseif category == CATEGORIES.INFECTED_SCRIPT then
            -- Try to clean/execute
            _log("Attempting to execute infected script", "EXEC")
            local source = _getSource(obj)
            if source then
                local fn = loadstring(source)
                if fn then return fn() end
            end
        end
        
        return "No execution method available"
    end)
    
    if success then
        _log("Execution successful", "SUCCESS")
        return true, result
    else
        _log("Execution failed: " .. tostring(result), "ERROR")
        return false, tostring(result)
    end
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
    
    -- Main Frame
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
    
    -- Title
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
    
    -- Note
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
    
    -- Scrolling Frame
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
    
    -- Create buttons
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
    
    -- Buttons
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
    
    -- Handlers
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

-- Scan with internal GUI fallback
function _bs.ScanWithManager(useInternal)
    local found, normalCount, backdoors = _bs.Scan()
    
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

-- Auto-scan on load
spawn(function()
    wait(2)
    _bs.Scan()
end)

return _bs
