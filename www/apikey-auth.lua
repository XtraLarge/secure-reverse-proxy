-- API Key Authentication for Apache mod_lua
-- Validates X-API-Key header OR api_key query parameter against keys in a file

local key_cache = {}

local function load_keys(filepath)
    if key_cache[filepath] then
        return key_cache[filepath]
    end
    
    local keys = {}
    local file = io.open(filepath, "r")
    if not file then
        return keys
    end
    
    for line in file:lines() do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and not line:match("^#") then
            keys[line] = true
        end
    end
    file:close()
    
    key_cache[filepath] = keys
    return keys
end

-- Helper: extract query parameter
local function get_query_param(args, name)
    if not args then return nil end
    for param in args:gmatch("[^&]+") do
        local k, v = param:match("^([^=]+)=(.*)$")
        if k == name then
            return v
        end
    end
    return nil
end

-- Apache hook: check API key (GLOBAL function for mod_lua)
function check_apikey(r)
    local servername = r.server_name or ""
    local sitename = servername:match("^([^.]+)") or "default"
    local keyfile = "/etc/apache2/config/apikeys/" .. sitename .. ".keys"
    
    -- Get API key from header OR query parameter
    local apikey = r.headers_in["X-API-Key"]
    if not apikey then
        apikey = get_query_param(r.args, "api_key")
    end
    
    if not apikey then
        return apache2.DECLINED
    end
    
    local valid_keys = load_keys(keyfile)
    if valid_keys[apikey] then
        r.subprocess_env["ValidAPIKey"] = "1"
        return apache2.DECLINED
    end
    
    r:warn("Invalid API key from " .. (r.useragent_ip or "unknown") .. " for " .. servername)
    return apache2.DECLINED
end
