-- API Key Authentication for Apache mod_lua
-- Validates X-API-Key header OR api_key query parameter against keys in a file
-- Called via LuaHookAccessChecker in CLIENTAPIKEY macro

-- Cache for loaded keys (per-request, not persistent)
local key_cache = {}

-- Load keys from file (one key per line, # comments allowed)
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
        -- Trim whitespace
        line = line:match("^%s*(.-)%s*$")
        -- Skip empty lines and comments
        if line ~= "" and not line:match("^#") then
            keys[line] = true
        end
    end
    file:close()
    
    key_cache[filepath] = keys
    return keys
end

-- Parse query string to get api_key parameter
local function get_query_param(query_string, param_name)
    if not query_string then return nil end
    for key, value in query_string:gmatch("([^&=]+)=([^&]*)") do
        if key == param_name then
            return value
        end
    end
    return nil
end

-- Apache hook: check API key (GLOBAL function for mod_lua)
function check_apikey(r)
    -- Derive key file path from ServerName (sitename.domain -> sitename)
    local servername = r.server_name or ""
    local sitename = servername:match("^([^.]+)") or "default"
    local keyfile = "/etc/apache2/config/apikeys/" .. sitename .. ".keys"
    
    -- Get the API key from header OR query parameter
    local apikey = r.headers_in["X-API-Key"]
    if not apikey then
        -- Try query parameter as fallback (for clients that cannot send headers)
        apikey = get_query_param(r.args, "api_key")
    end
    
    if not apikey then
        -- No API key provided - let RequireAny handle it
        return apache2.DECLINED
    end
    
    -- Load and check keys
    local valid_keys = load_keys(keyfile)
    if valid_keys[apikey] then
        -- Set environment variable for Require env directive
        r.subprocess_env["ValidAPIKey"] = "1"
        return apache2.DECLINED  -- Continue processing
    end
    
    -- Invalid key - log and decline (let RequireAny deny)
    r:warn("Invalid API key from " .. (r.useragent_ip or "unknown") .. " for " .. servername)
    return apache2.DECLINED
end
