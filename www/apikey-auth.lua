-- API Key Authentication for Apache mod_lua
-- Validates X-API-Key header against keys in a file
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

-- Apache hook: check API key (GLOBAL function for mod_lua)
function check_apikey(r)
    -- Get the API key file path from environment
    local keyfile = r.subprocess_env["APIKEY_FILE"]
    if not keyfile then
        r:err("APIKEY_FILE environment variable not set")
        return apache2.DECLINED
    end
    
    -- Get the X-API-Key header
    local apikey = r.headers_in["X-API-Key"]
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
    r:warn("Invalid API key from " .. (r.useragent_ip or "unknown"))
    return apache2.DECLINED
end
