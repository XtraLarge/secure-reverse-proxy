--
-- admin-kc.lua — Keycloak User & Role Management
--
-- Served from admin.DOMAIN/admin-kc.lua (via Admin_VHost macro, AddHandler lua-script .lua).
-- The logged-in admin's OIDC access_token is forwarded to the Keycloak Admin REST API.
-- No separate service account needed — the admin's own Keycloak roles determine access.
--
-- ── Required Keycloak setup ────────────────────────────────────────────────────
--
-- In Keycloak: Clients → <your-proxy-client> → Service Account Roles  (not needed here)
-- Instead: the *admin user* must have client roles from "realm-management":
--   • view-users          (list and view users)
--   • manage-users        (create, update, delete users + set passwords)
--   • query-roles         (list realm roles)
--
-- To assign these roles in Keycloak:
--   Users → <admin user> → Role Mappings → Client Roles → realm-management → Add above roles
--
-- Additionally, the Proxy client must include these roles in the access token.
-- In Keycloak: Clients → <proxy client> → Client Scopes → (dedicated scope) →
--   Mappers → Add Mapper → "User Client Role" → Client ID: realm-management → Token Claim Name: e.g. "realm_roles"
-- OR: use the built-in "roles" scope which already includes client roles.
--
-- ── Environment variables (set via entrypoint.sh) ─────────────────────────────
--
--   KEYCLOAK_ADMIN_URL    Full Keycloak Admin REST API URL including realm, e.g.
--                         https://iam.example.com/admin/realms/master
--                         Auto-derived from OIDC_PROVIDER_METADATA_URL if not set.
--   KEYCLOAK_ROLE_PREFIX  Only show/manage roles whose name starts with this prefix.
--                         Example: "proxy-" shows only "proxy-admin", "proxy-viewer" etc.
--                         Empty (default) = show all realm roles.
--

local KC_URL    = os.getenv("KEYCLOAK_ADMIN_URL") or ""
local KC_PREFIX = os.getenv("KEYCLOAK_ROLE_PREFIX") or ""

-- ── Minimal JSON decoder ──────────────────────────────────────────────────────
-- Handles all structures returned by the Keycloak Admin API
-- (arrays, objects, strings, numbers, booleans, null).

local function json_decode(s)
  if not s or s == "" then return nil end
  local i = 1

  local function skip()
    while i <= #s and s:sub(i,i):match("%s") do i = i + 1 end
  end

  local parse_val
  parse_val = function()
    skip()
    if i > #s then return nil end
    local c = s:sub(i,i)

    if c == '"' then
      -- String
      i = i + 1
      local t = {}
      while i <= #s do
        local ch = s:sub(i,i)
        if ch == '\\' then
          i = i + 1
          local e = s:sub(i,i)
          if e == 'u' then
            t[#t+1] = "?"   -- simplified unicode (not needed for user data)
            i = i + 4
          else
            local esc = { n="\n", t="\t", r="\r", ["\\"]="\\", ['"']='"', ["/"]=("/"), b="\b", f="\f" }
            t[#t+1] = esc[e] or e
          end
        elseif ch == '"' then
          i = i + 1
          return table.concat(t)
        else
          t[#t+1] = ch
        end
        i = i + 1
      end
      return ""

    elseif c == '{' then
      -- Object
      local obj = {}
      i = i + 1
      while true do
        skip()
        if i > #s or s:sub(i,i) == '}' then i = i + 1; break end
        if s:sub(i,i) == ',' then i = i + 1 end
        skip()
        local k = parse_val()
        skip()
        if i <= #s and s:sub(i,i) == ':' then i = i + 1 end
        if k ~= nil then obj[k] = parse_val() end
      end
      return obj

    elseif c == '[' then
      -- Array
      local arr = {}
      i = i + 1
      while true do
        skip()
        if i > #s or s:sub(i,i) == ']' then i = i + 1; break end
        if s:sub(i,i) == ',' then
          i = i + 1
        else
          arr[#arr+1] = parse_val()
        end
      end
      return arr

    elseif s:sub(i, i+3) == 'true'  then i = i + 4; return true
    elseif s:sub(i, i+4) == 'false' then i = i + 5; return false
    elseif s:sub(i, i+3) == 'null'  then i = i + 4; return nil
    else
      local n = s:match("^-?%d+%.?%d*[eE]?[+-]?%d*", i)
      if n then i = i + #n; return tonumber(n) end
      i = i + 1; return nil
    end
  end

  local ok, result = pcall(parse_val)
  return ok and result or nil
end

-- ── Minimal JSON encoder ──────────────────────────────────────────────────────

local function json_encode(v)
  local t = type(v)
  if     t == "nil"     then return "null"
  elseif t == "boolean" then return tostring(v)
  elseif t == "number"  then return tostring(v)
  elseif t == "string"  then
    return '"' .. v:gsub('\\','\\\\'):gsub('"','\\"'):gsub('\n','\\n'):gsub('\r','\\r'):gsub('\t','\\t') .. '"'
  elseif t == "table" then
    -- Distinguish array (sequential integer keys) from object
    local n = #v
    if n > 0 then
      local p = {}
      for _, item in ipairs(v) do p[#p+1] = json_encode(item) end
      return "[" .. table.concat(p, ",") .. "]"
    else
      local p = {}
      for k, val in pairs(v) do
        p[#p+1] = json_encode(tostring(k)) .. ":" .. json_encode(val)
      end
      return "{" .. table.concat(p, ",") .. "}"
    end
  end
  return "null"
end

-- ── Keycloak Admin REST API ───────────────────────────────────────────────────
--
-- All calls use the logged-in admin's access_token as Bearer token.
-- curl is used for HTTP (including HTTPS with -k for self-signed certs).
-- The token is written to a tmpfile to avoid shell injection.

local function kc_call(method, path, body, token)
  -- Auth header in tmpfile — JWT tokens are base64url and safe,
  -- but tmpfile avoids any risk from unusually formed tokens.
  local auth_tmp = os.tmpname()
  do
    local f = io.open(auth_tmp, "w")
    if f then f:write("Authorization: Bearer " .. token); f:close() end
  end

  local data_tmp = nil
  local data_arg = ""
  if body then
    data_tmp = os.tmpname()
    local f = io.open(data_tmp, "w")
    if f then f:write(body); f:close() end
    data_arg = "--data @" .. data_tmp .. " "
  end

  -- -k: skip TLS verification (Keycloak may use a self-signed cert on internal network)
  -- -s: silent (no progress bar)
  -- -w "\n%{http_code}": append HTTP status code as last line of output
  local cmd = string.format(
    'curl -s -k -w "\\n%%{http_code}" -X %s '
    .. '-H @%s -H "Content-Type: application/json" -H "Accept: application/json" '
    .. '%s"%s%s" 2>/dev/null',
    method, auth_tmp, data_arg, KC_URL, path
  )

  local p = io.popen(cmd)
  local out = p:read("*a")
  p:close()
  os.remove(auth_tmp)
  if data_tmp then os.remove(data_tmp) end

  -- Status code is the last line; response body is everything before it
  local body_out  = out:match("^(.*)\n%d+%s*$") or ""
  local status    = tonumber(out:match("\n(%d+)%s*$")) or 0
  return status, body_out
end

local function kc_get(path, token)    return kc_call("GET",    path, nil,  token) end
local function kc_post(path, b, tok)  return kc_call("POST",   path, b,    tok)   end
local function kc_put(path, b, tok)   return kc_call("PUT",    path, b,    tok)   end
local function kc_delete(path, b, tok) return kc_call("DELETE", path, b,   tok)   end

-- ── HTML helpers ──────────────────────────────────────────────────────────────

-- HTML-escape a value for output
local function h(s)
  return tostring(s or ""):gsub("&","&amp;"):gsub("<","&lt;"):gsub(">","&gt;"):gsub('"','&quot;')
end

-- URL-encode a string (for use in query parameters / redirect targets)
local function ue(s)
  return tostring(s or ""):gsub("([^A-Za-z0-9_%.~%-])", function(c)
    return string.format("%%%02X", string.byte(c))
  end)
end

local CSS = [[<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d0d1a;color:#ddd;min-height:100vh}
.topbar{display:flex;align-items:center;justify-content:space-between;
  background:#060614;border-bottom:1px solid #2a2a4e;
  padding:.6em 1.2em;flex-wrap:wrap;gap:.5em}
.topbar-title{color:#00d4ff;font-size:1.1em;font-weight:bold;text-decoration:none}
.topbar-nav{display:flex;gap:.5em}
.topbar-nav a{color:#7ecfff;text-decoration:none;font-size:.85em;
  border:1px solid #2a2a4e;border-radius:3px;padding:3px 10px;
  background:#0a0a22;transition:background .15s}
.topbar-nav a:hover,.topbar-nav a.active{background:#0f3460;color:#00d4ff}
.main{padding:1.2em;max-width:1100px}
h2{color:#7ecfff;font-size:1em;margin:0 0 .6em;border-bottom:1px solid #2a2a4e;padding-bottom:.3em}
h3{color:#aaa;font-size:.9em;margin:.8em 0 .4em;font-weight:normal}
table{border-collapse:collapse;width:100%;font-size:.88em}
th{background:#0f3460;color:#00d4ff;padding:6px 10px;text-align:left;white-space:nowrap}
td{padding:5px 10px;border-bottom:1px solid #1a1a3e;vertical-align:middle}
tr:hover td{background:#111130}
.card{background:#0a0a22;border:1px solid #2a2a4e;border-radius:5px;
  padding:1em;margin-bottom:1.3em}
a.btn,button.btn{padding:4px 11px;border:none;border-radius:3px;cursor:pointer;
  text-decoration:none;display:inline-block;font-size:.82em;line-height:1.5}
.b-edit{background:#0f3460;color:#7ecfff}
.b-del{background:#5c0000;color:#ff9999}
.b-add{background:#003d00;color:#99ff99}
.b-save{background:#003d3d;color:#99ffff}
.b-warn{background:#3d3d00;color:#ffff99}
.b-cancel{background:#2a2a4e;color:#aaa}
.b-dis{background:#3d1a00;color:#ff9966}
.form-row{margin:.55em 0;display:flex;align-items:center;gap:.7em}
.form-row label{width:165px;color:#aaa;flex-shrink:0;font-size:.9em}
.form-row input{background:#060614;color:#ddd;border:1px solid #3a3a6e;
  padding:5px 8px;border-radius:3px;flex:1;min-width:0;font-size:.9em}
.form-row input:focus{outline:none;border-color:#00d4ff}
.hint{color:#666;font-size:.8em;margin:.3em 0 .6em}
.msg{padding:.5em .8em;border-radius:3px;margin-bottom:.8em;font-size:.9em}
.ok{background:#003d00;color:#99ff99}.err{background:#3d0000;color:#ff9999}
.warn{background:#2a2600;color:#ffe066}
.actions{display:flex;gap:.4em;flex-wrap:nowrap;align-items:center}
.tag{font-size:.75em;padding:2px 7px;border-radius:3px;white-space:nowrap}
.tag-en{background:#003d00;color:#99ff99}
.tag-dis{background:#3d0000;color:#ff9999}
.role-grid{display:flex;flex-wrap:wrap;gap:.35em .9em;margin:.4em 0 .8em}
.role-item{display:flex;align-items:center;gap:.35em;font-size:.87em;
  padding:3px 8px;background:#0a0a1e;border:1px solid #1a1a3e;border-radius:3px}
.role-item input[type=checkbox]{width:15px;height:15px;cursor:pointer;accent-color:#00d4ff;flex-shrink:0}
.role-item.checked{border-color:#0f3460;background:#040422}
input[type=search],input[type=text].search{background:#060614;color:#ddd;
  border:1px solid #3a3a6e;padding:5px 8px;border-radius:3px;font-size:.9em}
.toolbar{display:flex;gap:.7em;align-items:center;margin-bottom:1em;flex-wrap:wrap}
.section-note{color:#666;font-size:.8em;margin:.2em 0 .7em;font-style:italic}
.user-header{display:flex;align-items:baseline;gap:.7em;margin-bottom:.3em;flex-wrap:wrap}
.user-header h2{margin:0;border:none;padding:0}
code{background:#060614;color:#aaa;padding:1px 5px;border-radius:2px;font-size:.85em}
</style>]]

-- Detect the domain from config files (for TOC/Logout links in topbar)
local TOC_DOMAIN = ""
do
  local p = io.popen("ls /etc/apache2/sites-admin/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | head -1")
  if p then
    local f = p:read("*l") or ""
    p:close()
    TOC_DOMAIN = f:match("([^/]+)%.conf$") or ""
  end
end

local function topbar(active)
  local toc = TOC_DOMAIN ~= "" and ("https://toc." .. TOC_DOMAIN) or "/"
  local out = TOC_DOMAIN ~= "" and ("https://logout." .. TOC_DOMAIN) or "/logout"
  local function nav(href, label, key)
    local cls = active == key and ' class="active"' or ''
    return '<a href="' .. href .. '"' .. cls .. '>' .. label .. '</a>'
  end
  return '<div class="topbar">'
    .. '<a class="topbar-title" href="/admin-kc.lua">\xF0\x9F\x91\xA4 Keycloak Benutzer</a>'
    .. '<div class="topbar-nav">'
    .. nav("/admin-kc.lua",         "\xF0\x9F\x91\xA5 Benutzerliste",   "list")
    .. nav("/admin-kc.lua?action=new", "+ Neuer Benutzer",                "new")
    .. nav("/",                     "\xE2\x9A\x99 VHosts",              "vhosts")
    .. nav(h(toc),                  "\xE2\x98\xB0 TOC",                 "toc")
    .. nav(h(out),                  "\xC3\x97 Logout",                  "logout")
    .. '</div></div>'
end

local function page_head(title, active)
  return "<!DOCTYPE html><html lang=de><head><meta charset=UTF-8>"
    .. "<meta name=viewport content='width=device-width,initial-scale=1'>"
    .. "<title>" .. h(title) .. " — Keycloak</title>"
    .. CSS .. "</head><body>" .. topbar(active)
end

local function msg_html(txt)
  if not txt or txt == "" then return "" end
  local cls = txt:sub(1,3) == "ERR" and "err" or "ok"
  return '<div class="msg ' .. cls .. '">' .. h(txt) .. '</div>'
end

-- ── Keycloak role helpers ─────────────────────────────────────────────────────

-- Returns all realm roles, filtered by KC_PREFIX (if set).
-- Each entry is a table: {id="...", name="...", description="..."}
local function get_all_roles(token)
  local status, body = kc_get("/roles?max=500", token)
  if status ~= 200 then return {}, status end
  local roles = json_decode(body) or {}
  if KC_PREFIX == "" then return roles, 200 end
  local filtered = {}
  for _, role in ipairs(roles) do
    if type(role) == "table" and role.name and role.name:sub(1, #KC_PREFIX) == KC_PREFIX then
      filtered[#filtered+1] = role
    end
  end
  return filtered, 200
end

-- Returns a set of role IDs currently assigned to a user: {role_id = role_name, ...}
local function get_user_roles(uid, token)
  local status, body = kc_get("/users/" .. uid .. "/role-mappings/realm", token)
  if status ~= 200 then return {} end
  local roles = json_decode(body) or {}
  local set = {}
  for _, role in ipairs(roles) do
    if type(role) == "table" and role.id then
      set[role.id] = role.name or ""
    end
  end
  return set
end

-- ── View: User list ───────────────────────────────────────────────────────────

local function show_user_list(r, token, msg)
  local args   = r:parseargs()
  local search = args.q or ""

  local path = "/users?max=100"
  if search ~= "" then path = path .. "&search=" .. ue(search) end

  local status, body = kc_get(path, token)
  local users = {}
  if status == 200 then users = json_decode(body) or {} end

  r:puts(page_head("Benutzerliste", "list"))
  r:puts('<div class="main">')
  r:puts(msg_html(msg))

  -- API access error
  if status == 403 then
    r:puts('<div class="msg err"><strong>Zugriff verweigert (HTTP 403)</strong><br><br>')
    r:puts('Der aktuelle Keycloak-Token hat keine <code>view-users</code>-Berechtigung.<br><br>')
    r:puts('Lösung: In Keycloak → Users → &lt;Admin-User&gt; → Role Mappings →<br>')
    r:puts('Client Roles → <code>realm-management</code> → Roles hinzufügen:<br>')
    r:puts('<code>view-users</code>, <code>manage-users</code>, <code>query-roles</code><br><br>')
    r:puts('Danach neu anmelden (Session erneuern), damit der Token die neuen Rollen enthält.')
    r:puts('</div></div></body></html>')
    return apache2.OK
  elseif status ~= 200 and status ~= 0 then
    r:puts('<div class="msg err">Keycloak-API-Fehler (HTTP ' .. tostring(status) .. ')</div>')
    r:puts('</div></body></html>')
    return apache2.OK
  elseif status == 0 then
    r:puts('<div class="msg err"><strong>Keycloak nicht erreichbar</strong><br><br>')
    r:puts('URL: <code>' .. h(KC_URL) .. '</code><br>')
    r:puts('Prüfe ob der Container Keycloak erreicht (extra_hosts / DNS).')
    r:puts('</div></div></body></html>')
    return apache2.OK
  end

  -- Toolbar: search + new user button
  r:puts('<div class="toolbar">')
  r:puts('<form method="GET" style="display:flex;gap:.4em">')
  r:puts('<input type="search" name="q" value="' .. h(search) .. '" placeholder="Suche nach Name, E-Mail, Username…" style="width:280px">')
  r:puts('<button class="btn b-edit" type="submit">Suchen</button>')
  if search ~= "" then r:puts('<a class="btn b-cancel" href="/admin-kc.lua">Zurücksetzen</a>') end
  r:puts('</form>')
  r:puts('<a class="btn b-add" href="?action=new">+ Neuer Benutzer</a>')
  r:puts('</div>')

  r:puts('<div class="card">')
  r:puts('<h2>Benutzer (' .. #users .. (search ~= "" and ', gefiltert' or '') .. ')</h2>')

  if #users == 0 then
    r:puts('<p class="hint">Keine Benutzer gefunden.</p>')
  else
    r:puts('<table>')
    r:puts('<tr><th>Benutzername</th><th>Name</th><th>E-Mail</th><th>Status</th><th>Aktionen</th></tr>')
    for _, u in ipairs(users) do
      if type(u) ~= "table" then goto next_user end
      local uid   = u.id or ""
      local uname = u.username or ""
      local email = u.email or ""
      local first = u.firstName or ""
      local last  = u.lastName  or ""
      local full  = ((first .. " " .. last):match("^%s*(.-)%s*$"))
      local en    = u.enabled
      local stag  = en
        and '<span class="tag tag-en">aktiv</span>'
        or  '<span class="tag tag-dis">gesperrt</span>'

      r:puts('<tr>')
      r:puts('<td><a href="?action=user&id=' .. h(uid) .. '" style="color:#7ecfff">' .. h(uname) .. '</a></td>')
      r:puts('<td>' .. h(full) .. '</td>')
      r:puts('<td>' .. h(email) .. '</td>')
      r:puts('<td>' .. stag .. '</td>')
      r:puts('<td class="actions">')
      r:puts('<a class="btn b-edit" href="?action=user&id=' .. h(uid) .. '">Bearbeiten</a>')
      r:puts('</td></tr>')
      ::next_user::
    end
    r:puts('</table>')
  end

  if #users == 100 then
    r:puts('<p class="hint" style="margin-top:.5em">Maximal 100 Einträge angezeigt — Suche verwenden um einzugrenzen.</p>')
  end
  r:puts('</div></div></body></html>')
  return apache2.OK
end

-- ── View: User detail ─────────────────────────────────────────────────────────

local function show_user_detail(r, uid, token, msg)
  -- Load user data
  local su, bu = kc_get("/users/" .. uid, token)
  if su == 404 then
    r:puts(page_head("Benutzer", "list"))
    r:puts('<div class="main"><div class="msg err">Benutzer nicht gefunden (ggf. gelöscht).</div>')
    r:puts('<a class="btn b-cancel" href="/admin-kc.lua">← Zurück</a></div></body></html>')
    return apache2.OK
  end
  local u = json_decode(bu) or {}
  local uname = u.username or ""
  local en    = u.enabled

  -- Load roles (best-effort — not fatal if this fails)
  local all_roles, _ = get_all_roles(token)
  local user_roles   = get_user_roles(uid, token)

  r:puts(page_head("Benutzer: " .. uname, "list"))
  r:puts('<div class="main">')
  r:puts(msg_html(msg))

  -- Back link + user header
  r:puts('<div class="user-header">')
  r:puts('<a class="btn b-cancel" href="/admin-kc.lua">← Alle Benutzer</a>')
  r:puts('<h2>' .. h(uname) .. '</h2>')
  if en then
    r:puts('<span class="tag tag-en">aktiv</span>')
  else
    r:puts('<span class="tag tag-dis">gesperrt</span>')
  end
  r:puts('</div>')

  -- ── Stammdaten ──────────────────────────────────────────────────────────────
  r:puts('<div class="card">')
  r:puts('<h2>Stammdaten</h2>')
  r:puts('<p class="section-note">Änderungen werden sofort in Keycloak gespeichert.</p>')
  r:puts('<form method="POST" action="?action=do_update&id=' .. h(uid) .. '">')

  local function frow(lbl, name, val, typ)
    typ = typ or "text"
    r:puts('<div class="form-row"><label>' .. lbl .. '</label>')
    r:puts('<input type="' .. typ .. '" name="' .. name .. '" value="' .. h(val or "") .. '"></div>')
  end
  frow("Benutzername",  "username",  u.username)
  frow("Vorname",       "firstName", u.firstName)
  frow("Nachname",      "lastName",  u.lastName)
  frow("E-Mail",        "email",     u.email, "email")

  r:puts('<div class="form-row"><label></label>')
  r:puts('<button class="btn b-save" type="submit">Speichern</button></div>')
  r:puts('</form></div>')

  -- ── Rollenzuweisung ─────────────────────────────────────────────────────────
  r:puts('<div class="card">')
  if KC_PREFIX ~= "" then
    r:puts('<h2>Rollen <span class="hint" style="font-weight:normal">(Prefix: <code>' .. h(KC_PREFIX) .. '</code>)</span></h2>')
    r:puts('<p class="section-note">Nur Rollen mit dem konfigurierten Prefix werden angezeigt (KEYCLOAK_ROLE_PREFIX).</p>')
  else
    r:puts('<h2>Rollen</h2>')
    r:puts('<p class="section-note">Alle Realm-Rollen werden angezeigt. Für nur proxy-spezifische Rollen KEYCLOAK_ROLE_PREFIX setzen.</p>')
  end

  if #all_roles == 0 then
    r:puts('<p class="hint">Keine passenden Rollen gefunden.')
    if KC_PREFIX ~= "" then r:puts(' (Prefix "' .. h(KC_PREFIX) .. '" passt auf keine Rolle.)') end
    r:puts('</p>')
  else
    r:puts('<form method="POST" action="?action=do_setroles&id=' .. h(uid) .. '">')
    r:puts('<div class="role-grid">')
    for _, role in ipairs(all_roles) do
      if type(role) ~= "table" then goto next_role end
      local rid   = role.id   or ""
      local rname = role.name or ""
      local rdesc = role.description or ""
      local checked = user_roles[rid] ~= nil
      local cls = checked and 'role-item checked' or 'role-item'
      local title_attr = rdesc ~= "" and (' title="' .. h(rdesc) .. '"') or ""
      r:puts('<label class="' .. cls .. '"' .. title_attr .. '>')
      r:puts('<input type="checkbox" name="role_' .. h(rid) .. '" value="' .. h(rname) .. '"')
      if checked then r:puts(' checked') end
      r:puts('>' .. h(rname) .. '</label>')
      ::next_role::
    end
    r:puts('</div>')
    r:puts('<p class="hint">Checkbox aktivieren = Rolle zuweisen. Deaktivieren = Rolle entziehen.</p>')
    r:puts('<button class="btn b-save" type="submit">Rollen speichern</button>')
    r:puts('</form>')
  end
  r:puts('</div>')

  -- ── Konto-Aktionen ──────────────────────────────────────────────────────────
  r:puts('<div class="card">')
  r:puts('<h2>Konto-Aktionen</h2>')

  r:puts('<h3>Passwort</h3>')
  r:puts('<div class="actions" style="margin-bottom:.8em">')
  r:puts('<form method="POST" action="?action=do_setpw&id=' .. h(uid) .. '" style="display:flex;gap:.4em;align-items:center">')
  r:puts('<input type="password" name="password" placeholder="Neues temporäres Passwort" style="width:240px">')
  r:puts('<button class="btn b-warn" type="submit">Passwort setzen</button>')
  r:puts('</form>')
  r:puts('</div>')
  r:puts('<p class="hint">Setzt ein temporäres Passwort — der Benutzer muss es beim nächsten Login ändern.</p>')

  r:puts('<form method="POST" action="?action=do_resetpw&id=' .. h(uid) .. '" style="margin-bottom:.3em">')
  r:puts('<button class="btn b-warn" type="submit"'
    .. ' onclick="return confirm(\'Passwort-Reset-E-Mail an ' .. h(u.email or uname) .. ' senden?\')">'
    .. 'Passwort-Reset-E-Mail senden</button>')
  r:puts('</form>')
  r:puts('<p class="hint">Sendet eine E-Mail mit einem Link zum Zurücksetzen des Passworts.')
  r:puts(' Setzt voraus dass SMTP in Keycloak konfiguriert ist (Realm Settings → Email).</p>')

  r:puts('<h3>Konto-Status</h3>')
  r:puts('<div class="actions" style="margin-bottom:.3em">')
  if en then
    r:puts('<form method="POST" action="?action=do_toggle&id=' .. h(uid) .. '">')
    r:puts('<input type="hidden" name="enabled" value="false">')
    r:puts('<button class="btn b-dis" type="submit"'
      .. ' onclick="return confirm(\'Benutzer ' .. h(uname) .. ' sperren?\')">'
      .. 'Benutzer sperren</button>')
    r:puts('</form>')
    r:puts('<span class="hint">Gesperrte Benutzer können sich nicht mehr anmelden.</span>')
  else
    r:puts('<form method="POST" action="?action=do_toggle&id=' .. h(uid) .. '">')
    r:puts('<input type="hidden" name="enabled" value="true">')
    r:puts('<button class="btn b-add" type="submit">Benutzer aktivieren</button>')
    r:puts('</form>')
  end
  r:puts('</div>')

  r:puts('<h3 style="color:#ff6666">Benutzer löschen</h3>')
  r:puts('<form method="POST" action="?action=do_delete&id=' .. h(uid) .. '">')
  r:puts('<button class="btn b-del" type="submit"'
    .. ' onclick="return confirm(\'Benutzer ' .. h(uname) .. ' unwiderruflich löschen?\')">'
    .. 'Benutzer löschen</button>')
  r:puts('</form>')
  r:puts('<p class="hint">Dieser Vorgang kann nicht rückgängig gemacht werden.</p>')

  r:puts('</div>')
  r:puts('</div></body></html>')
  return apache2.OK
end

-- ── View: New user form ───────────────────────────────────────────────────────

local function show_new_user(r, msg, prefill)
  prefill = prefill or {}
  r:puts(page_head("Neuer Benutzer", "new"))
  r:puts('<div class="main">')
  r:puts(msg_html(msg))
  r:puts('<div class="card">')
  r:puts('<h2>Neuen Keycloak-Benutzer anlegen</h2>')
  r:puts('<p class="section-note">Alle mit * markierten Felder sind Pflichtfelder.</p>')

  r:puts('<form method="POST" action="?action=do_create">')

  local function row(lbl, name, typ, req, note)
    typ = typ or "text"
    local req_attr = req and ' required' or ''
    r:puts('<div class="form-row"><label>' .. lbl .. (req and ' <span style="color:#ff6666">*</span>' or '') .. '</label>')
    r:puts('<input type="' .. typ .. '" name="' .. name .. '" value="' .. h(prefill[name] or "") .. '"' .. req_attr .. '></div>')
    if note then r:puts('<div class="form-row"><label></label><span class="hint">' .. note .. '</span></div>') end
  end

  row("Benutzername",         "username",  "text",     true,
    "Eindeutiger Anmeldename (nur Buchstaben, Zahlen, - und _)")
  row("Vorname",              "firstName", "text")
  row("Nachname",             "lastName",  "text")
  row("E-Mail",               "email",     "email",    false,
    "Wird für Passwort-Reset-E-Mails und als Anzeigename verwendet")
  row("Temporäres Passwort",  "password",  "password", true,
    "Der Benutzer muss das Passwort beim ersten Login selbst ändern")

  r:puts('<div class="form-row"><label></label>')
  r:puts('<button class="btn b-add" type="submit">Benutzer anlegen</button>')
  r:puts(' <a class="btn b-cancel" href="/admin-kc.lua">Abbrechen</a>')
  r:puts('</div></form>')
  r:puts('</div></div></body></html>')
  return apache2.OK
end

-- ── POST action handlers ──────────────────────────────────────────────────────

local function do_create(r, post, token)
  local uname = (post.username or ""):match("^%s*(.-)%s*$")
  local pw    = post.password or ""

  if uname == "" then
    return show_new_user(r, "ERR: Benutzername ist erforderlich", post)
  end
  if pw == "" then
    return show_new_user(r, "ERR: Temporäres Passwort ist erforderlich", post)
  end
  if not uname:match("^[A-Za-z0-9][A-Za-z0-9%._%-%+@]*$") then
    return show_new_user(r, "ERR: Benutzername enthält ungültige Zeichen", post)
  end

  local body = json_encode({
    username   = uname,
    firstName  = post.firstName or "",
    lastName   = post.lastName  or "",
    email      = post.email     or "",
    enabled    = true,
    credentials = {{ type="password", value=pw, temporary=true }},
  })

  local status, resp = kc_post("/users", body, token)
  if status == 201 then
    r.headers_out["Location"] = "/admin-kc.lua?msg=" .. ue("Benutzer '" .. uname .. "' angelegt")
    return apache2.HTTP_MOVED_TEMPORARILY
  elseif status == 409 then
    return show_new_user(r, "ERR: Benutzername '" .. uname .. "' ist bereits vergeben", post)
  elseif status == 403 then
    return show_new_user(r, "ERR: Zugriff verweigert (403) — Token hat keine manage-users-Berechtigung", post)
  else
    return show_new_user(r, "ERR: Keycloak-Fehler (HTTP " .. status .. "): " .. resp:sub(1,200), post)
  end
end

local function do_update(r, uid, post, token)
  -- Note: Keycloak's PUT /users/{id} is lenient about missing fields —
  -- omitted fields are kept as-is (Keycloak behaviour since v4+).
  local body = json_encode({
    username  = post.username  or "",
    firstName = post.firstName or "",
    lastName  = post.lastName  or "",
    email     = post.email     or "",
  })
  local status, _ = kc_put("/users/" .. uid, body, token)
  local msg = status == 204
    and "Stammdaten gespeichert"
    or  ("ERR: Speichern fehlgeschlagen (HTTP " .. status .. ")")
  r.headers_out["Location"] = "/admin-kc.lua?action=user&id=" .. uid .. "&msg=" .. ue(msg)
  return apache2.HTTP_MOVED_TEMPORARILY
end

local function do_setroles(r, uid, post, token)
  local all_roles  = get_all_roles(token)
  local user_roles = get_user_roles(uid, token)

  local to_add    = {}
  local to_remove = {}

  for _, role in ipairs(all_roles) do
    if type(role) ~= "table" then goto next end
    local rid   = role.id   or ""
    local rname = role.name or ""
    local wanted  = post["role_" .. rid] ~= nil
    local current = user_roles[rid] ~= nil
    if wanted and not current then
      to_add[#to_add+1]    = { id=rid, name=rname }
    elseif not wanted and current then
      to_remove[#to_remove+1] = { id=rid, name=rname }
    end
    ::next::
  end

  local ok = true
  if #to_add > 0 then
    local s, _ = kc_post("/users/" .. uid .. "/role-mappings/realm", json_encode(to_add), token)
    if s ~= 204 then ok = false end
  end
  if #to_remove > 0 then
    local s, _ = kc_delete("/users/" .. uid .. "/role-mappings/realm", json_encode(to_remove), token)
    if s ~= 204 then ok = false end
  end

  local msg = ok
    and ("Rollen gespeichert (" .. (#to_add) .. " hinzugefügt, " .. (#to_remove) .. " entfernt)")
    or  "ERR: Fehler beim Speichern der Rollen"
  r.headers_out["Location"] = "/admin-kc.lua?action=user&id=" .. uid .. "&msg=" .. ue(msg)
  return apache2.HTTP_MOVED_TEMPORARILY
end

local function do_setpw(r, uid, post, token)
  local pw = post.password or ""
  if pw == "" then
    r.headers_out["Location"] = "/admin-kc.lua?action=user&id=" .. uid .. "&msg=" .. ue("ERR: Kein Passwort eingegeben")
    return apache2.HTTP_MOVED_TEMPORARILY
  end
  local body = json_encode({ type="password", value=pw, temporary=true })
  local status, _ = kc_put("/users/" .. uid .. "/reset-password", body, token)
  local msg = status == 204
    and "Temporäres Passwort gesetzt"
    or  ("ERR: Fehler beim Setzen des Passworts (HTTP " .. status .. ")")
  r.headers_out["Location"] = "/admin-kc.lua?action=user&id=" .. uid .. "&msg=" .. ue(msg)
  return apache2.HTTP_MOVED_TEMPORARILY
end

local function do_resetpw(r, uid, token)
  -- Sends a "reset password" email via Keycloak's execute-actions-email endpoint.
  -- Requires SMTP to be configured in Keycloak (Realm Settings → Email).
  local body = json_encode({ "UPDATE_PASSWORD" })
  local status, _ = kc_put("/users/" .. uid .. "/execute-actions-email", body, token)
  local msg
  if status == 204 then
    msg = "Passwort-Reset-E-Mail wurde gesendet"
  elseif status == 400 then
    msg = "ERR: E-Mail-Versand fehlgeschlagen — SMTP in Keycloak konfiguriert? (Realm Settings → Email)"
  elseif status == 404 then
    msg = "ERR: Benutzer nicht gefunden"
  else
    msg = "ERR: Fehler beim E-Mail-Versand (HTTP " .. status .. ")"
  end
  r.headers_out["Location"] = "/admin-kc.lua?action=user&id=" .. uid .. "&msg=" .. ue(msg)
  return apache2.HTTP_MOVED_TEMPORARILY
end

local function do_toggle(r, uid, post, token)
  local enabled = post.enabled == "true"
  local body = json_encode({ enabled=enabled })
  local status, _ = kc_put("/users/" .. uid, body, token)
  local msg = status == 204
    and (enabled and "Benutzer aktiviert" or "Benutzer gesperrt")
    or  ("ERR: Statusänderung fehlgeschlagen (HTTP " .. status .. ")")
  r.headers_out["Location"] = "/admin-kc.lua?action=user&id=" .. uid .. "&msg=" .. ue(msg)
  return apache2.HTTP_MOVED_TEMPORARILY
end

local function do_delete(r, uid, token)
  local status, _ = kc_delete("/users/" .. uid, nil, token)
  if status == 204 then
    r.headers_out["Location"] = "/admin-kc.lua?msg=" .. ue("Benutzer gelöscht")
  else
    r.headers_out["Location"] = "/admin-kc.lua?action=user&id=" .. uid
      .. "&msg=" .. ue("ERR: Löschen fehlgeschlagen (HTTP " .. status .. ")")
  end
  return apache2.HTTP_MOVED_TEMPORARILY
end

-- ── Entry point ───────────────────────────────────────────────────────────────

function handle(r)
  r.content_type = "text/html; charset=utf-8"

  -- Configuration check
  if KC_URL == "" then
    r:puts(page_head("Keycloak Admin", "list"))
    r:puts('<div class="main"><div class="msg err">')
    r:puts('<strong>KEYCLOAK_ADMIN_URL nicht konfiguriert</strong><br><br>')
    r:puts('Setze die Umgebungsvariable <code>KEYCLOAK_ADMIN_URL</code> im Container,<br>')
    r:puts('z.B. <code>KEYCLOAK_ADMIN_URL=https://iam.example.com/admin/realms/master</code><br><br>')
    r:puts('Wird automatisch aus <code>OIDC_PROVIDER_METADATA_URL</code> abgeleitet wenn die URL<br>')
    r:puts('dem Standard-Keycloak-Format <code>https://host/realms/REALM/...</code> folgt.')
    r:puts('</div></div></body></html>')
    return apache2.OK
  end

  -- OIDC access token (set by mod_auth_openidc in the authentication phase).
  -- If empty the user reached this script without an OIDC session (e.g. an
  -- internal-IP request that bypassed OIDC at the Location / level).
  -- Show a login prompt rather than a cryptic error.
  local token = r.subprocess_env["OIDC_access_token"] or ""
  if token == "" then
    -- Build a return URL so the user lands back here after login
    local return_url = "https://" .. (r.hostname or "") .. r.uri
    if r.args and r.args ~= "" then return_url = return_url .. "?" .. r.args end
    local login_url  = "https://" .. (r.hostname or "") .. "/admin-kc.lua"

    r:puts(page_head("Keycloak Admin", "list"))
    r:puts('<div class="main">')
    r:puts('<div class="card" style="max-width:480px;margin-top:2em">')
    r:puts('<h2 style="margin-bottom:.7em">\xF0\x9F\x94\x90 Anmeldung erforderlich</h2>')
    r:puts('<p style="color:#aaa;font-size:.9em;margin-bottom:1.2em">')
    r:puts('Für die Keycloak-Benutzerverwaltung ist eine aktive OIDC-Session nötig.<br>')
    r:puts('Bitte melde dich an, um fortzufahren.')
    r:puts('</p>')
    r:puts('<a class="btn b-add" style="font-size:.95em;padding:7px 18px" href="'
      .. h(login_url) .. '">\xE2\x9E\x94 Jetzt anmelden</a>')
    r:puts('</div></div></body></html>')
    return apache2.OK
  end

  local args   = r:parseargs()
  local action = args.action or "list"
  local uid    = args.id  or ""
  local msg    = args.msg or ""

  -- Route POST requests to action handlers
  if r.method == "POST" then
    local post = r:parsebody() or {}
    if     action == "do_create"   then return do_create(r, post, token)
    elseif action == "do_update"   then return do_update(r, uid, post, token)
    elseif action == "do_setroles" then return do_setroles(r, uid, post, token)
    elseif action == "do_setpw"    then return do_setpw(r, uid, post, token)
    elseif action == "do_resetpw"  then return do_resetpw(r, uid, token)
    elseif action == "do_toggle"   then return do_toggle(r, uid, post, token)
    elseif action == "do_delete"   then return do_delete(r, uid, token)
    else
      r.headers_out["Location"] = "/admin-kc.lua"
      return apache2.HTTP_MOVED_TEMPORARILY
    end

  -- Route GET requests to views
  else
    if     action == "user" and uid ~= "" then return show_user_detail(r, uid, token, msg)
    elseif action == "new"                then return show_new_user(r, msg)
    else                                       return show_user_list(r, token, msg)
    end
  end
end
