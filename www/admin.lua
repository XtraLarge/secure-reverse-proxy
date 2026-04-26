--
-- admin.lua — Proxy VHost Admin Interface
--
-- Served on admin.DOMAIN — OIDC-protected via CLIENTOIDC_CLAIM.
-- Reads/writes /etc/apache2/sites-admin/*.conf (domain configs) and
-- /etc/apache2/AddOn/<domain>/<site>.preconfig|postconfig (AddOn snippets).
-- Both volumes must be mounted read-write.
--

local SITES_DIR = "/etc/apache2/sites-admin/"
local ADDON_DIR = "/etc/apache2/AddOn/"
local OIDC_DIR  = "/etc/apache2/AddOn/.oidc/"

local _lfs   = (function() local ok, m = pcall(require, 'lfs');   return ok and m end)()
local _posix = (function() local ok, m = pcall(require, 'posix'); return ok and m end)()  -- lua-posix needs Lua 5.4 build; nil on bookworm

-- List *.conf files from a directory; lfs primary, popen fallback
local function _list_dir_conf(dir)
  local files = {}
  if _lfs then
    pcall(function()
      for f in _lfs.dir(dir) do
        if f:match('%.conf$') and not f:match('%.bak') then
          table.insert(files, dir..'/'..f)
        end
      end
    end)
    table.sort(files)
  else
    local p = io.popen('ls '..dir..'/*.conf 2>/dev/null')
    if p then
      for f in p:lines() do
        if not f:match('%.bak') then table.insert(files, f) end
      end
      p:close()
    end
  end
  return files
end

-- Return the first *.conf file found across dirs; lfs primary, popen fallback
local function _first_conf(dirs)
  if _lfs then
    for _, dir in ipairs(dirs) do
      local found
      pcall(function()
        for f in _lfs.dir(dir) do
          if f:match('%.conf$') then found = dir..'/'..f; error('stop') end
        end
      end)
      if found then return found end
    end
    return ""
  else
    local globs = {}
    for _, dir in ipairs(dirs) do table.insert(globs, dir..'/*.conf') end
    local p = io.popen('ls '..table.concat(globs, ' ')..' 2>/dev/null | head -1')
    if p then local f = p:read('*l') or ''; p:close(); return f end
    return ""
  end
end

-- Recursive mkdir; lfs primary, posix secondary, os.execute fallback
local function _mkdir_p(path)
  if _lfs then
    local cur = path:sub(1,1) == '/' and '' or '.'
    for part in path:gmatch('[^/]+') do
      cur = cur..'/'..part
      _lfs.mkdir(cur)
    end
  elseif _posix then
    local cur = path:sub(1,1) == '/' and '' or '.'
    for part in path:gmatch('[^/]+') do
      cur = cur..'/'..part
      pcall(_posix.mkdir, cur, tonumber('755', 8))
    end
  else
    os.execute('mkdir -p '..path)
  end
end

-- chmod 600; posix primary, os.execute fallback (lfs has no chmod)
local function _chmod600(path)
  if _posix then
    pcall(_posix.chmod, path, tonumber('600', 8))
  else
    os.execute('chmod 600 '..path)
  end
end

-- Signal Apache graceful reload via FIFO; io.open primary, os.execute fallback
local function _apache_reload()
  local fifo = '/run/apache-reload.fifo'
  local f = io.open(fifo, 'w')
  if f then f:write('reload\n'); f:close(); return true end
  return os.execute('echo reload > '..fifo..' 2>/dev/null') == 0
end

-- Keycloak Admin API — uses the Proxy client's service account (client_credentials)
local KC_ADMIN_URL    = os.getenv("KEYCLOAK_ADMIN_URL") or ""
-- Normalise to the admin API base: if the URL already contains /admin/realms/ leave it,
-- otherwise transform /realms/ → /admin/realms/ (for URLs like https://iam/realms/master).
local KC_BASE_URL = (function()
  if KC_ADMIN_URL == "" then return "" end
  if KC_ADMIN_URL:find("/admin/realms/", 1, true) then
    return KC_ADMIN_URL  -- already the admin API URL
  end
  return KC_ADMIN_URL:gsub("/realms/", "/admin/realms/")
end)()
local KC_CLIENT_ID    = os.getenv("OIDC_CLIENT_ID")     or ""
local KC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET") or ""
-- Derive token endpoint from OIDC_PROVIDER_METADATA_URL
local KC_TOKEN_URL = (function()
  local meta = os.getenv("OIDC_PROVIDER_METADATA_URL") or ""
  -- Replace /.well-known/openid-configuration with /protocol/openid-connect/token
  return meta:gsub("/.well%-known/openid%-configuration$",
                   "/protocol/openid-connect/token")
end)()
local KC_LOGOUT_URL = KC_TOKEN_URL:gsub("/token$", "/logout")

local MACRO_TYPES = {
  "VHost_Proxy",
  "VHost_Proxy_Open",
  "VHost_Proxy_OIDC_User",
  "VHost_Proxy_OIDC_Any",
  "VHost_Proxy_OIDC_Group",
  "VHost_Proxy_Basic",
  "VHost_Alias",
}

-- ── Helpers ───────────────────────────────────────────────────────────────────

local function h(s)
  return tostring(s or "")
    :gsub("&","&amp;"):gsub("<","&lt;"):gsub(">","&gt;"):gsub('"','&quot;')
end

local function trim(s)
  return (tostring(s or "")):match("^%s*(.-)%s*$")
end

local function ue(s)
  return tostring(s or ""):gsub("([^A-Za-z0-9_%.~%-])", function(c)
    return string.format("%%%02X", string.byte(c))
  end)
end

local function is_vhost_line(line)
  local l = trim(line):lower()
  return l:match("^use%s+vhost_") ~= nil
end

-- Returns true when the line above a VHost entry is "# no-admin"
-- Such entries are hidden from the admin UI and cannot be edited or deleted.
local function is_no_admin(lines, lineno)
  local prev = trim(lines[lineno - 1] or ""):lower()
  return prev == "# no-admin"
end

local function is_disabled_line(line)
  return trim(line):match("^#%s*[Uu]se%s+") ~= nil
end

local function is_geolock_line(line)
  return trim(line):lower():match("^use%s+geolock_vhost%s+") ~= nil
end

local function parse_vhost_line(line)
  local raw = trim(line)
  -- Extract trailing quoted field (users or auth entry)
  local users = raw:match("'([^']*)'%s*$") or ""
  local base  = raw:gsub("%s*'[^']*'%s*$", "")

  local parts = {}
  for w in base:gmatch("%S+") do table.insert(parts, w) end
  -- parts: [1]=Use [2]=Macro [3]=name [4]=domain [5]=dest [6]=authtype(Basic)

  if #parts < 4 then return nil end

  local macro = parts[2]
  local m     = macro:lower()
  local result = {
    macro    = macro,
    name     = parts[3] or "",
    domain   = parts[4] or "",
    dest     = parts[5] or "",
    users    = users,
    authtype = (m == "vhost_proxy_basic") and (parts[6] or "user") or "",
    raw      = raw,
  }
  return result
end

local function build_line(macro, name, domain, dest, users, authtype)
  local m = trim(macro):lower()
  name     = trim(name)
  domain   = trim(domain)
  dest     = trim(dest)
  users    = trim(users)
  authtype = trim(authtype ~= "" and authtype or "user")

  if m == "vhost_proxy" or m == "vhost_proxy_open" or m == "vhost_proxy_oidc_any" or m == "vhost_alias" then
    return string.format("Use %-28s  %-20s  %-25s  %s", macro, name, domain, dest)
  elseif m == "vhost_proxy_oidc_user" or m == "vhost_proxy_oidc_group" then
    return string.format("Use %-28s  %-20s  %-25s  %-35s  '%s'", macro, name, domain, dest, users)
  elseif m == "vhost_proxy_basic" then
    return string.format("Use %-28s  %-20s  %-25s  %-35s  %-6s  '%s'", macro, name, domain, dest, authtype, users)
  end
  return nil
end

local function read_lines(fpath)
  local f = io.open(fpath, "r")
  if not f then return nil end
  local lines = {}
  for l in f:lines() do table.insert(lines, l) end
  f:close()
  return lines
end

local function write_lines(fpath, lines)
  local f = io.open(fpath, "w")
  if not f then return false, "Datei nicht schreibbar: " .. fpath end
  for _, l in ipairs(lines) do f:write(l .. "\n") end
  f:close()
  return true, nil
end

-- ── AddOn helpers ────────────────────────────────────────────────────────────

local function addon_path(domain, site, suffix)
  -- suffix: "preconfig" or "postconfig"
  return ADDON_DIR .. domain .. "/" .. site .. "." .. suffix
end

local function read_file(fpath)
  local f = io.open(fpath, "r")
  if not f then return "" end
  local s = f:read("*a")
  f:close()
  return s or ""
end

local function write_file(fpath, content)
  local dir = fpath:match("^(.*)/[^/]+$")
  if dir then _mkdir_p(dir) end
  if content == "" then
    os.remove(fpath)
    return true, nil
  end
  local f = io.open(fpath, "w")
  if not f then return false, "Nicht schreibbar: " .. fpath end
  f:write(content)
  f:close()
  return true, nil
end

-- Run apache2ctl configtest and return (ok, output)
local function configtest()
  local p = io.popen("/usr/sbin/apache2ctl configtest 2>&1")
  local out = p:read("*a")
  local ok  = p:close()
  -- apache2ctl exits 0 on success; pclose returns true on exit 0
  return (ok == true or ok == 0), out
end

local function list_conf_files()
  return _list_dir_conf(SITES_DIR)
end

local function validate_name(s)
  return trim(s):match("^[a-zA-Z0-9][a-zA-Z0-9_%-]*$") ~= nil
end

local function validate_domain(s)
  return trim(s):match("^[a-zA-Z0-9][a-zA-Z0-9%.%-]+%.[a-zA-Z]+$") ~= nil
end

local function validate_dest(s)
  s = trim(s)
  -- Allow http/https URL or plain hostname/ip for VHost_Alias
  return s ~= "" and not s:match("[;|`$<>]")
end

local function validate_users(s)
  return trim(s):match("^[a-zA-Z0-9%.@_|%-]*$") ~= nil
end

local function fexists(p)
  local f = io.open(p, "r")
  if f then f:close(); return true end
  return false
end

-- ── CSS / HTML ─────────────────────────────────────────────────────────────────

local CSS = [[<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d0d1a;color:#ddd;min-height:100vh}
.topbar{
  display:flex;align-items:center;justify-content:space-between;
  background:#060614;border-bottom:1px solid #2a2a4e;
  padding:.6em 1.2em;flex-wrap:wrap;gap:.5em}
.topbar-back{color:#7ecfff;text-decoration:none;font-size:.85em;
  border:1px solid #2a2a4e;border-radius:3px;padding:3px 10px;
  background:#0a0a22;margin-right:.3em;transition:background .15s}
.topbar-back:hover{background:#0f3460;color:#00d4ff}
.topbar-title{color:#00d4ff;font-size:1.1em;font-weight:bold;text-decoration:none}
.topbar-nav{display:flex;gap:.5em}
.topbar-nav a{
  color:#7ecfff;text-decoration:none;font-size:.85em;
  border:1px solid #2a2a4e;border-radius:3px;padding:3px 10px;
  background:#0a0a22;transition:background .15s}
.topbar-nav a:hover{background:#0f3460;color:#00d4ff}
.topbar-user-block{display:flex;flex-direction:column;align-items:flex-end;
  gap:.15em;margin-left:.7em;line-height:1.3}
.topbar-user{color:#aaa;font-size:.85em;font-family:Arial,sans-serif;white-space:nowrap}
.topbar-logout{color:#666;font-size:.75em;text-decoration:none;white-space:nowrap}
.topbar-logout:hover{color:#ff9999}
.main{padding:1.2em}
h2{color:#7ecfff;font-size:1em;margin:0 0 .7em;border-bottom:1px solid #2a2a4e;padding-bottom:.3em}
table{border-collapse:collapse;width:100%;font-size:.88em}
th{background:#0f3460;color:#00d4ff;padding:6px 10px;text-align:left;white-space:nowrap}
td{padding:5px 10px;border-bottom:1px solid #1a1a3e;vertical-align:middle}
tr:hover td{background:#111130}
.card{background:#0a0a22;border:1px solid #2a2a4e;border-radius:5px;padding:1em;margin-bottom:1.3em}
.tag{font-size:.75em;background:#0f3460;color:#7ecfff;padding:2px 7px;border-radius:3px;white-space:nowrap}
.tag-basic{background:#2d1a00;color:#ffb366}
.tag-alias{background:#1a2d00;color:#99ff66}
.tag-proxy{background:#001a2d;color:#66ccff}
.tag-oidc{background:#1a002d;color:#cc99ff}
.tag-claim{background:#2d0028;color:#ff99ee}
.tag-geo{background:#002d1a;color:#66ffcc}
.tag-open{background:#1a1400;color:#ffdd44}
a.btn,button.btn{padding:4px 11px;border:none;border-radius:3px;cursor:pointer;
  text-decoration:none;display:inline-block;font-size:.82em;line-height:1.5}
.b-edit{background:#0f3460;color:#7ecfff}.b-del{background:#5c0000;color:#ff9999}
.b-addon{background:#1a1a00;color:#ffee66}
.b-cfg{background:#001f33;color:#5599bb}
.b-add{background:#003d00;color:#99ff99}.b-apply{background:#3d3d00;color:#ffff99;
  font-size:.95em;padding:7px 18px}.b-save{background:#003d3d;color:#99ffff}
.b-cancel{background:#2a2a4e;color:#aaa}
.b-warn{background:#3d2000;color:#ffaa44}
.form-row{margin:.6em 0;display:flex;align-items:center;gap:.7em}
.form-row label{width:160px;color:#aaa;flex-shrink:0;font-size:.9em}
.form-row input,.form-row select{
  background:#060614;color:#ddd;border:1px solid #3a3a6e;
  padding:5px 8px;border-radius:3px;flex:1;min-width:0}
.form-row select{cursor:pointer}
.msg{padding:.5em .8em;border-radius:3px;margin-bottom:.8em;font-size:.9em}
.ok{background:#003d00;color:#99ff99}.err{background:#3d0000;color:#ff9999}
.actions{display:flex;gap:.4em;flex-wrap:nowrap}
.applybar{display:flex;align-items:center;gap:1em;margin-bottom:1.2em;flex-wrap:wrap}
.dim{color:#666;font-size:.8em}
.uf-field{margin-bottom:.8em}
.uf-field label{display:block;color:#aaa;font-size:.85em;margin-bottom:.3em}
.uf-field input{width:100%;max-width:340px;background:#0a0a1e;color:#ddd;
  border:1px solid #3a3a6e;padding:.4em .7em;border-radius:4px;font-size:.9em}
.grp-checks{display:flex;flex-wrap:wrap;gap:.5em}
.grp-checks label{display:flex;align-items:center;gap:.35em;cursor:pointer;
  background:#0a0a22;border:1px solid #2a2a4e;border-radius:3px;padding:3px 8px}
.grp-checks input[type=checkbox]{accent-color:#00d4ff}
.pre-wrap{position:relative}
.copy-btn{position:absolute;top:.4em;right:.4em;background:#0d0d20;border:1px solid #2a2a4e;
  color:#445577;border-radius:4px;cursor:pointer;padding:3px 8px;font-size:.72em;
  opacity:.55;transition:opacity .15s,background .15s,color .15s,border-color .15s;line-height:1.5}
.copy-btn:hover{opacity:1;background:#0f3460;color:#7ecfff;border-color:#3a5a8e}
.copy-btn.copy-ok{background:#003d00;color:#99ff99;border-color:#005500;opacity:1}
tr.disabled-row td{opacity:.38;font-style:italic}
.b-disable{background:#2a1800;color:#ffaa44}.b-enable{background:#003d00;color:#99ff99}
</style>]]

local JS = [[<script>
function onMacroChange(sel) {
  var m = sel.value.toLowerCase();
  document.getElementById('row_oidc_users').style.display  = m === 'vhost_proxy_oidc_user'  ? '' : 'none';
  document.getElementById('row_group_users').style.display = m === 'vhost_proxy_oidc_group' ? '' : 'none';
  document.getElementById('row_basic_users').style.display = m === 'vhost_proxy_basic'      ? '' : 'none';
  document.getElementById('row_auth').style.display        = m === 'vhost_proxy_basic'      ? '' : 'none';
}
function serializeUsers(form) {
  var m = form.querySelector('[name=macro]').value.toLowerCase();
  var val = '';
  var sel, fb;
  if (m === 'vhost_proxy_oidc_user') {
    sel = document.getElementById('sel_oidc_users');
    fb  = document.getElementById('fb_oidc');
  } else if (m === 'vhost_proxy_oidc_group') {
    sel = document.getElementById('sel_group_users');
    fb  = document.getElementById('fb_group');
  } else if (m === 'vhost_proxy_basic') {
    sel = document.getElementById('sel_basic_users');
    fb  = document.getElementById('fb_basic');
  }
  if (sel) {
    var selected = Array.from(sel.selectedOptions).map(function(o){return o.value;}).join('|');
    if (selected !== '') document.getElementById('users_val').value = selected;
  } else if (fb) {
    document.getElementById('users_val').value = fb.value;
  }
  return true;
}
function normalizeDest(input) {
  var v = input.value.trim();
  v = v.replace(/^[a-zA-Z]+:\/\//, function(m){ return m.toLowerCase(); });
  if (/^https?:\/\/[^/]+$/.test(v)) v = v + '/';
  input.value = v;
}
function filterSites(q) {
  q = q.toLowerCase();
  document.querySelectorAll('table tr').forEach(function(tr) {
    if (!tr.querySelector('td')) return;
    tr.style.display = tr.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
  });
}
function copyPre(btn) {
  var pre = btn.parentElement.querySelector('pre');
  if (!navigator.clipboard) return;
  navigator.clipboard.writeText(pre.textContent).then(function() {
    var prev = btn.innerHTML;
    btn.innerHTML = '&#10003;&nbsp;Kopiert';
    btn.classList.add('copy-ok');
    setTimeout(function(){ btn.innerHTML = prev; btn.classList.remove('copy-ok'); }, 1800);
  });
}
</script>]]

-- Debug mode: set LUA_DEBUG=1 in proxy.env to enable, remove to disable.
local DEBUG = os.getenv("LUA_DEBUG") == "1"
local function dbg(r, label, value)
  if not DEBUG then return end
  local s
  if type(value) == "table" then
    local t = {}
    for k, v in pairs(value) do t[#t+1] = tostring(k) .. "=" .. tostring(v) end
    s = "{" .. table.concat(t, ", ") .. "}"
  else
    s = tostring(value)
  end
  r:puts('<pre style="background:#111;color:#ff0;padding:.5em;margin:.3em 0">'
    .. '[DEBUG] ' .. h(label) .. ': ' .. h(s) .. '</pre>')
end

-- Logged-in user (set in handle() from r.user; used by topbar).
local ADMIN_REMOTE_USER = ""

-- Use OIDC_COOKIE_DOMAIN (e.g. "example.com") as the authoritative domain.
-- Fall back to parsing the first sites-admin conf filename if not set.
local TOC_DOMAIN = os.getenv("OIDC_COOKIE_DOMAIN") or ""
if TOC_DOMAIN == "" then
  local f = _first_conf({'/etc/apache2/sites-admin', '/etc/apache2/sites-enabled'})
  TOC_DOMAIN = f:match("([^/]+)%.conf$") or ""
end

local function topbar(title, back_url)
  local toc_link  = TOC_DOMAIN ~= "" and ("https://toc."    .. TOC_DOMAIN) or "/"
  local logout_link = TOC_DOMAIN ~= "" and ("https://logout." .. TOC_DOMAIN) or "/logout"
  local user_block = ADMIN_REMOTE_USER ~= ""
    and ('<div class="topbar-user-block">'
      .. '<span class="topbar-user">' .. h(ADMIN_REMOTE_USER) .. '</span>'
      .. '<a class="topbar-logout" href="' .. h(logout_link) .. '">\xC3\x97 Logout</a>'
      .. '</div>')
    or ('<a class="topbar-nav" href="' .. h(logout_link) .. '">\xC3\x97 Logout</a>')
  return '<div class="topbar">'
    .. '<a class="topbar-title" href="/">\xE2\x9A\x99 ' .. h(title) .. '</a>'
    .. '<div class="topbar-nav">'
    .. '<a class="topbar-back" href="' .. h(back_url or toc_link) .. '">\xE2\x86\x90</a>'
    .. '<a href="/?action=users">\xF0\x9F\x91\xA4 OIDC Auth</a>'
    .. '<a href="/?action=htpasswd">\xF0\x9F\x94\x91 Basic Auth</a>'
    .. '<a href="/?action=geolock">\xF0\x9F\x8C\x8D GeoLock</a>'
    .. '</div>'
    .. user_block
    .. '</div>'
end

local function page_head(title, back_url)
  return "<!DOCTYPE html><html lang=de><head><meta charset=UTF-8>"
    .. "<meta name=viewport content='width=device-width,initial-scale=1'>"
    .. "<title>" .. h(title) .. " — Proxy Admin</title>"
    .. CSS .. JS .. "</head><body>"
    .. topbar(title, back_url)
end

local function msg_html(txt)
  if not txt or txt == "" then return "" end
  local cls = txt:sub(1,3) == "ERR" and "err" or "ok"
  return '<div class="msg ' .. cls .. '">' .. h(txt) .. '</div>'
end

-- ── Macro tag coloring ────────────────────────────────────────────────────────

local function macro_tag(m)
  local ml = (m or ""):lower()
  local cls = "tag"
  if ml:find("geolock")  then cls = cls .. " tag-geo"
  elseif ml:find("_open")   then cls = cls .. " tag-open"
  elseif ml:find("basic")   then cls = cls .. " tag-basic"
  elseif ml:find("_any")    then cls = cls .. " tag-oidc"
  elseif ml:find("oidc")    then cls = cls .. " tag-claim"
  elseif ml:find("alias")   then cls = cls .. " tag-alias"
  else                           cls = cls .. " tag-proxy" end
  return '<span class="' .. cls .. '">' .. h(m) .. '</span>'
end

-- ── Forward declarations ──────────────────────────────────────────────────────
local show_kc_client_section
local kc_token
local json_enc
local kc_create_group
local kc_list_users
local kc_list_groups
local htpasswd_list_users

local PENDING_FILE = "/tmp/apache-pending-reload"
local function set_pending_reload()  local f = io.open(PENDING_FILE, "w"); if f then f:close() end end
local function clear_pending_reload() os.remove(PENDING_FILE) end
local function has_pending_reload()
  local f = io.open(PENDING_FILE, "r")
  if f then f:close(); return true end
  return false
end

-- ── List page ─────────────────────────────────────────────────────────────────

local function show_list(r, msg)
  r:puts(page_head("Übersicht"))
  if msg then r:puts(msg_html(msg)) end

  r:puts('<div class="main">')
  r:puts('<div class="applybar">')
  r:puts('<a class="btn b-add" href="/?action=domain_new">+ Neue Domain</a>')
  if has_pending_reload() then
    r:puts('<span style="color:#ffee66;font-size:.9em">'
      .. '\xE2\x9A\xA0\xEF\xB8\x8F  Nicht angewendete \xC3\x84nderungen</span>')
    r:puts('<form method="POST" action="/?action=apply" style="margin-left:auto">')
    r:puts('<button class="btn b-apply" type="submit">&#9654;&nbsp;Konfiguration anwenden</button>')
    r:puts('</form>')
  end
  r:puts('</div>')

  r:puts('<div class="card" style="padding:.5em 1em;margin-bottom:.5em">'
    .. '<input id=filter_sites oninput="filterSites(this.value)" placeholder="\xF0\x9F\x94\x8D Suchen\xE2\x80\xA6"'
    .. ' style="width:100%;box-sizing:border-box;background:#0d0d1a;color:#ddd;'
    .. 'border:1px solid #2a2a4e;border-radius:4px;padding:.4em .7em;font-size:.95em">'
    .. '</div>')

  local files = list_conf_files()
  for _, fpath in ipairs(files) do
    local fname = fpath:match("([^/]+)$")
    local lines = read_lines(fpath)
    if not lines then goto continue end

    -- Count vhost entries and collect unique domains
    local entries = 0
    local disabled_count = 0
    local domains_seen = {}
    local domains_ordered = {}
    for i, l in ipairs(lines) do
      if is_vhost_line(l) and not is_no_admin(lines, i) then
        entries = entries + 1
        local v = parse_vhost_line(l)
        if v and not domains_seen[v.domain] then
          domains_seen[v.domain] = true
          domains_ordered[#domains_ordered + 1] = v.domain
        end
      elseif is_geolock_line(l) then
        entries = entries + 1
      elseif is_disabled_line(l) then
        disabled_count = disabled_count + 1
      end
    end

    r:puts('<div class="card">')
    local dim_disabled = disabled_count > 0
      and (' <span class="dim">' .. disabled_count .. ' deaktiviert</span>') or ""
    r:puts('<h2>' .. h(fname)
      .. ' <span class="dim">(' .. entries .. ' Eintr\xC3\xA4ge)</span>'
      .. dim_disabled .. '&nbsp;'
      .. '<a class="btn b-add" href="/?action=new&amp;file=' .. h(fname) .. '">+ Hinzufügen</a>'
      .. '</h2>')

    -- KC client strip — inline, directly below the heading
    if KC_ADMIN_URL ~= "" then
      for _, domain in ipairs(domains_ordered) do
        show_kc_client_section(r, domain, nil, true)
      end
    end

    if entries == 0 and disabled_count == 0 then
      r:puts('<p class="dim">Keine VHost-Eintr\xC3\xA4ge in dieser Datei.</p>')
    else
      r:puts('<table><tr><th>Typ</th><th>Name</th><th>Domain</th><th>Ziel</th><th>Benutzer</th><th>Aktionen</th></tr>')
      for lineno, line in ipairs(lines) do
        if is_vhost_line(line) and not is_no_admin(lines, lineno) then
          local v = parse_vhost_line(line)
          if v then
            -- Check if AddOn files exist for this entry
            local has_pre  = fexists(addon_path(v.domain, v.name, "preconfig"))
            local has_post = fexists(addon_path(v.domain, v.name, "postconfig"))
            local addon_tag = (has_pre or has_post)
              and ' <span class="tag" style="background:#1a1a00;color:#ffee66">AddOn</span>' or ""

            r:puts('<tr>')
            r:puts('<td>' .. macro_tag(v.macro) .. '</td>')
            r:puts('<td>' .. h(v.name) .. addon_tag .. '</td>')
            r:puts('<td>' .. h(v.domain) .. '</td>')
            r:puts('<td style="font-family:monospace;font-size:.82em">' .. h(v.dest) .. '</td>')
            r:puts('<td style="font-size:.82em">' .. h(v.users) .. '</td>')
            r:puts('<td><div class="actions">')
            -- Edit
            r:puts('<a class="btn b-edit" href="/?action=edit&amp;file='
              .. h(fname) .. '&amp;line=' .. lineno .. '">Bearbeiten</a>')
            -- AddOn
            r:puts('<a class="btn b-addon" href="/?action=addon&amp;name='
              .. h(v.name) .. '&amp;domain=' .. h(v.domain) .. '">AddOn</a>')
            -- Config view
            r:puts('<a class="btn b-cfg" href="/?action=config&amp;file='
              .. h(fname) .. '&amp;line=' .. lineno .. '">Config</a>')
            -- Delete
            r:puts('<form method="POST" action="/?action=delete" style="margin:0"'
              .. ' onsubmit="return confirm(\'Eintrag ' .. h(v.name) .. ' wirklich löschen?\')">')
            r:puts('<input type=hidden name=file value="' .. h(fname) .. '">')
            r:puts('<input type=hidden name=line value="' .. lineno .. '">')
            r:puts('<input type=hidden name=check value="' .. h(trim(line)) .. '">')
            r:puts('<button class="btn b-del" type=submit>L\xC3\xB6schen</button></form>')
            -- Disable toggle
            r:puts('<form method="POST" action="/?action=toggle_disable" style="margin:0">')
            r:puts('<input type=hidden name=file value="' .. h(fname) .. '">')
            r:puts('<input type=hidden name=line value="' .. lineno .. '">')
            r:puts('<input type=hidden name=check value="' .. h(trim(line)) .. '">')
            r:puts('<input type=hidden name=toggle value="disable">')
            r:puts('<button class="btn b-disable" type=submit>Deaktivieren</button></form>')
            r:puts('</div></td></tr>')
          end
        elseif is_geolock_line(line) then
          local parts = {}
          for w in trim(line):gmatch("%S+") do table.insert(parts, w) end
          local gl_domain = parts[3] or ""
          r:puts('<tr>')
          r:puts('<td>' .. macro_tag("GeoLock_VHost") .. '</td>')
          r:puts('<td>\xF0\x9F\x8C\x8D GeoLock</td>')
          r:puts('<td>' .. h(gl_domain) .. '</td>')
          r:puts('<td colspan=2 style="font-size:.82em;color:#888">PIN-gesch\xC3\xBCtzt</td>')
          r:puts('<td><div class="actions">')
          r:puts('<form method="POST" action="/?action=toggle_disable" style="margin:0">')
          r:puts('<input type=hidden name=file value="' .. h(fname) .. '">')
          r:puts('<input type=hidden name=line value="' .. lineno .. '">')
          r:puts('<input type=hidden name=check value="' .. h(trim(line)) .. '">')
          r:puts('<input type=hidden name=toggle value="disable">')
          r:puts('<button class="btn b-disable" type=submit>Deaktivieren</button></form>')
          r:puts('</div></td></tr>')
        elseif is_disabled_line(line) then
          local raw_line = trim(line):gsub("^#%s*", "")
          local vd = parse_vhost_line(raw_line)
          r:puts('<tr class="disabled-row">')
          if is_geolock_line(raw_line) then
            local gparts = {}
            for w in raw_line:gmatch("%S+") do table.insert(gparts, w) end
            r:puts('<td>' .. macro_tag("GeoLock_VHost") .. '</td>')
            r:puts('<td>\xF0\x9F\x8C\x8D GeoLock</td>')
            r:puts('<td>' .. h(gparts[3] or "") .. '</td>')
            r:puts('<td colspan=2 style="font-size:.82em;color:#888">PIN-gesch\xC3\xBCtzt</td>')
          elseif vd then
            r:puts('<td>' .. macro_tag(vd.macro) .. '</td>')
            r:puts('<td>' .. h(vd.name) .. '</td>')
            r:puts('<td>' .. h(vd.domain) .. '</td>')
            r:puts('<td style="font-family:monospace;font-size:.82em">' .. h(vd.dest) .. '</td>')
            r:puts('<td style="font-size:.82em">' .. h(vd.users) .. '</td>')
          else
            r:puts('<td colspan=5 style="font-family:monospace;font-size:.82em">' .. h(raw_line) .. '</td>')
          end
          r:puts('<td><div class="actions">')
          r:puts('<form method="POST" action="/?action=toggle_disable" style="margin:0">')
          r:puts('<input type=hidden name=file value="' .. h(fname) .. '">')
          r:puts('<input type=hidden name=line value="' .. lineno .. '">')
          r:puts('<input type=hidden name=check value="' .. h(trim(line)) .. '">')
          r:puts('<input type=hidden name=toggle value="enable">')
          r:puts('<button class="btn b-enable" type=submit>Aktivieren</button></form>')
          r:puts('</div></td></tr>')
        end
      end
      r:puts('</table>')
    end
    r:puts('</div>')

    ::continue::
  end
  r:puts('</div></body></html>')
end

-- ── Entry form ────────────────────────────────────────────────────────────────

local function get_known_domains()
  local seen, ordered = {}, {}
  for _, fpath in ipairs(list_conf_files()) do
    local lines = read_lines(fpath)
    if lines then
      for _, line in ipairs(lines) do
        local v = parse_vhost_line(line)
        if v and v.domain ~= "" and not seen[v.domain] then
          seen[v.domain] = true
          table.insert(ordered, v.domain)
        end
      end
    end
  end
  table.sort(ordered)
  return ordered
end

local function show_form(r, fname, lineno, pre, errmsg)
  local title = lineno and "Eintrag bearbeiten" or "Neuer Eintrag"

  -- Load selection data before any HTML output
  local ht_users = htpasswd_list_users()
  local kc_users_list, kc_groups_list = nil, nil
  if KC_ADMIN_URL ~= "" then
    local tok, _ = kc_token(r)
    if tok then
      kc_users_list, _ = kc_list_users(tok)
      kc_groups_list, _ = kc_list_groups(tok)
    end
  end

  r:puts(page_head(title, "/"))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>' .. title .. ' — ' .. h(fname) .. '</h2>')
  if errmsg then r:puts(msg_html("ERR: " .. errmsg)) end

  r:puts('<form method="POST" action="/?action=save" onsubmit="return serializeUsers(this)">')
  r:puts('<input type=hidden name=file value="' .. h(fname) .. '">')
  r:puts('<input type=hidden name=users id=users_val value="' .. h((pre and pre.users) or "") .. '">')
  if lineno then
    r:puts('<input type=hidden name=line value="' .. lineno .. '">')
    r:puts('<input type=hidden name=check value="' .. h(pre and pre.raw or "") .. '">')
  end

  -- Macro type
  local cur = trim((pre and pre.macro) or "VHost_Proxy"):lower()
  r:puts('<div class="form-row"><label>Typ:</label><select name=macro onchange="onMacroChange(this)">')
  for _, m in ipairs(MACRO_TYPES) do
    local sel = (m:lower() == cur) and " selected" or ""
    r:puts('<option value="' .. m .. '"' .. sel .. '>' .. m .. '</option>')
  end
  r:puts('</select></div>')

  -- Name
  r:puts('<div class="form-row"><label>Name:</label>'
    .. '<input name=name value="' .. h((pre and pre.name) or "") .. '" placeholder="myapp" required></div>')

  -- Domain
  local known_domains = get_known_domains()
  local dl = '<datalist id="domain_list">'
  for _, d in ipairs(known_domains) do dl = dl .. '<option value="' .. h(d) .. '">' end
  dl = dl .. '</datalist>'
  r:puts('<div class="form-row"><label>Domain:</label>'
    .. '<input name=domain list="domain_list" value="' .. h((pre and pre.domain) or "") .. '" placeholder="example.com" required>'
    .. dl .. '</div>')

  -- Destination
  r:puts('<div class="form-row"><label>Ziel-URL:</label>'
    .. '<input name=dest id=dest_input onblur="normalizeDest(this)"'
    .. ' value="' .. h((pre and pre.dest) or "") .. '" placeholder="http://10.0.0.1:8080/" required></div>')
  r:puts('<div class="form-row"><label></label>'
    .. '<span class="dim" style="font-size:.8em">'
    .. 'http:// oder https:// &mdash; Trailing-Slash wird automatisch erg\xC3\xA4nzt'
    .. ' &mdash; Port optional (Standard: 80&nbsp;/&nbsp;443)'
    .. '</span></div>')

  -- Build set of currently selected values for pre-selection
  local pre_sel = {}
  if pre and (pre.users or "") ~= "" then
    for v in pre.users:gmatch("[^|]+") do pre_sel[trim(v)] = true end
  end
  local sel_style = "min-width:180px;background:#0d0d1a;color:#ddd;border:1px solid #2a2a4e;padding:.3em"

  -- OIDC users multi-select
  r:puts('<div class="form-row" id=row_oidc_users style="display:' .. (cur == "vhost_proxy_oidc_user" and "" or "none") .. '">')
  r:puts('<label>Benutzer:</label>')
  if kc_users_list then
    r:puts('<select multiple size=6 id=sel_oidc_users style="' .. sel_style .. '">')
    for _, u in ipairs(kc_users_list) do
      local s = pre_sel[u.username] and ' selected' or ''
      r:puts('<option value="' .. h(u.username) .. '"' .. s .. '>' .. h(u.username) .. '</option>')
    end
    r:puts('</select>')
  else
    r:puts('<input id=fb_oidc value="' .. h((pre and pre.users) or "") .. '" placeholder="alice|bob">')
  end
  r:puts('</div>')

  -- OIDC group multi-select
  r:puts('<div class="form-row" id=row_group_users style="display:' .. (cur == "vhost_proxy_oidc_group" and "" or "none") .. '">')
  r:puts('<label>Gruppen:</label>')
  if kc_groups_list then
    r:puts('<select multiple size=6 id=sel_group_users style="' .. sel_style .. '">')
    for _, g in ipairs(kc_groups_list) do
      local s = pre_sel[g.name] and ' selected' or ''
      r:puts('<option value="' .. h(g.name) .. '"' .. s .. '>' .. h(g.name) .. '</option>')
    end
    r:puts('</select>')
  else
    r:puts('<input id=fb_group value="' .. h((pre and pre.users) or "") .. '" placeholder="groupname">')
  end
  r:puts('</div>')

  -- Basic users multi-select
  r:puts('<div class="form-row" id=row_basic_users style="display:' .. (cur == "vhost_proxy_basic" and "" or "none") .. '">')
  r:puts('<label>Passwort-Eintrag:</label>')
  if #ht_users > 0 then
    r:puts('<select multiple size=6 id=sel_basic_users style="' .. sel_style .. '">')
    for _, u in ipairs(ht_users) do
      local s = pre_sel[u] and ' selected' or ''
      r:puts('<option value="' .. h(u) .. '"' .. s .. '>' .. h(u) .. '</option>')
    end
    r:puts('</select>')
  else
    r:puts('<input id=fb_basic value="' .. h((pre and pre.users) or "") .. '" placeholder="alice">')
    r:puts('<span class="dim" style="font-size:.8em"> (keine htpasswd-Eintr\xC3\xA4ge vorhanden)</span>')
  end
  r:puts('</div>')

  -- AuthType (Basic only)
  local show_auth = (cur == "vhost_proxy_basic")
  r:puts('<div class="form-row" id=row_auth style="display:' .. (show_auth and "" or "none") .. '">')
  r:puts('<label>Auth-Typ:</label>')
  r:puts('<input name=authtype value="' .. h((pre and pre.authtype ~= "" and pre.authtype) or "user") .. '" placeholder="user"></div>')

  r:puts('<div class="form-row" style="margin-top:1.2em">')
  r:puts('<button class="btn b-save" type=submit>&#10003;&nbsp;Speichern</button>&nbsp;')
  r:puts('<a class="btn b-cancel" href="/">Abbrechen</a>')
  r:puts('</div></form></div></div></body></html>')
end

-- ── Toggle disable (POST) ─────────────────────────────────────────────────────

local function do_toggle_disable(r, p)
  local fname  = trim(p["file"]   or "")
  local lineno = tonumber(p["line"])
  local check  = trim(p["check"]  or "")
  local toggle = trim(p["toggle"] or "")

  if fname == "" or fname:match("[/\\]") or not lineno then
    return show_list(r, "ERR: Ung\xC3\xBCltige Parameter")
  end
  if toggle ~= "disable" and toggle ~= "enable" then
    return show_list(r, "ERR: Unbekannte Aktion")
  end

  local fpath = SITES_DIR .. fname
  local lines = read_lines(fpath)
  if not lines then return show_list(r, "ERR: Datei nicht lesbar") end

  if trim(lines[lineno] or "") ~= check then
    return show_list(r, "ERR: Datei wurde zwischenzeitlich ge\xC3\xA4ndert \xe2\x80\x94 bitte neu laden")
  end

  if toggle == "disable" then
    if is_no_admin(lines, lineno) then
      return show_list(r, "ERR: Dieser Eintrag ist mit # no-admin gesch\xC3\xBCtzt")
    end
    lines[lineno] = "# " .. lines[lineno]
  else
    lines[lineno] = lines[lineno]:gsub("^%s*#%s*", "")
  end

  local ftmp = fpath .. ".tmp"
  local fbak  = fpath .. ".bak"
  local ok, err = write_lines(ftmp, lines)
  if not ok then return show_list(r, "ERR: " .. (err or "")) end

  os.rename(fpath, fbak)
  os.rename(ftmp,  fpath)

  local test_ok, test_out = configtest()
  if not test_ok then
    os.remove(fpath)
    os.rename(fbak, fpath)
    return show_list(r, "ERR: Konfigurationstest fehlgeschlagen \xe2\x80\x94 " .. (test_out or ""))
  end

  os.remove(fbak)
  set_pending_reload()
  local verb = toggle == "disable" and "Deaktiviert" or "Aktiviert"
  show_list(r, "OK: " .. verb .. " \xe2\x80\x94 Konfiguration noch anwenden!")
end

-- ── GeoLock status view ────────────────────────────────────────────────────────

local function show_geolock_view(r, msg)
  local lock_path = "/etc/apache2/conf-runtime/geolock.lock"
  local conf_path = "/etc/apache2/AddOn/.extra-countries.conf"
  local failures  = tonumber(read_file(lock_path) or "") or 0
  local locked    = failures >= 3
  local conf      = read_file(conf_path) or ""
  local codes     = conf:match('"^%(([A-Z|]+)%)%$"')

  r:puts(page_head("GeoLock"))
  if msg then r:puts(msg_html(msg)) end
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>\xF0\x9F\x8C\x8D GeoLock</h2>')
  r:puts('<table><tr><th>Status</th><th>Fehlversuche</th><th>Extra-L\xC3\xA4nder</th></tr><tr>')
  local status_cell = locked
    and '<span style="color:#ff8888">&#9679; Gesperrt</span>'
    or  '<span style="color:#88ff88">&#9679; Entsperrt</span>'
  r:puts('<td>' .. status_cell .. '</td>')
  r:puts('<td>' .. failures .. '\xC2\xA0/ 3</td>')
  r:puts('<td>' .. (codes and h(codes:gsub("|", ", ")) or '\xe2\x80\x93') .. '</td>')
  r:puts('</tr></table>')
  if failures > 0 then
    r:puts('<form method="POST" action="/?action=geolock_reset" style="margin-top:1em">')
    r:puts('<button class="btn b-add" type="submit">&#128275; Z\xC3\xA4hler zur\xC3\xBCcksetzen</button>')
    r:puts('</form>')
  end
  r:puts('<p class="dim" style="margin-top:1em">VHost aktivieren/deaktivieren: '
    .. '\xC3\xBCber die Hauptliste (Deaktivieren-Button).</p>')
  r:puts('</div></div></body></html>')
end

local function do_geolock_reset(r)
  local lock_path = "/etc/apache2/conf-runtime/geolock.lock"
  local f = io.open(lock_path, "w")
  if f then f:write("0\n"); f:close() end
  show_geolock_view(r, "OK: Z\xC3\xA4hler zur\xC3\xBCckgesetzt")
end

-- ── Save (POST) ───────────────────────────────────────────────────────────────

local function do_save(r, p)
  local fname    = trim(p["file"]    or "")
  local lineno   = tonumber(p["line"])
  local check    = trim(p["check"]   or "")
  local macro    = trim(p["macro"]   or "")
  local name     = trim(p["name"]    or "")
  local domain   = trim(p["domain"]  or "")
  local dest     = trim(p["dest"]    or "")
  local users    = trim(p["users"]   or "")
  local authtype = trim(p["authtype"] or "user")

  -- Normalize dest: lowercase scheme, add trailing slash if no path present
  dest = dest:gsub("^(%a+://)", function(s) return s:lower() end)
  if dest:match("^https?://[^/]+$") then dest = dest .. "/" end

  -- Validate
  if fname == "" or fname:match("[/\\]") then
    return show_list(r, "ERR: Ungültiger Dateiname")
  end
  if not validate_name(name) then
    return show_form(r, fname, lineno,
      {macro=macro,name=name,domain=domain,dest=dest,users=users,authtype=authtype,raw=check},
      "Ungültiger Name (a-z, 0-9, -, _ erlaubt)")
  end
  if not validate_domain(domain) then
    return show_form(r, fname, lineno,
      {macro=macro,name=name,domain=domain,dest=dest,users=users,authtype=authtype,raw=check},
      "Ungültige Domain")
  end
  if not validate_dest(dest) then
    return show_form(r, fname, lineno,
      {macro=macro,name=name,domain=domain,dest=dest,users=users,authtype=authtype,raw=check},
      "Ungültige Ziel-URL (keine Sonderzeichen ; | ` $ < >)")
  end
  if users ~= "" and not validate_users(users) then
    return show_form(r, fname, lineno,
      {macro=macro,name=name,domain=domain,dest=dest,users=users,authtype=authtype,raw=check},
      "Ungültige Benutzer (a-z, 0-9, ., @, _, |, - erlaubt)")
  end

  local new_line = build_line(macro, name, domain, dest, users, authtype)
  if not new_line then
    return show_form(r, fname, lineno, nil, "Unbekannter Macro-Typ: " .. macro)
  end

  local fpath = SITES_DIR .. fname
  local lines = read_lines(fpath)
  if not lines then
    return show_list(r, "ERR: Datei nicht lesbar: " .. fname)
  end

  if lineno then
    -- Edit: verify line hasn't changed since form was loaded
    if trim(lines[lineno] or "") ~= check then
      return show_list(r, "ERR: Datei wurde zwischenzeitlich geändert — bitte neu laden")
    end
    if is_no_admin(lines, lineno) then
      return show_list(r, "ERR: Dieser Eintrag ist mit # no-admin geschützt")
    end
    lines[lineno] = new_line
  else
    -- Add: insert before Domain_Final, or before last non-empty line
    local insert_pos = #lines + 1
    for i = #lines, 1, -1 do
      if lines[i]:lower():match("^%s*use%s+domain_final") then
        insert_pos = i
        break
      end
    end
    table.insert(lines, insert_pos, new_line)
  end

  -- Write to .tmp, swap with .bak, run configtest, restore .bak on failure
  local ftmp = fpath .. ".tmp"
  local fbak = fpath .. ".bak"

  local ok, err = write_lines(ftmp, lines)
  if not ok then
    return show_list(r, "ERR: Temp-Datei nicht schreibbar — " .. (err or ""))
  end

  os.rename(fpath, fbak)
  os.rename(ftmp,  fpath)

  local test_ok, test_out = configtest()
  if not test_ok then
    os.remove(fpath)
    os.rename(fbak, fpath)
    return show_list(r, "ERR: Konfigurationstest fehlgeschlagen — Änderungen nicht gespeichert.\n" .. (test_out or ""))
  end

  os.remove(fbak)
  set_pending_reload()
  show_list(r, "OK: Gespeichert (Konfigurationstest erfolgreich) — Konfiguration noch anwenden!")
end

-- ── Delete (POST) ─────────────────────────────────────────────────────────────

local function do_delete(r, p)
  local fname  = trim(p["file"]  or "")
  local lineno = tonumber(p["line"])
  local check  = trim(p["check"] or "")

  if fname == "" or fname:match("[/\\]") or not lineno then
    return show_list(r, "ERR: Ungültige Parameter")
  end

  local fpath = SITES_DIR .. fname
  local lines = read_lines(fpath)
  if not lines then return show_list(r, "ERR: Datei nicht lesbar") end

  if trim(lines[lineno] or "") ~= check then
    return show_list(r, "ERR: Datei wurde zwischenzeitlich geändert — bitte neu laden")
  end
  if is_no_admin(lines, lineno) then
    return show_list(r, "ERR: Dieser Eintrag ist mit # no-admin geschützt")
  end

  table.remove(lines, lineno)

  local ftmp = fpath .. ".tmp"
  local fbak = fpath .. ".bak"

  local ok, err = write_lines(ftmp, lines)
  if not ok then
    return show_list(r, "ERR: Temp-Datei nicht schreibbar — " .. (err or ""))
  end

  os.rename(fpath, fbak)
  os.rename(ftmp,  fpath)

  local test_ok, test_out = configtest()
  if not test_ok then
    os.remove(fpath)
    os.rename(fbak, fpath)
    return show_list(r, "ERR: Konfigurationstest fehlgeschlagen — Änderungen nicht gespeichert.\n" .. (test_out or ""))
  end

  os.remove(fbak)
  set_pending_reload()
  show_list(r, "OK: Gelöscht (Konfigurationstest erfolgreich) — Konfiguration noch anwenden!")
end

-- ── Apply (POST) ──────────────────────────────────────────────────────────────

local kc_sync_redirects  -- forward declaration; assigned after KC helpers below

local function do_apply(r)
  local test_ok, test_out = configtest()
  if not test_ok then
    return show_list(r, "ERR: Konfigurationstest fehlgeschlagen — Reload abgebrochen.\n" .. (test_out or ""))
  end
  if not _apache_reload() then
    return show_list(r, "ERR: Graceful reload fehlgeschlagen")
  end
  clear_pending_reload()
  local msg = "OK: Apache graceful reload ausgef\xC3\xBCh\x72t"
  if KC_ADMIN_URL ~= "" and kc_sync_redirects then
    local tok, _ = kc_token(r)
    if tok and TOC_DOMAIN ~= "" then
      local ok, kmsg = kc_sync_redirects(TOC_DOMAIN, tok)
      if ok then
        msg = msg .. "\nOK: Keycloak redirect URIs aktualisiert (" .. kmsg .. ")"
      else
        msg = msg .. "\nWARN: Keycloak sync fehlgeschlagen — " .. kmsg
      end
    end
  end
  show_list(r, msg)
end

-- ── AddOn form ────────────────────────────────────────────────────────────────

-- pre_override / post_override: when not nil, these override what's read from disk
-- (used to redisplay attempted content after a failed configtest)
local function show_addon_form(r, name, domain, errmsg, testout, pre_override, post_override)
  r:puts(page_head("AddOn: " .. name .. "." .. domain, "/"))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>AddOn-Konfiguration — <code>' .. h(name) .. '.' .. h(domain) .. '</code></h2>')
  r:puts('<p style="color:#888;font-size:.85em;margin-bottom:.8em">'
    .. 'Diese Direktiven werden direkt vor bzw. nach dem ProxyPass in den VHost eingefügt.<br>'
    .. 'Typisch: SSL-Proxy-Einstellungen, eigene Header, ProxyPassMatch für WebSockets.<br>'
    .. '<strong>Speichern testet die Konfiguration automatisch — bei Fehler wird nichts gespeichert.</strong>'
    .. '</p>')
  if errmsg then
    r:puts('<div class="msg err">' .. h(errmsg) .. '</div>')
  end
  if testout and testout ~= "" then
    r:puts('<pre style="background:#0a0005;color:#ff9999;padding:.7em;border-radius:3px;'
      .. 'font-size:.8em;overflow-x:auto;margin-bottom:.8em">' .. h(testout) .. '</pre>')
  end

  local pre_path  = addon_path(domain, name, "preconfig")
  local post_path = addon_path(domain, name, "postconfig")
  local pre_bak   = pre_path  .. ".bak"
  local post_bak  = post_path .. ".bak"
  local has_bak   = fexists(pre_bak) or fexists(post_bak)

  -- Show restore-from-backup button when a previous version exists
  if has_bak then
    r:puts('<form method="POST" action="/?action=addon_restore" style="margin-bottom:.7em">')
    r:puts('<input type=hidden name=name   value="' .. h(name)   .. '">')
    r:puts('<input type=hidden name=domain value="' .. h(domain) .. '">')
    r:puts('<button class="btn" style="background:#2a1a00;color:#ffaa33" type=submit>'
      .. '&#8635;&nbsp;Auf letzte gespeicherte Version zurücksetzen</button>')
    r:puts('</form>')
  end

  -- Use override content (after a failed save) or read from disk
  local pre_content  = pre_override  ~= nil and pre_override  or read_file(pre_path)
  local post_content = post_override ~= nil and post_override or read_file(post_path)

  r:puts('<form method="POST" action="/?action=addon_save">')
  r:puts('<input type=hidden name=name   value="' .. h(name)   .. '">')
  r:puts('<input type=hidden name=domain value="' .. h(domain) .. '">')

  r:puts('<div style="margin-bottom:1em">')
  r:puts('<label style="color:#aaa;font-size:.9em;display:block;margin-bottom:.3em">'
    .. 'Pre-Config <span style="color:#666">(' .. h(pre_path) .. ')</span></label>')
  r:puts('<textarea name=pre_content rows=10 style="'
    .. 'width:100%;background:#060614;color:#ddd;border:1px solid #3a3a6e;'
    .. 'border-radius:3px;padding:8px;font-family:monospace;font-size:.85em;resize:vertical">'
    .. h(pre_content) .. '</textarea>')
  r:puts('</div>')

  r:puts('<div style="margin-bottom:1.2em">')
  r:puts('<label style="color:#aaa;font-size:.9em;display:block;margin-bottom:.3em">'
    .. 'Post-Config <span style="color:#666">(' .. h(post_path) .. ')</span></label>')
  r:puts('<textarea name=post_content rows=6 style="'
    .. 'width:100%;background:#060614;color:#ddd;border:1px solid #3a3a6e;'
    .. 'border-radius:3px;padding:8px;font-family:monospace;font-size:.85em;resize:vertical">'
    .. h(post_content) .. '</textarea>')
  r:puts('</div>')

  r:puts('<div class="form-row" style="margin-top:1.2em">')
  r:puts('<button class="btn b-save" type=submit>&#10003;&nbsp;Speichern &amp; Testen</button>&nbsp;')
  r:puts('<a class="btn b-cancel" href="/">Abbrechen</a>')
  r:puts('</div></form></div></div></body></html>')
end

local function do_addon_save(r, p)
  local name         = trim(p["name"]         or "")
  local domain       = trim(p["domain"]       or "")
  local pre_content  = p["pre_content"]  or ""
  local post_content = p["post_content"] or ""

  if not validate_name(name) or not validate_domain(domain) then
    return show_list(r, "ERR: Ungültige Parameter")
  end

  -- Reject obviously dangerous content (mod_lua runs as www-data, but still)
  for _, content in ipairs({pre_content, post_content}) do
    if content:find("\0") then
      return show_list(r, "ERR: Ungültiger Inhalt (Null-Bytes)")
    end
  end

  local pre_path  = addon_path(domain, name, "preconfig")
  local post_path = addon_path(domain, name, "postconfig")
  local pre_bak   = pre_path  .. ".bak"
  local post_bak  = post_path .. ".bak"

  -- Move existing files to .bak before touching anything
  local pre_existed  = fexists(pre_path)
  local post_existed = fexists(post_path)
  if pre_existed  then os.rename(pre_path,  pre_bak)  end
  if post_existed then os.rename(post_path, post_bak) end

  -- Write new content (empty string = don't create file)
  local ok, err = write_file(pre_path,  pre_content)
  if not ok then
    if pre_existed  then os.rename(pre_bak,  pre_path)  end
    if post_existed then os.rename(post_bak, post_path) end
    return show_addon_form(r, name, domain, "ERR: " .. err)
  end
  ok, err = write_file(post_path, post_content)
  if not ok then
    os.remove(pre_path)
    if pre_existed  then os.rename(pre_bak,  pre_path)  end
    if post_existed then os.rename(post_bak, post_path) end
    return show_addon_form(r, name, domain, "ERR: " .. err)
  end

  -- Config test — on failure: discard new files, restore .bak, show form with attempted content
  local test_ok, test_out = configtest()
  if not test_ok then
    os.remove(pre_path)
    os.remove(post_path)
    if pre_existed  then os.rename(pre_bak,  pre_path)  end
    if post_existed then os.rename(post_bak, post_path) end
    -- Pass the attempted content back so the user can edit and retry
    return show_addon_form(r, name, domain,
      "ERR: Konfigurationstest fehlgeschlagen — Änderungen nicht gespeichert.", test_out,
      pre_content, post_content)
  end

  -- Success: keep .bak as a restorable snapshot (overwrite any older .bak)
  -- .bak files are cleaned up only when the user explicitly restores or when no pre/post existed
  set_pending_reload()
  show_list(r, "OK: AddOn gespeichert (Konfigurationstest erfolgreich) — Konfiguration noch anwenden!")
end

-- ── AddOn restore (POST) ─────────────────────────────────────────────────────

local function do_addon_restore(r, p)
  local name   = trim(p["name"]   or "")
  local domain = trim(p["domain"] or "")

  if not validate_name(name) or not validate_domain(domain) then
    return show_list(r, "ERR: Ungültige Parameter")
  end

  local pre_path  = addon_path(domain, name, "preconfig")
  local post_path = addon_path(domain, name, "postconfig")
  local pre_bak   = pre_path  .. ".bak"
  local post_bak  = post_path .. ".bak"

  if not fexists(pre_bak) and not fexists(post_bak) then
    return show_addon_form(r, name, domain, "ERR: Kein Backup vorhanden")
  end

  -- Write restored content to .tmp, test, swap on success
  local restored_pre  = read_file(pre_bak)
  local restored_post = read_file(post_bak)

  -- Save current files to tmp-bak before overwriting
  local cur_pre  = read_file(pre_path)
  local cur_post = read_file(post_path)

  local ok, err = write_file(pre_path,  restored_pre)
  if not ok then return show_addon_form(r, name, domain, "ERR: " .. err) end
  ok, err = write_file(post_path, restored_post)
  if not ok then
    write_file(pre_path, cur_pre)
    return show_addon_form(r, name, domain, "ERR: " .. err)
  end

  local test_ok, test_out = configtest()
  if not test_ok then
    write_file(pre_path,  cur_pre)
    write_file(post_path, cur_post)
    return show_addon_form(r, name, domain,
      "ERR: Backup-Konfigurationstest fehlgeschlagen — Restore nicht möglich.", test_out)
  end

  -- Clean up .bak after successful restore
  os.remove(pre_bak)
  os.remove(post_bak)
  set_pending_reload()
  show_list(r, "OK: AddOn auf letzte Version zurückgesetzt (Konfigurationstest erfolgreich) — noch anwenden!")
end

-- ── Keycloak User & Group management ─────────────────────────────────────────

-- Generic GET against the Keycloak Admin API.
local function kc_api_get(path, token)
  local base = KC_BASE_URL
  local tmp = os.tmpname()
  io.open(tmp,"w"):write("Authorization: Bearer " .. token):close()
  -- Append "\nHTTP_STATUS:NNN" so we can detect non-200 responses.
  local cmd = string.format(
    'curl -s -k -H @%s -w "\\nHTTP_STATUS:%%{http_code}" "%s%s" 2>/dev/null',
    tmp, base, path)
  local p = io.popen(cmd); local out = p:read("*a"); p:close()
  os.remove(tmp)
  local body   = out:gsub("\nHTTP_STATUS:%d+%s*$", "")
  local status = tonumber(out:match("\nHTTP_STATUS:(%d+)")) or 0
  return body, status
end

-- Generic write (POST/PUT/DELETE) against the Keycloak Admin API.
-- body may be nil for DELETE/PUT without body.
-- Returns status, response_body (body may be empty for success responses).
local function kc_api_write(method, path, body, token)
  local base = KC_BASE_URL
  local tmp_h = os.tmpname()
  local tmp_o = os.tmpname()
  io.open(tmp_h,"w"):write("Authorization: Bearer " .. token):close()
  local cmd
  if body then
    local tmp_b = os.tmpname()
    io.open(tmp_b,"w"):write(body):close()
    cmd = string.format(
      'curl -s -k -o %s -w "%%{http_code}" -X %s'
      ..' -H @%s -H "Content-Type: application/json" --data @%s "%s%s" 2>/dev/null',
      tmp_o, method, tmp_h, tmp_b, base, path)
    local p = io.popen(cmd); local status = tonumber(p:read("*a") or "0"); p:close()
    local f = io.open(tmp_o); local rbody = f and f:read("*a") or ""; if f then f:close() end
    os.remove(tmp_h); os.remove(tmp_b); os.remove(tmp_o)
    return status, rbody
  else
    cmd = string.format(
      'curl -s -k -o %s -w "%%{http_code}" -X %s -H @%s "%s%s" 2>/dev/null',
      tmp_o, method, tmp_h, base, path)
    local p = io.popen(cmd); local status = tonumber(p:read("*a") or "0"); p:close()
    local f = io.open(tmp_o); local rbody = f and f:read("*a") or ""; if f then f:close() end
    os.remove(tmp_h); os.remove(tmp_o)
    return status, rbody
  end
end

-- Extract Keycloak error description from a JSON error response body.
local function kc_errmsg(rbody)
  return rbody:match('"error_description"%s*:%s*"([^"]+)"')
      or rbody:match('"errorMessage"%s*:%s*"([^"]+)"')
      or rbody:match('"error"%s*:%s*"([^"]+)"')
end

-- Parse a flat JSON object block into a Lua table (strings + booleans).
local function json_obj_flat(s)
  local t = {}
  for k, v in s:gmatch('"([^"]+)"%s*:%s*"([^"]*)"') do t[k] = v end
  for k    in s:gmatch('"([^"]+)"%s*:%s*true')       do t[k] = true  end
  for k    in s:gmatch('"([^"]+)"%s*:%s*false')      do t[k] = false end
  return t
end

-- Parse a JSON array of flat objects.
local function json_arr_flat(s)
  local result = {}
  for block in s:gmatch("%b{}") do
    local obj = json_obj_flat(block)
    if obj.id then result[#result+1] = obj end  -- skip empty blocks
  end
  return result
end

-- Fetch all users (max 500, skip service accounts).
-- Returns (list, nil) on success or (nil, errmsg) on failure.
kc_list_users = function(token)
  local raw, status = kc_api_get("/users?max=500", token)
  if status ~= 200 then
    local detail = status == 403
      and " \xE2\x80\x94 Account ben\xC3\xB6tigt manage-users / view-users Rolle in Keycloak"
      or  ""
    return nil, "Keycloak /users: HTTP " .. tostring(status) .. detail
  end
  local all = json_arr_flat(raw)
  local out = {}
  for _, u in ipairs(all) do
    if not (u.username or ""):match("^service%-account%-") then
      out[#out+1] = u
    end
  end
  return out, nil
end

-- Fetch all groups (flat list).
-- Returns (list, nil) on success or (nil, errmsg) on failure.
kc_list_groups = function(token)
  local raw, status = kc_api_get("/groups?max=200", token)
  if status ~= 200 then
    local detail = status == 403
      and " \xE2\x80\x94 Account ben\xC3\xB6tigt view-groups Rolle in Keycloak"
      or  ""
    return nil, "Keycloak /groups: HTTP " .. tostring(status) .. detail
  end
  return json_arr_flat(raw), nil
end

-- Fetch group IDs a user belongs to; returns {id→name} map.
local function kc_user_group_map(uid, token)
  local m = {}
  for _, g in ipairs(json_arr_flat(kc_api_get("/users/" .. uid .. "/groups", token))) do
    m[g.id] = g.name or ""
  end
  return m
end

-- Set user's group memberships to exactly the given list of group IDs.
-- Returns nil on success, error string on first failure.
local function kc_user_set_groups(uid, desired_ids, token)
  local current = kc_user_group_map(uid, token)
  local desired = {}
  for _, id in ipairs(desired_ids) do desired[id] = true end
  -- Add new
  for id in pairs(desired) do
    if not current[id] then
      local st, rb = kc_api_write("PUT", "/users/" .. uid .. "/groups/" .. id, nil, token)
      if st ~= 204 then
        return kc_errmsg(rb) or ("Gruppe setzen fehlgeschlagen: HTTP " .. tostring(st))
      end
    end
  end
  -- Remove old
  for id in pairs(current) do
    if not desired[id] then
      local st, rb = kc_api_write("DELETE", "/users/" .. uid .. "/groups/" .. id, nil, token)
      if st ~= 204 then
        return kc_errmsg(rb) or ("Gruppe entfernen fehlgeschlagen: HTTP " .. tostring(st))
      end
    end
  end
end

-- Create a user. Returns new UUID or nil + error string.
local function kc_user_create(data, token)
  local payload = json_enc({
    username  = data.username,
    email     = data.email     ~= "" and data.email     or nil,
    firstName = data.firstName ~= "" and data.firstName or nil,
    lastName  = data.lastName  ~= "" and data.lastName  or nil,
    enabled   = true,
    credentials = {{ type="password", value=data.password, temporary=false }},
  })
  local status, rbody = kc_api_write("POST", "/users", payload, token)
  if status ~= 201 then
    local detail = kc_errmsg(rbody)
    return nil, detail or ("Keycloak antwortete mit HTTP " .. tostring(status))
  end
  -- Fetch the new user's UUID
  local found = json_arr_flat(kc_api_get(
    "/users?username=" .. data.username .. "&exact=true", token))
  if #found == 0 then return nil, "Nutzer angelegt, aber UUID nicht lesbar" end
  return found[1].id, nil
end

-- Update user fields (email, firstName, lastName). Returns nil on success, error string on failure.
local function kc_user_update(uid, data, token)
  local payload = json_enc({
    email     = data.email     or "",
    firstName = data.firstName or "",
    lastName  = data.lastName  or "",
    enabled   = true,
  })
  local status, rbody = kc_api_write("PUT", "/users/" .. uid, payload, token)
  if status == 204 then return nil end
  return kc_errmsg(rbody) or ("Keycloak antwortete mit HTTP " .. tostring(status))
end

-- Reset a user's password.
-- Returns nil on success, error string on failure.
local function kc_user_reset_pw(uid, password, token)
  local status, rbody = kc_api_write("PUT", "/users/" .. uid .. "/reset-password",
    json_enc({type="password", value=password, temporary=false}), token)
  if status == 204 then return nil end
  return kc_errmsg(rbody) or ("Keycloak antwortete mit HTTP " .. tostring(status))
end

-- Delete a user.
local function kc_user_delete(uid, token)
  return kc_api_write("DELETE", "/users/" .. uid, nil, token) == 204
end

-- Accounts that must not be deleted via the UI.
local KC_PROTECTED_USERS = { admin=true, claude=true }
-- Groups ending in -admins or -users (domain or global) must not be deleted via the UI.
local function is_protected_group(name)
  return name ~= nil and (name:match("%-admins$") ~= nil or name:match("%-users$") ~= nil)
end
-- Returns true if the currently logged-in user is a member of global-admins.
local function is_global_admin(r)
  local raw = (r.subprocess_env and r.subprocess_env["OIDC_CLAIM_groups"]) or ""
  return raw:find("global%-admins") ~= nil
end

-- ── Keycloak insufficient-rights notice ───────────────────────────────────────

-- Shown when the OIDC token does not have Keycloak admin rights.
-- Instructs the user to log out and re-login with an account that has the roles.
local function show_kc_login(r, errmsg)
  r:puts(page_head("Keine Admin-Rechte", "/"))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>Keycloak-Admin-Rechte erforderlich</h2>')
  if errmsg and errmsg ~= "needs_login" then
    r:puts(msg_html("ERR: " .. errmsg))
  end
  r:puts('<p>Der aktuell angemeldete Account hat keine ausreichenden Rechte '
    .. 'zur Nutzerverwaltung in Keycloak.</p>')
  r:puts('<p>Bitte abmelden und mit einem Account mit <code>manage-users</code>-Rolle '
    .. 'neu anmelden.</p>')
  r:puts('<div class="applybar">')
  local _redir = TOC_DOMAIN ~= "" and ("https://admin." .. TOC_DOMAIN .. "/?action=users") or "/?action=users"
  local _lo = TOC_DOMAIN ~= "" and ("https://admin." .. TOC_DOMAIN .. "/protected?logout=" .. ue(_redir)) or _redir
  r:puts('<a class="btn b-del" href="' .. h(_lo) .. '">Abmelden &amp; neu einloggen</a>')
  r:puts('</div></div></div></body></html>')
end

-- ── User/group pages ──────────────────────────────────────────────────────────

local function show_users(r, msg)
  r:puts(page_head("Nutzerverwaltung", "/"))
  r:puts('<div class="main">')
  if msg then r:puts(msg_html(msg)) end
  r:puts('<div class="applybar">')
  r:puts('<a class="btn b-add" href="/?action=user_new">+ Neuer Nutzer</a>')
  r:puts('<a class="btn b-add" href="/?action=group_new">+ Neue Gruppe</a>')
  r:puts('</div>')

  if KC_ADMIN_URL == "" then
    r:puts('<div class="card"><p class="dim">KEYCLOAK_ADMIN_URL nicht gesetzt '
      .. '— Keycloak-Integration nicht verf\xC3\xBCgbar.</p></div>')
    r:puts('</div></body></html>')
    return
  end

  local tok, terr = kc_token(r)
  if not tok then
    r:puts('</div></body></html>')
    show_kc_login(r, terr)
    return
  end

  local users,  uerr = kc_list_users(tok)
  local groups, gerr = kc_list_groups(tok)

  -- 403/401 = Infokarte; sonstige Fehler → ERR sichtbar lassen
  local is403 = (uerr and uerr:find("HTTP 403")) or (gerr and gerr:find("HTTP 403"))
  local is401 = (uerr and uerr:find("HTTP 401")) or (gerr and gerr:find("HTTP 401"))
  if is403 or is401 then
    local _redir2 = TOC_DOMAIN ~= "" and ("https://admin." .. TOC_DOMAIN .. "/?action=users") or "/?action=users"
    local logout_link = TOC_DOMAIN ~= "" and ("https://admin." .. TOC_DOMAIN .. "/protected?logout=" .. ue(_redir2)) or _redir2
    local msg = is403
      and '<p style="margin:.5em 0">Das angemeldete Konto hat keine Berechtigung, die Keycloak-Nutzerliste abzurufen.</p>'
       .. '<p style="margin:.5em 0 1em">Bitte melden Sie sich ab und erneut mit einem Administrator-Konto an, oder wenden Sie sich an den Systemadministrator.</p>'
      or  '<p style="margin:.5em 0">Kein g\xC3\xBCltiges Token f\xC3\xBCr den Zugriff auf Keycloak vorhanden.</p>'
       .. '<p style="margin:.5em 0 1em">Bitte ab- und wieder anmelden.</p>'
    r:puts('<div class="card" style="border-color:#3a3a00">'
      .. '<h2 style="color:#ffee66;border-color:#3a3a00">Keycloak-Nutzerverwaltung nicht verf\xC3\xBCgbar</h2>'
      .. msg
      .. '<a class="btn b-warn" href="' .. h(logout_link) .. '">Abmelden</a>'
      .. '</div>')
  else
    if uerr then r:puts(msg_html("ERR: " .. uerr)) end
    if gerr and gerr ~= uerr then r:puts(msg_html("ERR: " .. gerr)) end
  end

  users  = users  or {}
  groups = groups or {}

  -- Users card
  r:puts('<div class="card">')
  r:puts('<h2>Nutzer (' .. #users .. ')</h2>')
  if #users == 0 then
    r:puts('<p class="dim">' .. (uerr and "Keine Daten \xE2\x80\x94 siehe Fehler oben." or "Keine Nutzer gefunden.") .. '</p>')
  else
    r:puts('<table><tr>'
      .. '<th>Benutzername</th><th>E-Mail</th><th>Name</th><th>Gruppen</th><th>Aktionen</th>'
      .. '</tr>')
    for _, u in ipairs(users) do
      local gmap = kc_user_group_map(u.id, tok)
      local gbadges = ""
      for _, gname in pairs(gmap) do
        gbadges = gbadges .. '<span class="tag">' .. h(gname) .. '</span> '
      end
      local fullname = trim((u.firstName or "") .. " " .. (u.lastName or ""))
      r:puts('<tr>')
      r:puts('<td><strong>' .. h(u.username or "") .. '</strong></td>')
      r:puts('<td style="font-size:.85em">' .. h(u.email or "") .. '</td>')
      r:puts('<td style="font-size:.85em">' .. h(fullname) .. '</td>')
      r:puts('<td style="font-size:.82em">' .. gbadges .. '</td>')
      r:puts('<td><div class="actions">')
      -- Edit: POST form so credentials flow through
      r:puts('<a class="btn b-edit" href="/?action=user_edit&uid=' .. h(u.id) .. '">Bearbeiten</a>')
      if not KC_PROTECTED_USERS[u.username] then
        r:puts('<form method="POST" action="/?action=user_delete" style="display:inline"'
          .. ' onsubmit="return confirm(\'Nutzer &quot;' .. h(u.username or "") .. '&quot; wirklich l\xC3\xB6schen?\')">')
        r:puts('<input type=hidden name=uid value="'       .. h(u.id)             .. '">')
        r:puts('<input type=hidden name=username value="'  .. h(u.username or "") .. '">')
        r:puts('<button class="btn b-del" type=submit>L\xC3\xB6schen</button></form>')
      end
      r:puts('</div></td></tr>')
    end
    r:puts('</table>')
  end
  r:puts('</div>')

  -- Groups card
  r:puts('<div class="card">')
  r:puts('<h2>Gruppen (' .. #groups .. ')</h2>')
  if #groups == 0 and gerr then
    r:puts('<p class="dim">Keine Daten \xE2\x80\x94 siehe Fehler oben.</p></div>')
    r:puts('</div></body></html>')
    return
  end
  r:puts('<table><tr><th>Name</th><th>Typ</th><th>Aktionen</th></tr>')
  for _, g in ipairs(groups) do
    local is_protected = is_protected_group(g.name)
    local is_global    = (g.name or ""):match("^global%-") ~= nil
    r:puts('<tr>')
    r:puts('<td><code>' .. h(g.name or "") .. '</code></td>')
    r:puts('<td>' .. (is_global
      and '<span class="tag" style="background:#1a1a1a;color:#666">Global</span>'
      or  '<span class="tag">Domain</span>') .. '</td>')
    r:puts('<td><div class="actions">')
    if not is_protected then
      r:puts('<form method="POST" action="/?action=group_delete" style="display:inline"'
        .. ' onsubmit="return confirm(\'Gruppe &quot;' .. h(g.name or "") .. '&quot; l\xC3\xB6schen?\')">')
      r:puts('<input type=hidden name=gid   value="' .. h(g.id)   .. '">')
      r:puts('<input type=hidden name=gname value="' .. h(g.name or "") .. '">')
      r:puts('<button class="btn b-del" type=submit>L\xC3\xB6schen</button></form>')
    end
    r:puts('</div></td></tr>')
  end
  r:puts('</table></div>')

  r:puts('</div></body></html>')
end

-- Render the user create/edit form.
-- uid=nil → new user; uid=string → edit existing.
local function show_user_form(r, uid, pre, msg)
  local is_new = (uid == nil or uid == "")

  -- Fetch all data BEFORE writing any HTML to avoid double-page output on error
  if KC_ADMIN_URL == "" then
    r:puts(page_head(is_new and "Neuer Nutzer" or "Nutzer bearbeiten", "/?action=users"))
    r:puts('<div class="main"><div class="card">')
    r:puts('<h2>' .. (is_new and "Neuer Nutzer" or "Nutzer bearbeiten") .. '</h2>')
    r:puts('<p class="dim">KEYCLOAK_ADMIN_URL nicht gesetzt.</p></div></div></body></html>')
    return
  end

  local tok, terr = kc_token(r)
  if not tok then
    show_kc_login(r, terr)
    return
  end

  local all_groups, gerr2 = kc_list_groups(tok)
  if gerr2 and gerr2:find("401") then
    show_kc_login(r, gerr2)
    return
  end
  all_groups = all_groups or {}

  local user_group_ids = {}
  if not is_new then
    user_group_ids = kc_user_group_map(uid, tok)
  end

  -- Now render the page
  r:puts(page_head(is_new and "Neuer Nutzer" or "Nutzer bearbeiten", "/?action=users"))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>' .. (is_new and "Neuer Nutzer" or "Nutzer bearbeiten: <code>" .. h((pre or {}).username or "") .. "</code>") .. '</h2>')
  if msg then r:puts(msg_html(msg)) end
  if gerr2 then r:puts(msg_html("ERR: " .. gerr2)) end

  local p = pre or {}
  local action_url = is_new
    and "/?action=user_create"
    or  ("/?action=user_save&uid=" .. h(uid))

  -- JS: serialize checkboxes → hidden CSV field on submit
  r:puts('<script>')
  r:puts('function serializeGroups(form){')
  r:puts('  var ids=Array.from(form.querySelectorAll("input.grp-cb:checked")).map(function(c){return c.value;});')
  r:puts('  form.querySelector("#groups_csv").value=ids.join(",");')
  r:puts('  return true;')
  r:puts('}')
  r:puts('</script>')

  r:puts('<form method="POST" action="' .. h(action_url) .. '" onsubmit="return serializeGroups(this)">')
  r:puts('<input type=hidden name=groups_csv id=groups_csv value="">')

  -- Username
  r:puts('<div class="uf-field">')
  r:puts('<label>Benutzername</label>')
  if is_new then
    r:puts('<input type="text" name="username" value="' .. h(p.username or "") .. '" required autocomplete=off>')
  else
    r:puts('<code style="font-size:.95em">' .. h(p.username or "") .. '</code>')
    r:puts('<input type=hidden name=username value="' .. h(p.username or "") .. '">')
  end
  r:puts('</div>')

  -- E-Mail
  r:puts('<div class="uf-field"><label>E-Mail</label>')
  r:puts('<input type="email" name="email" value="' .. h(p.email or "") .. '" autocomplete=off>')
  r:puts('</div>')

  -- First / Last name
  r:puts('<div style="display:flex;gap:1em;margin-bottom:.8em">')
  for _, f in ipairs({{"firstName","Vorname"},{"lastName","Nachname"}}) do
    r:puts('<div class="uf-field" style="flex:1;margin-bottom:0"><label>' .. f[2] .. '</label>')
    r:puts('<input type="text" name="' .. f[1] .. '" value="' .. h(p[f[1]] or "") .. '" style="max-width:none;width:100%">')
    r:puts('</div>')
  end
  r:puts('</div>')

  -- Password
  r:puts('<div class="uf-field">')
  r:puts('<label>' .. (is_new and 'Initiales Passwort' or 'Neues Passwort <span class="dim">(leer = unver\xC3\xA4ndert)</span>') .. '</label>')
  r:puts('<input type="password" name="password"' .. (is_new and ' required' or '') .. ' autocomplete=new-password>')
  r:puts('</div>')

  -- Group checkboxes
  local is_gadmin = is_global_admin(r)
  r:puts('<div class="uf-field"><label>Gruppen</label>')
  r:puts('<div class="grp-checks">')
  for _, g in ipairs(all_groups) do
    local checked   = user_group_ids[g.id] and ' checked' or ''
    local is_global = (g.name or ""):match("^global%-") ~= nil
    local disabled  = (is_global and not is_gadmin) and ' disabled' or ''
    r:puts('<label' .. (disabled ~= "" and ' title="Nur Global-Admins k\xC3\xB6nnen diese Gruppe verwalten"' or '') .. '>')
    r:puts('<input type="checkbox" class="grp-cb" value="' .. h(g.id) .. '"' .. checked .. disabled .. '>')
    r:puts('<span class="tag"' .. (disabled ~= "" and ' style="opacity:.45"' or '') .. '>' .. h(g.name or "") .. '</span>')
    r:puts('</label>')
  end
  r:puts('</div></div>')

  -- Buttons
  r:puts('<div style="display:flex;gap:.7em;margin-top:1.2em">')
  r:puts('<button class="btn b-add" type="submit">' .. (is_new and 'Anlegen' or 'Speichern') .. '</button>')
  r:puts('<a class="btn b-cancel" href="/?action=users">Abbrechen</a>')
  r:puts('</div>')
  r:puts('</form>')
  r:puts('</div></div></body></html>')
end

-- Render the new group form.
local function show_group_form(r, pre, msg)
  r:puts(page_head("Neue Gruppe", "/"))
  r:puts('<div class="main"><div class="card"><h2>Neue Gruppe anlegen</h2>')
  if msg then r:puts(msg_html(msg)) end
  r:puts('<form method="POST" action="/?action=group_create">')
  r:puts('<div class="uf-field"><label>Gruppenname</label>')
  r:puts('<input type="text" name="gname" value="' .. h((pre or {}).gname or "")
    .. '" required placeholder="z.B. example.com-users" autocomplete=off>')
  r:puts('</div>')
  r:puts('<div style="display:flex;gap:.7em;margin-top:1.2em">')
  r:puts('<button class="btn b-add" type="submit">Anlegen</button>')
  r:puts('<a class="btn b-cancel" href="/?action=users">Abbrechen</a>')
  r:puts('</div></form>')
  r:puts('</div></div></body></html>')
end

-- ── User/group action handlers ────────────────────────────────────────────────

local function do_user_create(r, post)
  local username = trim(post.username  or "")
  local email    = trim(post.email     or "")
  local fname    = trim(post.firstName or "")
  local lname    = trim(post.lastName  or "")
  local password = post.password       or ""
  local grp_csv  = trim(post.groups_csv or "")
  

  if username == "" or password == "" then
    return show_user_form(r, nil,
      {username=username,email=email,firstName=fname,lastName=lname},
      "ERR: Benutzername und Passwort sind Pflichtfelder")
  end

  local tok, terr = kc_token(r)
  if not tok then return show_kc_login(r, terr) end

  local uid, cerr = kc_user_create(
    {username=username,email=email,firstName=fname,lastName=lname,password=password}, tok)
  if not uid then
    return show_user_form(r, nil,
      {username=username,email=email,firstName=fname,lastName=lname},
      "ERR: " .. (cerr or ""))
  end

  -- Parse comma-separated group IDs
  local desired = {}
  for id in grp_csv:gmatch("[^,]+") do
    id = trim(id)
    if id ~= "" then desired[#desired+1] = id end
  end
  local sgerr = kc_user_set_groups(uid, desired, tok)
  if sgerr then
    show_users(r, "OK Nutzer angelegt, aber Gruppen nicht gesetzt — " .. sgerr)
  else
    show_users(r, "OK Nutzer '" .. username .. "' angelegt")
  end
end

local function do_user_save(r, uid, post)
  if not uid or uid == "" then return show_users(r, "ERR: Keine UID") end
  

  local tok, terr = kc_token(r)
  if not tok then return show_kc_login(r, terr) end

  local uerr = kc_user_update(uid, {
    email     = trim(post.email     or ""),
    firstName = trim(post.firstName or ""),
    lastName  = trim(post.lastName  or ""),
  }, tok)
  if uerr then
    if uerr:find("401") then return show_users(r, nil) end
    return show_users(r, "ERR: " .. uerr)
  end

  local pw = post.password or ""
  if pw ~= "" then
    local pwerr = kc_user_reset_pw(uid, pw, tok)
    if pwerr then
      if pwerr:find("401") then return show_users(r, nil) end
      return show_users(r, "ERR: Passwort nicht gesetzt — " .. pwerr)
    end
  end

  local desired = {}
  for id in (trim(post.groups_csv or "")):gmatch("[^,]+") do
    id = trim(id)
    if id ~= "" then desired[#desired+1] = id end
  end
  -- Non-global-admins cannot change global group memberships:
  -- add back existing global memberships that were filtered out by disabled checkboxes.
  if not is_global_admin(r) then
    local cur_gmap = kc_user_group_map(uid, tok)
    for gid2, gname in pairs(cur_gmap) do
      if gname:match("^global%-") then
        desired[#desired+1] = gid2
      end
    end
  end
  local gerr = kc_user_set_groups(uid, desired, tok)
  if gerr then
    if gerr:find("401") then return show_users(r, nil) end
    return show_users(r, "ERR: Gruppen nicht gesetzt — " .. gerr)
  end

  show_users(r, "OK Nutzer gespeichert")
end

local function do_user_delete(r, post)
  local uid      = trim(post.uid      or "")
  local username = trim(post.username or "")
  
  if uid == "" then return show_users(r, "ERR: Keine UID") end
  if KC_PROTECTED_USERS[username] then
    return show_users(r, "ERR: Systemnutzer k\xC3\xB6nnen nicht gel\xC3\xB6scht werden")
  end
  local tok, terr = kc_token(r)
  if not tok then return show_kc_login(r, terr) end
  if kc_user_delete(uid, tok) then
    show_users(r, "OK Nutzer '" .. username .. "' gel\xC3\xB6scht")
  else
    show_users(r, "ERR: L\xC3\xB6schen fehlgeschlagen")
  end
end

local function do_group_create(r, post)
  local gname = trim(post.gname or "")
  
  if gname == "" then return show_group_form(r, post, "ERR: Gruppenname fehlt") end
  local tok, terr = kc_token(r)
  if not tok then return show_kc_login(r, terr) end
  local gid = kc_create_group(gname, tok)
  if gid then
    show_users(r, "OK Gruppe '" .. gname .. "' angelegt")
  else
    show_group_form(r, post, "ERR: Gruppe konnte nicht angelegt werden")
  end
end

local function do_group_delete(r, post)
  local gid   = trim(post.gid   or "")
  local gname = trim(post.gname or "")
  
  if gid == "" then return show_users(r, "ERR: Keine GID") end
  if is_protected_group(gname) then
    return show_users(r, "ERR: Diese Gruppe kann nicht gel\xC3\xB6scht werden")
  end
  local tok, terr = kc_token(r)
  if not tok then return show_kc_login(r, terr) end
  local status = kc_api_write("DELETE", "/groups/" .. gid, nil, tok)
  if status == 204 then
    show_users(r, "OK Gruppe '" .. gname .. "' gel\xC3\xB6scht")
  else
    show_users(r, "ERR: L\xC3\xB6schen fehlgeschlagen (HTTP " .. tostring(status) .. ")")
  end
end

-- ── Domain creation form ──────────────────────────────────────────────────────

-- ── Keycloak client management ───────────────────────────────────────────────

-- Get a Keycloak admin token from the current OIDC session.
-- The logged-in user must have manage-users / view-users roles on master-realm.
-- Returns: token_string, nil  OR  nil, error_message
-- Special error "needs_login" means: no valid token → show re-login prompt.
kc_token = function(r)
  if KC_ADMIN_URL == "" then
    return nil, "KEYCLOAK_ADMIN_URL nicht gesetzt"
  end

  local tok = r and r.subprocess_env and r.subprocess_env["OIDC_access_token"]
  if not tok or tok == "" then
    return nil, "needs_login"
  end

  return tok, nil
end

-- Minimal JSON encoder for Keycloak API calls
json_enc = function(v)
  local t = type(v)
  if t == "boolean" then return v and "true" or "false"
  elseif t == "number" then return tostring(v)
  elseif t == "string" then
    return '"' .. v:gsub('\\','\\\\'):gsub('"','\\"'):gsub('\n','\\n') .. '"'
  elseif t == "table" then
    if #v > 0 then
      local a = {}; for _,x in ipairs(v) do a[#a+1] = json_enc(x) end
      return "[" .. table.concat(a,",") .. "]"
    else
      local o = {}; for k,val in pairs(v) do
        o[#o+1] = json_enc(tostring(k)) .. ":" .. json_enc(val)
      end
      return "{" .. table.concat(o,",") .. "}"
    end
  end
  return "null"
end

-- Client naming convention: proxy-<domain>
local function kc_client_id(domain) return "proxy-" .. domain end

-- Check whether a Keycloak client proxy-<domain> exists.
-- Returns internal UUID or nil.
local function kc_client_exists(domain, token)
  if KC_ADMIN_URL == "" then return nil end
  local base = KC_BASE_URL
  local cid  = kc_client_id(domain)
  local tmp = os.tmpname()
  io.open(tmp,"w"):write("Authorization: Bearer " .. token):close()
  local cmd = string.format(
    'curl -s -k -H @%s "%s/clients?clientId=%s&search=false" 2>/dev/null',
    tmp, base, cid)
  local p = io.popen(cmd); local out = p:read("*a"); p:close()
  os.remove(tmp)
  local esc = cid:gsub("([%-%.])","%%%1")
  if out:find('"clientId"') and out:find('"' .. esc .. '"') then
    return out:match('"id"%s*:%s*"([^"]+)"')
  end
  return nil
end

-- Scan all conf files for the given domain and return every OIDC vhost name.
local function _collect_oidc_names(domain)
  local oidc_macros = { vhost_proxy_oidc_user=true, vhost_proxy_oidc_any=true, vhost_proxy_oidc_group=true }
  local seen, names = {}, {}
  for _, dir in ipairs({ SITES_DIR, "/etc/apache2/sites-enabled/" }) do
    for _, fpath in ipairs(_list_dir_conf(dir)) do
      local lines = read_lines(fpath)
      if lines then
        for _, line in ipairs(lines) do
          local v = parse_vhost_line(line)
          if v and oidc_macros[v.macro:lower()] and v.domain == domain and not seen[v.name] then
            seen[v.name] = true
            table.insert(names, v.name)
          end
        end
      end
    end
  end
  return names
end

-- Build complete redirectUris list and PUT it to Keycloak.
kc_sync_redirects = function(domain, token)
  local uuid = kc_client_exists(domain, token)
  if not uuid then return false, "Client proxy-" .. domain .. " nicht gefunden" end

  local uris = {}
  for _, n in ipairs({ "toc", "logout", "admin" }) do
    table.insert(uris, "https://" .. n .. "." .. domain .. "/protected")
  end
  for _, name in ipairs(_collect_oidc_names(domain)) do
    table.insert(uris, "https://" .. name .. "." .. domain .. "/protected")
  end

  local status, rbody = kc_api_write("PUT", "/clients/" .. uuid,
    json_enc({ redirectUris = uris }), token)
  if status == 204 then
    return true, #uris .. " redirect URIs gesetzt"
  end
  return false, "HTTP " .. tostring(status) .. ": " .. (kc_errmsg(rbody) or rbody or "")
end

-- Fetch a realm role's internal ID by name.
local function kc_realm_role_id(role_name, token)
  local base = KC_BASE_URL
  local tmp = os.tmpname()
  io.open(tmp,"w"):write("Authorization: Bearer " .. token):close()
  local cmd = string.format('curl -s -k -H @%s "%s/roles/%s" 2>/dev/null', tmp, base, role_name)
  local p = io.popen(cmd); local out = p:read("*a"); p:close()
  os.remove(tmp)
  return out:match('"id"%s*:%s*"([^"]+)"')
end

-- Create a client role (admin / user) on a client UUID.
local function kc_add_client_role(cuuid, role_name, desc, token)
  local base = KC_BASE_URL
  local tmp_h = os.tmpname(); local tmp_b = os.tmpname()
  io.open(tmp_h,"w"):write("Authorization: Bearer " .. token):close()
  io.open(tmp_b,"w"):write(json_enc({name=role_name, description=desc})):close()
  local cmd = string.format(
    'curl -s -k -o /dev/null -w "%%{http_code}" -X POST'
    ..' -H @%s -H "Content-Type: application/json" --data @%s "%s/clients/%s/roles" 2>/dev/null',
    tmp_h, tmp_b, base, cuuid)
  local p = io.popen(cmd); p:read("*a"); p:close()
  os.remove(tmp_h); os.remove(tmp_b)
end

-- Fetch a client role's internal ID.
local function kc_client_role_id(cuuid, role_name, token)
  local base = KC_BASE_URL
  local tmp = os.tmpname()
  io.open(tmp,"w"):write("Authorization: Bearer " .. token):close()
  local cmd = string.format(
    'curl -s -k -H @%s "%s/clients/%s/roles/%s" 2>/dev/null', tmp, base, cuuid, role_name)
  local p = io.popen(cmd); local out = p:read("*a"); p:close()
  os.remove(tmp)
  return out:match('"id"%s*:%s*"([^"]+)"')
end

-- Create a Keycloak group by name; returns its UUID.
kc_create_group = function(name, token)
  local base = KC_BASE_URL
  local tmp_h = os.tmpname(); local tmp_b = os.tmpname()
  io.open(tmp_h,"w"):write("Authorization: Bearer " .. token):close()
  io.open(tmp_b,"w"):write(json_enc({name=name})):close()
  local cmd = string.format(
    'curl -s -k -o /dev/null -X POST'
    ..' -H @%s -H "Content-Type: application/json" --data @%s "%s/groups" 2>/dev/null',
    tmp_h, tmp_b, base)
  local p = io.popen(cmd); p:read("*a"); p:close()
  os.remove(tmp_h); os.remove(tmp_b)
  -- Retrieve the new group's ID by listing and matching by name
  local tmp2 = os.tmpname()
  io.open(tmp2,"w"):write("Authorization: Bearer " .. token):close()
  local cmd2 = string.format('curl -s -k -H @%s "%s/groups?max=200" 2>/dev/null', tmp2, base)
  local p2 = io.popen(cmd2); local out2 = p2:read("*a"); p2:close()
  os.remove(tmp2)
  local esc = name:gsub("%-","%%%-"):gsub("%.","%%%%.")
  for block in out2:gmatch("%b{}") do
    if block:find('"name"%s*:%s*"' .. esc .. '"') then
      local gid = block:match('"id"%s*:%s*"([^"]+)"')
      if gid then return gid end
    end
  end
  return nil
end

-- Assign a realm role to a group.
local function kc_group_realm_role(gid, role_id, role_name, token)
  local base = KC_BASE_URL
  local tmp_h = os.tmpname(); local tmp_b = os.tmpname()
  io.open(tmp_h,"w"):write("Authorization: Bearer " .. token):close()
  io.open(tmp_b,"w"):write(json_enc({{id=role_id, name=role_name}})):close()
  local cmd = string.format(
    'curl -s -k -o /dev/null -X POST'
    ..' -H @%s -H "Content-Type: application/json" --data @%s "%s/groups/%s/role-mappings/realm" 2>/dev/null',
    tmp_h, tmp_b, base, gid)
  local p = io.popen(cmd); p:read("*a"); p:close()
  os.remove(tmp_h); os.remove(tmp_b)
end

-- Assign a client role to a group.
local function kc_group_client_role(gid, cuuid, role_id, role_name, token)
  local base = KC_BASE_URL
  local tmp_h = os.tmpname(); local tmp_b = os.tmpname()
  io.open(tmp_h,"w"):write("Authorization: Bearer " .. token):close()
  io.open(tmp_b,"w"):write(json_enc({{id=role_id, name=role_name, clientRole=true, containerId=cuuid}})):close()
  local cmd = string.format(
    'curl -s -k -o /dev/null -X POST'
    ..' -H @%s -H "Content-Type: application/json" --data @%s "%s/groups/%s/role-mappings/clients/%s" 2>/dev/null',
    tmp_h, tmp_b, base, gid, cuuid)
  local p = io.popen(cmd); p:read("*a"); p:close()
  os.remove(tmp_h); os.remove(tmp_b)
end

-- Create a new Keycloak client for the given domain.
-- Returns secret or nil + error.
-- Create a new Keycloak client for the given domain.
-- Naming: proxy-<domain>
-- Also creates client roles (admin/user), domain groups, and role mappings.
-- Returns secret or nil + error.
local function kc_create_client(domain, token)
  local base      = KC_BASE_URL
  local client_id = kc_client_id(domain)
  local tmp_h     = os.tmpname()
  local tmp_b     = os.tmpname()
  io.open(tmp_h,"w"):write("Authorization: Bearer " .. token):close()

  local body = json_enc({
    clientId               = client_id,
    name                   = "Apache OIDC Proxy " .. domain,
    description            = "Apache OIDC Proxy fuer " .. domain,
    enabled                = true,
    protocol               = "openid-connect",
    publicClient           = false,
    standardFlowEnabled    = true,
    directAccessGrantsEnabled = false,
    serviceAccountsEnabled = false,
    redirectUris           = { "https://*." .. domain .. "/protected" },
    webOrigins             = { "https://*." .. domain },
    attributes             = { ["post.logout.redirect.uris"] = "https://logout." .. domain .. "/*"
                               .. (TOC_DOMAIN ~= "" and ("##https://admin." .. TOC_DOMAIN .. "/*") or "") },
  })
  io.open(tmp_b,"w"):write(body):close()

  -- Create client
  local cmd = string.format(
    'curl -s -k -o /dev/null -w "%%{http_code}" -X POST'
    .. ' -H @%s -H "Content-Type: application/json"'
    .. ' --data @%s "%s/clients" 2>/dev/null',
    tmp_h, tmp_b, base)
  local p = io.popen(cmd); local status = tonumber(p:read("*a")); p:close()

  if status ~= 201 then
    os.remove(tmp_h); os.remove(tmp_b)
    return nil, "Keycloak antwortete mit HTTP " .. tostring(status)
  end

  local cuuid = kc_client_exists(domain, token)
  if not cuuid then
    os.remove(tmp_h); os.remove(tmp_b)
    return nil, "Client angelegt, aber UUID nicht lesbar"
  end

  -- Groups claim mapper
  local mapper = json_enc({
    name           = "groups",
    protocol       = "openid-connect",
    protocolMapper = "oidc-group-membership-mapper",
    config = {
      ["full.path"]            = "false",
      ["id.token.claim"]       = "true",
      ["access.token.claim"]   = "true",
      ["claim.name"]           = "groups",
      ["userinfo.token.claim"] = "true",
    }
  })
  io.open(tmp_b,"w"):write(mapper):close()
  local cm = string.format(
    'curl -s -k -X POST -H @%s -H "Content-Type: application/json"'
    .. ' --data @%s "%s/clients/%s/protocol-mappers/models" 2>/dev/null',
    tmp_h, tmp_b, base, cuuid)
  local pm = io.popen(cm); pm:read("*a"); pm:close()

  -- Client roles: admin + user
  kc_add_client_role(cuuid, "admin", "Administratoren fuer " .. domain, token)
  kc_add_client_role(cuuid, "user",  "Benutzer fuer " .. domain,        token)

  local admin_rid = kc_client_role_id(cuuid, "admin", token)
  local user_rid  = kc_client_role_id(cuuid, "user",  token)
  local gu_rid    = kc_realm_role_id("global_user", token)

  -- Domain groups with role mappings
  local ga_gid = kc_create_group(domain .. "-admins", token)
  local gu_gid = kc_create_group(domain .. "-users",  token)

  if ga_gid and admin_rid then
    kc_group_client_role(ga_gid, cuuid, admin_rid, "admin", token)
    if gu_rid then kc_group_realm_role(ga_gid, gu_rid, "global_user", token) end
  end
  if gu_gid and user_rid then
    kc_group_client_role(gu_gid, cuuid, user_rid, "user", token)
    if gu_rid then kc_group_realm_role(gu_gid, gu_rid, "global_user", token) end
  end

  -- Fetch the generated secret
  local sm = string.format(
    'curl -s -k -H @%s "%s/clients/%s/client-secret" 2>/dev/null',
    tmp_h, base, cuuid)
  local sp = io.popen(sm); local sout = sp:read("*a"); sp:close()
  local secret = sout:match('"value"%s*:%s*"([^"]+)"')
  os.remove(tmp_h); os.remove(tmp_b)
  return secret, nil
end

-- Write domain OIDC client credentials to AddOn/.oidc/<domain>.conf
local function write_oidc_client_conf(domain, client_id, secret)
  _mkdir_p(OIDC_DIR)
  local path = OIDC_DIR .. domain .. ".conf"
  local f, err = io.open(path, "w")
  if not f then return false, err end
  f:write("# OIDC client credentials for " .. domain .. " — managed by admin.lua\n")
  f:write("OIDCClientID     " .. client_id .. "\n")
  f:write("OIDCClientSecret " .. secret   .. "\n")
  f:close()
  _chmod600(path)
  return true, nil
end

-- Read existing OIDC client credentials from AddOn/.oidc/<domain>.conf
local function read_oidc_client_conf(domain)
  local path = OIDC_DIR .. domain .. ".conf"
  local f = io.open(path, "r")
  if not f then return nil end
  local id, sec
  for line in f:lines() do
    id  = id  or line:match("^OIDCClientID%s+(.+)$")
    sec = sec or line:match("^OIDCClientSecret%s+(.+)$")
  end
  f:close()
  return id and { client_id = trim(id), has_secret = (sec ~= nil) }
end

-- Show or handle Keycloak client section for a domain
show_kc_client_section = function(r, domain, msg, inline)
  local existing   = read_oidc_client_conf(domain)
  local target_cid = kc_client_id(domain)   -- proxy-<domain>

  if inline then
    -- Compact strip inside the domain card (no own card/h2 wrapper)
    local sep = 'border-top:1px solid #1a1a3e;margin:.6em 0 .8em;padding:.5em 0 .3em;'
      .. 'display:flex;align-items:center;gap:1em;flex-wrap:wrap'
    r:puts('<div style="' .. sep .. '">')
    r:puts('\xF0\x9F\x94\x91 <span style="color:#aaa;font-size:.85em">Keycloak-Client</span>')
    if msg then
      local cls = msg:sub(1,3) == "ERR" and "color:#ff6666" or "color:#99ff99"
      r:puts('<span style="' .. cls .. ';font-size:.85em">' .. h(msg) .. '</span>')
    end
    if KC_ADMIN_URL == "" then
      r:puts('<span class="dim">KEYCLOAK_ADMIN_URL nicht gesetzt</span>')
    elseif existing then
      r:puts('<code style="color:#99ff99;font-size:.85em">\xE2\x9C\x94 ' .. h(existing.client_id) .. '</code>')
      r:puts('<span style="color:#666;font-size:.8em">Gruppen: '
        .. '<code>' .. h(domain) .. '-admins</code> / <code>' .. h(domain) .. '-users</code></span>')
      r:puts('<form method="POST" action="/?action=kc_rotate&domain=' .. h(domain) .. '" style="margin:0">')
      r:puts('<button class="btn b-warn" type="submit" style="font-size:.8em;padding:.2em .6em">'
        .. '&#x21BA;&nbsp;Secret rotieren</button>')
      r:puts('</form>')
    else
      r:puts('<span style="color:#aaa;font-size:.85em">Kein eigener Client — globaler Client <code>'
        .. h(KC_CLIENT_ID) .. '</code> aktiv</span>')
      r:puts('<form method="POST" action="/?action=kc_create&domain=' .. h(domain) .. '" style="margin:0">')
      r:puts('<button class="btn b-add" type="submit" style="font-size:.8em;padding:.2em .6em">'
        .. '&#x2B;&nbsp;Client <code>' .. h(target_cid) .. '</code> anlegen</button>')
      r:puts('</form>')
    end
    r:puts('</div>')
    return
  end

  -- Full-card mode (used when shown standalone after an action)
  r:puts('<div class="card" style="margin-top:1em">')
  r:puts('<h2>\xF0\x9F\x94\x91 Keycloak-Client &mdash; <code>' .. h(domain) .. '</code></h2>')
  if msg then
    local cls = msg:sub(1,3) == "ERR" and "err" or "ok"
    r:puts('<div class="msg ' .. cls .. '">' .. h(msg) .. '</div>')
  end
  if KC_ADMIN_URL == "" then
    r:puts('<p class="hint">KEYCLOAK_ADMIN_URL nicht gesetzt — Keycloak-Integration nicht verf\xC3\xBCgbar.</p>')
  elseif existing then
    r:puts('<p style="color:#99ff99;margin-bottom:.6em">')
    r:puts('\xE2\x9C\x94 Client <code>' .. h(existing.client_id) .. '</code> ist konfiguriert.')
    r:puts('</p>')
    r:puts('<p style="color:#888;font-size:.85em;margin-bottom:.8em">')
    r:puts('Gruppen: <code>' .. h(domain) .. '-admins</code> / <code>' .. h(domain) .. '-users</code>')
    r:puts('</p>')
    r:puts('<form method="POST" action="/?action=kc_rotate&domain=' .. h(domain) .. '">')
    r:puts('<button class="btn b-warn" type="submit">&#x21BA;&nbsp;Secret rotieren</button>')
    r:puts('</form>')
  else
    r:puts('<p style="color:#aaa;font-size:.9em;margin-bottom:.8em">')
    r:puts('Kein eigener Keycloak-Client f\xC3\xBCr <code>' .. h(domain) .. '</code>.<br>')
    r:puts('Aktuell wird der globale Client <code>' .. h(KC_CLIENT_ID) .. '</code> verwendet.<br>')
    r:puts('Neu angelegt als <code>' .. h(target_cid) .. '</code> mit Rollen <code>admin</code> / <code>user</code>')
    r:puts(' und Gruppen <code>' .. h(domain) .. '-admins</code> / <code>' .. h(domain) .. '-users</code>.')
    r:puts('</p>')
    r:puts('<form method="POST" action="/?action=kc_create&domain=' .. h(domain) .. '">')
    r:puts('<button class="btn b-add" type="submit">')
    r:puts('&#x2B;&nbsp;Client <code>' .. h(target_cid) .. '</code> anlegen</button>')
    r:puts('</form>')
  end
  r:puts('</div>')
end

local function do_kc_create(r, domain)
  local tok, err = kc_token(r)
  if not tok then
    return show_list(r, "ERR Keycloak-Token: " .. (err or ""))
  end

  -- Check if client already exists
  if kc_client_exists(domain, tok) then
    return show_list(r, "ERR Client '" .. kc_client_id(domain) .. "' existiert bereits in Keycloak")
  end

  local secret, cerr = kc_create_client(domain, tok)
  if not secret then
    return show_list(r, "ERR Keycloak-Client anlegen: " .. (cerr or ""))
  end

  local ok, werr = write_oidc_client_conf(domain, kc_client_id(domain), secret)
  if not ok then
    return show_list(r, "ERR Conf-Datei schreiben: " .. (werr or ""))
  end

  -- Graceful reload so Apache picks up the new IncludeOptional file
  _apache_reload()

  show_list(r, "OK Keycloak-Client '" .. kc_client_id(domain) .. "' angelegt und aktiviert")
end

local function do_kc_rotate(r, domain)
  local existing = read_oidc_client_conf(domain)
  if not existing then
    return show_list(r, "ERR Kein Keycloak-Client f\xC3\xBCr " .. domain .. " konfiguriert")
  end

  local tok, err = kc_token(r)
  if not tok then
    return show_list(r, "ERR Keycloak-Token: " .. (err or ""))
  end

  local base = KC_BASE_URL
  local cid  = kc_client_exists(domain, tok)
  if not cid then
    return show_list(r, "ERR Client '" .. domain .. "' nicht in Keycloak gefunden")
  end

  -- Rotate secret
  local tmp = os.tmpname()
  io.open(tmp,"w"):write("Authorization: Bearer " .. tok):close()
  local cmd = string.format(
    'curl -s -k -X POST -H @%s "%s/clients/%s/client-secret" 2>/dev/null',
    tmp, base, cid)
  local p = io.popen(cmd); local out = p:read("*a"); p:close()
  os.remove(tmp)
  local new_secret = out:match('"value"%s*:%s*"([^"]+)"')
  if not new_secret then
    return show_list(r, "ERR Secret-Rotation fehlgeschlagen")
  end

  local ok, werr = write_oidc_client_conf(domain, kc_client_id(domain), new_secret)
  if not ok then
    return show_list(r, "ERR Conf-Datei schreiben: " .. (werr or ""))
  end
  _apache_reload()
  show_list(r, "OK Secret f\xC3\xBCr '" .. kc_client_id(domain) .. "' rotiert und aktiviert")
end

local function show_domain_form(r, pre, errmsg)
  r:puts(page_head("Neue Domain"))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>Neue Domain anlegen</h2>')
  r:puts('<p style="color:#888;font-size:.85em;margin-bottom:.8em">'
    .. 'Legt eine neue <code>.conf</code>-Datei in <code>sites-admin/</code> an.<br>'
    .. 'Eine Admin-VHost-Zeile (admin.DOMAIN) wird automatisch eingefügt.<br>'
    .. 'Konfiguration wird vor dem Speichern automatisch getestet.'
    .. '</p>')
  if errmsg then r:puts('<div class="msg err">' .. h(errmsg) .. '</div>') end

  pre = pre or {}
  r:puts('<form method="POST" action="/?action=domain_create">')

  r:puts('<div class="form-row"><label>Domain:</label>'
    .. '<input name=domain value="' .. h(pre.domain or "") .. '" placeholder="example.com" required></div>')

  r:puts('<div class="form-row"><label>Admin-Benutzer:</label>'
    .. '<input name=adminuser value="' .. h(pre.adminuser or "") .. '" placeholder="Hans.Mustermann" required></div>')

  local certs = {{"le","Let\'s Encrypt"},{"self","Self-signed"},{"none","Kein SSL"}}
  r:puts('<div class="form-row"><label>Zertifikatstyp:</label><select name=certtype>')
  for _, c in ipairs(certs) do
    local sel = (pre.certtype == c[1]) and " selected" or ""
    r:puts('<option value="' .. c[1] .. '"' .. sel .. '>' .. c[2] .. '</option>')
  end
  r:puts('</select></div>')

  r:puts('<div class="form-row"><label>TOC-URL:</label>'
    .. '<input name=tocurl value="' .. h(pre.tocurl or "") .. '" placeholder="https://toc.example.com"></div>')

  r:puts('<div class="form-row" style="margin-top:1.2em">')
  r:puts('<button class="btn b-save" type=submit>&#10003;&nbsp;Anlegen &amp; Testen</button>&nbsp;')
  r:puts('<a class="btn b-cancel" href="/">Abbrechen</a>')
  r:puts('</div></form></div></div></body></html>')
end

local function do_domain_create(r, p)
  local domain    = trim(p["domain"]    or "")
  local adminuser = trim(p["adminuser"] or "")
  local certtype  = trim(p["certtype"]  or "le")
  local tocurl    = trim(p["tocurl"]    or "")

  if not validate_domain(domain) then
    return show_domain_form(r, p, "Ungültige Domain")
  end
  if adminuser == "" or adminuser:match("[^a-zA-Z0-9%.@_%-]") then
    return show_domain_form(r, p, "Ungültiger Admin-Benutzer")
  end
  if certtype ~= "le" and certtype ~= "self" and certtype ~= "none" then
    certtype = "le"
  end
  if tocurl == "" then
    tocurl = "https://toc." .. domain
  end

  local fname = domain .. ".conf"
  local fpath = SITES_DIR .. fname

  if fexists(fpath) then
    return show_domain_form(r, p, "Domain existiert bereits: " .. fname)
  end

  local lines = {
    "# " .. domain .. " — Proxy-Konfiguration",
    "",
    "Use Domain_Init  " .. domain .. "  " .. certtype .. "  " .. tocurl,
    "Use Admin_VHost  " .. domain .. "  '" .. adminuser .. "'",
    "",
    "Use Domain_Final " .. domain,
  }

  local ftmp = fpath .. ".tmp"
  local ok, err = write_lines(ftmp, lines)
  if not ok then
    return show_domain_form(r, p, "Datei nicht schreibbar: " .. (err or ""))
  end

  os.rename(ftmp, fpath)

  local test_ok, test_out = configtest()
  if not test_ok then
    os.remove(fpath)
    return show_domain_form(r, p,
      "Konfigurationstest fehlgeschlagen — Domain nicht angelegt.\n" .. (test_out or ""))
  end

  set_pending_reload()
  show_list(r, "OK: Domain " .. domain .. " angelegt — Konfiguration noch anwenden!")
end

-- ── Macro expansion (for config view) ───────────────────────────────────────

-- Load all macro definitions from /etc/apache2/macro/*.conf (rendered templates).
-- Returns macros[NAME_UPPER] = { params = {"P1","P2",...}, body = "..." }
local function load_macros()
  local macros = {}
  local dir = "/etc/apache2/macro/"
  local files = {
    "01-frame-domain.conf",
    "05-common.conf",
    "30-secure-basic.conf",
    "40-secure-oidc.conf",
  }
  local function parse_file(content)
    local lines = {}
    for ln in (content .. "\n"):gmatch("([^\n]*)\n") do
      table.insert(lines, ln)
    end
    local i = 1
    while i <= #lines do
      -- Match opening <Macro NAME $(P1) $(P2) ...> (case-insensitive)
      local hdr = lines[i]:match("^%s*<[Mm]acro%s+(.-)%s*>%s*$")
      if hdr then
        local name = hdr:match("^(%S+)")
        local plist = {}
        for p in hdr:gmatch("%$%((%u[%u_]*)%)") do
          table.insert(plist, p)
        end
        local body = {}
        i = i + 1
        while i <= #lines do
          if lines[i]:match("^%s*</[Mm]acro>") then break end
          table.insert(body, lines[i])
          i = i + 1
        end
        if name then
          macros[name:upper()] = { params = plist, body = table.concat(body, "\n") }
        end
      end
      i = i + 1
    end
  end
  for _, fname in ipairs(files) do
    local f = io.open(dir .. fname, "r")
    if f then parse_file(f:read("*a")); f:close() end
  end
  return macros
end

-- Parse space-separated args from a USE argument string.
-- Single-quoted strings are treated as one token (quotes stripped).
local function parse_use_args(s)
  s = (s or ""):match("^%s*(.-)%s*$")
  local args = {}
  while s ~= "" do
    if s:sub(1,1) == "'" then
      local q, rest = s:match("^'([^']*)'(.*)")
      if q then table.insert(args, q); s = rest:match("^%s*(.-)%s*$") or ""
      else break end
    else
      local w, rest = s:match("^(%S+)(.*)")
      if w then table.insert(args, w); s = rest:match("^%s*(.-)%s*$") or ""
      else break end
    end
  end
  return args
end

-- Recursively expand a USE call.  depth guards against infinite loops.
local _expand_use  -- forward declaration
_expand_use = function(name, args, macros, depth)
  if depth > 15 then return "  <!-- max recursion depth -->\n" end
  local m = macros[name:upper()]
  if not m then
    return ("  <!-- macro %s not found -->\n"):format(name)
  end
  -- Map positional params → values
  local env = {}
  for i, p in ipairs(m.params) do env[p] = args[i] or "" end
  -- Substitute $(PARAM) in body
  local body = m.body:gsub("%$%((%u[%u_]*)%)", function(p)
    return env[p] or ("$(" .. p .. ")")
  end)
  -- Recursively expand nested USE directives
  local out = {}
  for line in (body .. "\n"):gmatch("([^\n]*)\n") do
    local indent, uname, urest = line:match("^(%s*)[Uu][Ss][Ee]%s+(%S+)%s*(.*)")
    if uname then
      local sub_args = parse_use_args(urest)
      local expanded = _expand_use(uname, sub_args, macros, depth + 1)
      -- Re-indent each expanded line
      for eline in (expanded .. "\n"):gmatch("([^\n]*)\n") do
        if eline ~= "" then
          table.insert(out, indent .. eline)
        else
          table.insert(out, "")
        end
      end
    else
      table.insert(out, line)
    end
  end
  return table.concat(out, "\n")
end

-- ── VHost config view ────────────────────────────────────────────────────────
local function show_vhost_config_view(r, name, domain, rawline)
  local vhost_fqdn = name .. "." .. domain
  local copy_btn = '<button class="copy-btn" onclick="copyPre(this)" title="In Zwischenablage kopieren">'
    .. '<svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor" style="vertical-align:middle">'
    .. '<path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"/>'
    .. '<path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"/>'
    .. '</svg></button>'
  r:puts(page_head("Config: " .. vhost_fqdn, "/"))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>Konfiguration — <code>' .. h(vhost_fqdn) .. '</code></h2>')

  -- Show the raw macro call from sites-admin
  r:puts('<p style="color:#aaa;font-size:.85em;margin-bottom:.4em">Macro-Aufruf in sites-admin:</p>')
  r:puts('<div class="pre-wrap">' .. copy_btn)
  r:puts('<pre style="background:#060614;color:#7ecfff;padding:.7em;border-radius:3px;'
    .. 'font-size:.85em;margin-bottom:1.2em;overflow-x:auto">' .. h(rawline) .. '</pre></div>')

  -- Expand the macro call by reading the macro definition files.
  -- This works purely in Lua without requiring DUMP_CONFIG or root access.
  local v = parse_vhost_line(rawline)
  if not v then
    r:puts('<p style="color:#aa6600">Macro-Aufruf nicht parsebar.</p>')
    r:puts('<a class="btn b-cancel" href="/">&#8592;&nbsp;Zur\xC3\xBCck</a>')
    r:puts('</div></div></body></html>')
    return
  end

  local macros = load_macros()
  local args = parse_use_args(
    v.name .. "  " .. v.domain
    .. (v.dest ~= "" and ("  " .. v.dest) or "")
    .. (v.authtype ~= "" and ("  " .. v.authtype) or "")
    .. (v.users ~= "" and ("  '" .. v.users .. "'") or "")
  )
  -- args[1]=name, args[2]=domain, args[3]=dest, args[4...]=extra
  -- rebuild from parsed fields for correctness
  args = { v.name, v.domain }
  if v.dest ~= "" then table.insert(args, v.dest) end
  if v.authtype ~= "" then table.insert(args, v.authtype) end
  if v.users ~= "" then table.insert(args, v.users) end

  local expanded = _expand_use(v.macro, args, macros, 0)

  -- Extract <VirtualHost> blocks from the expanded text
  local blocks = {}
  local pos = 1
  while true do
    local s = expanded:find("<VirtualHost", pos, true)
    if not s then break end
    local e = expanded:find("</VirtualHost>", s, true)
    if not e then break end
    e = e + #"</VirtualHost>" - 1
    table.insert(blocks, expanded:sub(s, e))
    pos = e + 1
  end

  if #blocks > 0 then
    r:puts('<p style="color:#aaa;font-size:.85em;margin-bottom:.4em">'
      .. 'Expandierte Konfiguration (Macro-Expansion, '
      .. #blocks .. ' VirtualHost-Block'
      .. (#blocks > 1 and "s" or "") .. '):</p>')
    r:puts('<p style="color:#555;font-size:.78em;margin-bottom:.8em">'
      .. 'Dargestellt sind die Direktiven aus den Macro-Definitionen. '
      .. 'Platzhalter wie <code>${VAR}</code> stammen aus den Container-Umgebungsvariablen.</p>')
    for _, block in ipairs(blocks) do
      local port = block:match("<VirtualHost[^>]*:(%d+)") or "?"
      r:puts('<p style="color:#666;font-size:.78em;margin:.6em 0 .2em">— Port ' .. port .. ' —</p>')
      r:puts('<div class="pre-wrap">' .. copy_btn)
      r:puts('<pre style="background:#060614;color:#ddd;padding:.7em;border-radius:3px;'
        .. 'font-size:.82em;margin-bottom:1em;overflow-x:auto;white-space:pre-wrap">'
        .. h(block) .. '</pre></div>')
    end
  else
    -- Macro not found or produced no VirtualHost blocks — show raw expansion
    r:puts('<p style="color:#aa6600;font-size:.85em;margin-bottom:.6em">'
      .. 'Kein VirtualHost-Block in der Macro-Expansion gefunden.</p>')
    if expanded ~= "" then
      r:puts('<div class="pre-wrap">' .. copy_btn)
      r:puts('<pre style="background:#060614;color:#ddd;padding:.7em;border-radius:3px;'
        .. 'font-size:.82em;margin-bottom:1em;overflow-x:auto;white-space:pre-wrap">'
        .. h(expanded) .. '</pre></div>')
    end
  end

  r:puts('<a class="btn b-cancel" href="/">&#8592;&nbsp;Zur\xC3\xBCck zur \xC3\x9Cbersicht</a>')
  r:puts('</div></div></body></html>')
end

-- ── BasicAuth / htpasswd management ──────────────────────────────────────────

local HTPASSWD_FILE = "/etc/apache2/basic.htpasswd"

local function validate_htpasswd_user(s)
  -- Only safe characters — no shell metacharacters
  return s and s ~= "" and s:match("^[%w%-%._]+$") ~= nil
end

htpasswd_list_users = function()
  local users = {}
  local f = io.open(HTPASSWD_FILE, "r")
  if not f then return users end
  for line in f:lines() do
    local user = line:match("^([^:]+):")
    if user then table.insert(users, user) end
  end
  f:close()
  return users
end

-- Set or update a user's password via htpasswd (bcrypt).
-- Password is passed via a tmpfile redirect so stderr/stdout can be captured.
-- Returns nil on success, error string on failure.
local function htpasswd_set(username, password)
  if not validate_htpasswd_user(username) then return "Ungültiger Benutzername" end
  if not password or password == "" then return "Passwort darf nicht leer sein" end
  local tmp = os.tmpname()
  local f = io.open(tmp, "w")
  if not f then return "Temporäre Datei konnte nicht erstellt werden" end
  f:write(password .. "\n"); f:close()
  local create = fexists(HTPASSWD_FILE) and "" or " -c"
  local cmd = string.format("htpasswd -B -i%s %s %s < %s 2>&1",
    create, HTPASSWD_FILE, username, tmp)
  local p = io.popen(cmd)
  local out = p and p:read("*a") or ""
  local ok, _, code = p and p:close()
  os.remove(tmp)
  if not ok then
    local detail = trim(out) ~= "" and (": " .. trim(out)) or ""
    return "htpasswd fehlgeschlagen (exit " .. tostring(code or "?") .. ")" .. detail
  end
  return nil
end

-- Delete a user from the htpasswd file.
-- Returns nil on success, error string on failure.
local function htpasswd_del(username)
  if not validate_htpasswd_user(username) then return "Ungültiger Benutzername" end
  if not fexists(HTPASSWD_FILE) then return "Datei nicht gefunden" end
  local cmd = string.format("htpasswd -D %s %s 2>&1", HTPASSWD_FILE, username)
  local p = io.popen(cmd)
  if not p then return "htpasswd konnte nicht ausgeführt werden" end
  local out = p:read("*a")
  local ok, _, code = p:close()
  if not ok then
    local detail = trim(out) ~= "" and (": " .. trim(out)) or ""
    return "htpasswd fehlgeschlagen (exit " .. tostring(code or "?") .. ")" .. detail
  end
  return nil
end

local function show_htpasswd(r, msg)
  r:puts(page_head("BasicAuth Benutzer", "/"))
  if msg then r:puts(msg_html(msg)) end
  r:puts('<div class="main">')

  local users = htpasswd_list_users()
  r:puts('<div class="card">')
  r:puts('<h2>Benutzer in basic.htpasswd</h2>')
  if #users == 0 then
    r:puts('<p class="dim">Keine Benutzer vorhanden.</p>')
  else
    r:puts('<table><tr><th>Benutzername</th><th>Aktionen</th></tr>')
    for _, user in ipairs(users) do
      r:puts('<tr><td>' .. h(user) .. '</td><td class="actions">')
      r:puts('<a class="btn b-edit" href="/?action=htpasswd_edit&user=' .. h(user) .. '">Passwort \xC3\xA4ndern</a> ')
      r:puts('<form method="POST" action="/?action=htpasswd_delete" style="display:inline"'
          .. ' onsubmit="return confirm(\'Benutzer &quot;' .. h(user) .. '&quot; wirklich l\xC3\xB6schen?\')">')
      r:puts('<input type="hidden" name="username" value="' .. h(user) .. '">')
      r:puts('<button class="btn b-del" type="submit">L\xC3\xB6schen</button></form>')
      r:puts('</td></tr>')
    end
    r:puts('</table>')
  end
  r:puts('</div>')

  r:puts('<div class="card"><h2>Neuer Benutzer</h2>')
  r:puts('<form method="POST" action="/?action=htpasswd_set">')
  r:puts('<input type="hidden" name="mode" value="new">')
  r:puts('<div class="form-row"><label>Benutzername</label>')
  r:puts('<input name="username" required placeholder="benutzername"></div>')
  r:puts('<div class="form-row"><label>Passwort</label>')
  r:puts('<input type="password" name="password" required placeholder="Passwort"></div>')
  r:puts('<div class="form-row"><label>Passwort (wdh.)</label>')
  r:puts('<input type="password" name="confirm" required placeholder="Passwort wiederholen"></div>')
  r:puts('<div class="form-row"><label></label><button class="btn b-save" type="submit">Anlegen</button></div>')
  r:puts('</form></div>')
  r:puts('</div>')
end

local function show_htpasswd_edit(r, username, msg)
  r:puts(page_head("Passwort \xC3\xA4ndern", "/"))
  if msg then r:puts(msg_html(msg)) end
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>Passwort f\xC3\xBCr <strong>' .. h(username) .. '</strong></h2>')
  r:puts('<form method="POST" action="/?action=htpasswd_set">')
  r:puts('<input type="hidden" name="mode" value="edit">')
  r:puts('<input type="hidden" name="username" value="' .. h(username) .. '">')
  r:puts('<div class="form-row"><label>Neues Passwort</label>')
  r:puts('<input type="password" name="password" required autofocus placeholder="Neues Passwort"></div>')
  r:puts('<div class="form-row"><label>Passwort (wdh.)</label>')
  r:puts('<input type="password" name="confirm" required placeholder="Passwort wiederholen"></div>')
  r:puts('<div class="form-row"><label></label>')
  r:puts('<button class="btn b-save" type="submit">Speichern</button> ')
  r:puts('<a class="btn b-cancel" href="/?action=htpasswd">Abbrechen</a></div>')
  r:puts('</form></div></div>')
end

local function do_htpasswd_set(r, post)
  local username = trim(post["username"] or "")
  local password = post["password"] or ""
  local confirm  = post["confirm"]  or ""
  local mode     = post["mode"]     or "new"

  local function err(msg)
    if mode == "edit" then show_htpasswd_edit(r, username, "ERR: " .. msg)
    else                   show_htpasswd(r, "ERR: " .. msg) end
  end

  dbg(r, "htpasswd_set", {username=username, mode=mode})
  if not validate_htpasswd_user(username) then return err("Ung\xC3\xBCltiger Benutzername") end
  if password == ""           then return err("Passwort darf nicht leer sein") end
  if password ~= confirm      then return err("Passw\xC3\xB6rter stimmen nicht \xC3\xBCberein") end

  local e = htpasswd_set(username, password)
  if e then err(e) else show_htpasswd(r, "OK: Passwort f\xC3\xBCr '" .. h(username) .. "' gespeichert") end
end

local function do_htpasswd_delete(r, post)
  local username = trim(post["username"] or "")
  if not validate_htpasswd_user(username) then
    return show_htpasswd(r, "ERR: Ung\xC3\xBCltiger Benutzername")
  end
  local e = htpasswd_del(username)
  if e then show_htpasswd(r, "ERR: " .. e)
  else      show_htpasswd(r, "OK: Benutzer '" .. h(username) .. "' gel\xC3\xB6scht") end
end

-- ── Request dispatcher ────────────────────────────────────────────────────────

function handle(r)
  r.content_type = "text/html; charset=UTF-8"
  ADMIN_REMOTE_USER = r.user or ""

  local get  = r:parseargs()
  local post = {}
  if r.method == "POST" then
    local _, body = r:parsebody(1024 * 64)
    if type(body) == "table" then
      for k, v in pairs(body) do
        post[k] = type(v) == "table" and v[1] or v
      end
    end
    dbg(r, "parsebody", post)
  end

  -- Merge: GET params take precedence for routing, POST for data
  local action = get["action"] or post["action"] or "list"

  if action == "list" then
    show_list(r)

  elseif action == "new" then
    local fname = trim(get["file"] or "")
    if fname == "" or fname:match("[/\\]") then
      show_list(r, "ERR: Keine Datei angegeben")
    else
      show_form(r, fname, nil, nil, nil)
    end

  elseif action == "edit" then
    local fname  = trim(get["file"] or "")
    local lineno = tonumber(get["line"])
    if fname == "" or not lineno then
      show_list(r, "ERR: Parameter fehlen")
    else
      local lines = read_lines(SITES_DIR .. fname)
      if not lines or not lines[lineno] then
        show_list(r, "ERR: Zeile nicht gefunden")
      else
        local pre = parse_vhost_line(lines[lineno])
        if pre then
          pre.raw = trim(lines[lineno])
          show_form(r, fname, lineno, pre, nil)
        else
          show_list(r, "ERR: Zeile nicht parsebar: " .. h(lines[lineno]))
        end
      end
    end

  elseif action == "save" and r.method == "POST" then
    do_save(r, post)

  elseif action == "delete" and r.method == "POST" then
    do_delete(r, post)

  elseif action == "apply" and r.method == "POST" then
    do_apply(r)

  elseif action == "config" then
    local fname  = trim(get["file"]  or "")
    local lineno = tonumber(get["line"])
    if fname == "" or not lineno then
      show_list(r, "ERR: Parameter fehlen")
    else
      local lines = read_lines(SITES_DIR .. fname)
      if not lines or not lines[lineno] then
        show_list(r, "ERR: Zeile nicht gefunden")
      else
        local v = parse_vhost_line(lines[lineno])
        if v then
          show_vhost_config_view(r, v.name, v.domain, trim(lines[lineno]))
        else
          show_list(r, "ERR: Zeile nicht parsebar")
        end
      end
    end

  elseif action == "addon" then
    local name   = trim(get["name"]   or "")
    local domain = trim(get["domain"] or "")
    if not validate_name(name) or not validate_domain(domain) then
      show_list(r, "ERR: Ungültige Parameter")
    else
      show_addon_form(r, name, domain, nil, nil, nil, nil)
    end

  elseif action == "addon_save" and r.method == "POST" then
    do_addon_save(r, post)

  elseif action == "addon_restore" and r.method == "POST" then
    do_addon_restore(r, post)

  elseif action == "domain_new" then
    show_domain_form(r, nil, nil)

  elseif action == "domain_create" and r.method == "POST" then
    do_domain_create(r, post)

  elseif action == "kc_create" and r.method == "POST" then
    local domain = trim(get["domain"] or "")
    if not validate_domain(domain) then
      show_list(r, "ERR: Ungültige Domain")
    else
      do_kc_create(r, domain)
    end

  elseif action == "kc_rotate" and r.method == "POST" then
    local domain = trim(get["domain"] or "")
    if not validate_domain(domain) then
      show_list(r, "ERR: Ungültige Domain")
    else
      do_kc_rotate(r, domain)
    end

  elseif action == "htpasswd" then
    show_htpasswd(r)

  elseif action == "htpasswd_edit" then
    local user = trim(get["user"] or "")
    if not validate_htpasswd_user(user) then
      show_htpasswd(r, "ERR: Ung\xC3\xBCltiger Benutzername")
    else
      show_htpasswd_edit(r, user, nil)
    end

  elseif action == "htpasswd_set" and r.method == "POST" then
    do_htpasswd_set(r, post)

  elseif action == "htpasswd_delete" and r.method == "POST" then
    do_htpasswd_delete(r, post)

  elseif action == "users" then
    
    
    show_users(r, nil)

  elseif action == "user_new" then
    show_user_form(r, nil, nil, nil)

  elseif action == "user_edit" then
    local uid = trim(post["uid"] or get["uid"] or "")
    
    
    if uid == "" then
      show_users(r, "ERR: Keine UID")
    else
      local tok, terr = kc_token(r)
      if not tok then
        show_kc_login(r, terr)
      else
        local udata = json_obj_flat(kc_api_get("/users/" .. uid, tok))
        show_user_form(r, uid, udata, nil)
      end
    end

  elseif action == "user_create" and r.method == "POST" then
    do_user_create(r, post)

  elseif action == "user_save" and r.method == "POST" then
    local uid = trim(post["uid"] or get["uid"] or "")
    do_user_save(r, uid, post)

  elseif action == "user_delete" and r.method == "POST" then
    do_user_delete(r, post)

  elseif action == "group_new" then
    show_group_form(r, nil, nil)

  elseif action == "group_create" and r.method == "POST" then
    do_group_create(r, post)

  elseif action == "group_delete" and r.method == "POST" then
    do_group_delete(r, post)

  elseif action == "toggle_disable" and r.method == "POST" then
    do_toggle_disable(r, post)

  elseif action == "geolock" then
    show_geolock_view(r, nil)

  elseif action == "geolock_reset" and r.method == "POST" then
    do_geolock_reset(r)

  else
    show_list(r)
  end
end
