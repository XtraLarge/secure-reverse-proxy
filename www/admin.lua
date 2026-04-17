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

local MACRO_TYPES = {
  "VHost_Proxy",
  "VHost_Proxy_OIDC",
  "VHost_Proxy_OIDC_Any",
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

  if m == "vhost_proxy" or m == "vhost_proxy_oidc_any" or m == "vhost_alias" then
    return string.format("Use %-28s  %-20s  %-25s  %s", macro, name, domain, dest)
  elseif m == "vhost_proxy_oidc" then
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
  -- Ensure parent directory exists
  local dir = fpath:match("^(.*)/[^/]+$")
  if dir then os.execute("mkdir -p " .. dir) end
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
  local files = {}
  local p = io.popen("ls " .. SITES_DIR .. "*.conf 2>/dev/null")
  for fname in p:lines() do
    if not fname:match("%.bak") then
      table.insert(files, fname)
    end
  end
  p:close()
  return files
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
.topbar-title{color:#00d4ff;font-size:1.1em;font-weight:bold;text-decoration:none}
.topbar-nav{display:flex;gap:.5em}
.topbar-nav a{
  color:#7ecfff;text-decoration:none;font-size:.85em;
  border:1px solid #2a2a4e;border-radius:3px;padding:3px 10px;
  background:#0a0a22;transition:background .15s}
.topbar-nav a:hover{background:#0f3460;color:#00d4ff}
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
a.btn,button.btn{padding:4px 11px;border:none;border-radius:3px;cursor:pointer;
  text-decoration:none;display:inline-block;font-size:.82em;line-height:1.5}
.b-edit{background:#0f3460;color:#7ecfff}.b-del{background:#5c0000;color:#ff9999}
.b-addon{background:#1a1a00;color:#555533}.b-addon-active{background:#3a3300;color:#ffee44;font-weight:bold}
.b-cfg{background:#001f33;color:#5599bb}
.b-add{background:#003d00;color:#99ff99}.b-apply{background:#3d3d00;color:#ffff99;
  font-size:.95em;padding:7px 18px}.b-save{background:#003d3d;color:#99ffff}
.b-cancel{background:#2a2a4e;color:#aaa}
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
</style>]]

local JS = [[<script>
var NEEDS_USERS  = {vhost_proxy_oidc:1, vhost_proxy_basic:1};
var NEEDS_AUTH   = {vhost_proxy_basic:1};
function onMacroChange(sel) {
  var m = sel.value.toLowerCase();
  document.getElementById('row_users').style.display  = NEEDS_USERS[m]  ? '' : 'none';
  document.getElementById('row_auth').style.display   = NEEDS_AUTH[m]   ? '' : 'none';
  document.getElementById('lbl_users').textContent    =
    m === 'vhost_proxy_basic' ? 'Passwort-Eintrag:' : 'Benutzer (|getrennt):';
}
</script>]]

local TOC_DOMAIN = ""
do
  -- Derive TOC domain from sites-admin first, fall back to sites-enabled
  local p = io.popen("ls /etc/apache2/sites-admin/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | head -1")
  if p then
    local f = p:read("*l") or ""
    p:close()
    -- extract domain: basename without .conf
    TOC_DOMAIN = f:match("([^/]+)%.conf$") or ""
  end
end

local function topbar(title)
  local toc_link  = TOC_DOMAIN ~= "" and ("https://toc."    .. TOC_DOMAIN) or "/"
  local logout_link = TOC_DOMAIN ~= "" and ("https://logout." .. TOC_DOMAIN) or "/logout"
  return '<div class="topbar">'
    .. '<a class="topbar-title" href="/">\xE2\x9A\x99 ' .. h(title) .. '</a>'
    .. '<div class="topbar-nav">'
    .. '<a href="' .. h(toc_link) .. '">\xE2\x98\xB0 TOC</a>'
    .. '<a href="' .. h(logout_link) .. '">\xC3\x97 Logout</a>'
    .. '</div>'
    .. '</div>'
end

local function page_head(title)
  return "<!DOCTYPE html><html lang=de><head><meta charset=UTF-8>"
    .. "<meta name=viewport content='width=device-width,initial-scale=1'>"
    .. "<title>" .. h(title) .. " — Proxy Admin</title>"
    .. CSS .. JS .. "</head><body>"
    .. topbar(title)
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
  if ml:find("basic")   then cls = cls .. " tag-basic"
  elseif ml:find("_any")   then cls = cls .. " tag-oidc"
  elseif ml:find("oidc")   then cls = cls .. " tag-claim"
  elseif ml:find("alias")  then cls = cls .. " tag-alias"
  else                          cls = cls .. " tag-proxy" end
  return '<span class="' .. cls .. '">' .. h(m) .. '</span>'
end

-- ── List page ─────────────────────────────────────────────────────────────────

local function show_list(r, msg)
  r:puts(page_head("Übersicht"))
  if msg then r:puts(msg_html(msg)) end

  r:puts('<div class="main">')
  r:puts('<div class="applybar">')
  r:puts('<form method="POST" action="/?action=apply">')
  r:puts('<button class="btn b-apply" type="submit">&#9654;&nbsp;Konfiguration anwenden</button>')
  r:puts('</form>')
  r:puts('<a class="btn b-add" href="/?action=domain_new">+ Neue Domain</a>')
  r:puts('<span class="dim">Änderungen erst nach "Anwenden" aktiv (graceful reload)</span>')
  r:puts('</div>')

  local files = list_conf_files()
  for _, fpath in ipairs(files) do
    local fname = fpath:match("([^/]+)$")
    local lines = read_lines(fpath)
    if not lines then goto continue end

    -- Count vhost entries
    local entries = 0
    for i, l in ipairs(lines) do
      if is_vhost_line(l) and not is_no_admin(lines, i) then entries = entries + 1 end
    end

    r:puts('<div class="card">')
    r:puts('<h2>' .. h(fname)
      .. ' <span class="dim">(' .. entries .. ' Einträge)</span>&nbsp;'
      .. '<a class="btn b-add" href="/?action=new&amp;file=' .. h(fname) .. '">+ Hinzufügen</a>'
      .. '</h2>')

    if entries == 0 then
      r:puts('<p class="dim">Keine VHost-Einträge in dieser Datei.</p>')
    else
      r:puts('<table><tr><th>Typ</th><th>Name</th><th>Domain</th><th>Ziel</th><th>Benutzer</th><th>Aktionen</th></tr>')
      for lineno, line in ipairs(lines) do
        if is_vhost_line(line) and not is_no_admin(lines, lineno) then
          local v = parse_vhost_line(line)
          if v then
            -- Check if AddOn files exist for this entry
            local has_pre  = fexists(addon_path(v.domain, v.name, "preconfig"))
            local has_post = fexists(addon_path(v.domain, v.name, "postconfig"))
            local has_addon = has_pre or has_post
            -- Describe which files exist (pre / post / beide)
            local addon_hint = ""
            if has_pre and has_post then addon_hint = "pre+post"
            elseif has_pre          then addon_hint = "pre"
            elseif has_post         then addon_hint = "post"
            end

            r:puts('<tr>')
            r:puts('<td>' .. macro_tag(v.macro) .. '</td>')
            r:puts('<td>' .. h(v.name) .. '</td>')
            r:puts('<td>' .. h(v.domain) .. '</td>')
            r:puts('<td style="font-family:monospace;font-size:.82em">' .. h(v.dest) .. '</td>')
            r:puts('<td style="font-size:.82em">' .. h(v.users) .. '</td>')
            r:puts('<td><div class="actions">')
            -- Edit
            r:puts('<a class="btn b-edit" href="/?action=edit&amp;file='
              .. h(fname) .. '&amp;line=' .. lineno .. '">Bearbeiten</a>')
            -- AddOn: bright when files exist, dim when not
            if has_addon then
              r:puts('<a class="btn b-addon-active" href="/?action=addon&amp;name='
                .. h(v.name) .. '&amp;domain=' .. h(v.domain)
                .. '" title="AddOn vorhanden: ' .. addon_hint .. '">'
                .. '&#9679;&nbsp;AddOn</a>')
            else
              r:puts('<a class="btn b-addon" href="/?action=addon&amp;name='
                .. h(v.name) .. '&amp;domain=' .. h(v.domain) .. '">AddOn</a>')
            end
            -- Config view
            r:puts('<a class="btn b-cfg" href="/?action=config&amp;file='
              .. h(fname) .. '&amp;line=' .. lineno .. '">Config</a>')
            -- Delete
            r:puts('<form method="POST" action="/?action=delete" style="margin:0"'
              .. ' onsubmit="return confirm(\'Eintrag ' .. h(v.name) .. ' wirklich löschen?\')">')
            r:puts('<input type=hidden name=file value="' .. h(fname) .. '">')
            r:puts('<input type=hidden name=line value="' .. lineno .. '">')
            r:puts('<input type=hidden name=check value="' .. h(trim(line)) .. '">')
            r:puts('<button class="btn b-del" type=submit>Löschen</button></form>')
            r:puts('</div></td></tr>')
          end
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

local function show_form(r, fname, lineno, pre, errmsg)
  local title = lineno and "Eintrag bearbeiten" or "Neuer Eintrag"
  r:puts(page_head(title))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>' .. title .. ' — ' .. h(fname) .. '</h2>')
  if errmsg then r:puts(msg_html("ERR: " .. errmsg)) end

  r:puts('<form method="POST" action="/?action=save">')
  r:puts('<input type=hidden name=file value="' .. h(fname) .. '">')
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
    .. '<input name=name value="' .. h((pre and pre.name) or "") .. '" placeholder="monitor" required></div>')

  -- Domain
  r:puts('<div class="form-row"><label>Domain:</label>'
    .. '<input name=domain value="' .. h((pre and pre.domain) or "") .. '" placeholder="example.com" required></div>')

  -- Destination
  r:puts('<div class="form-row"><label>Ziel-URL:</label>'
    .. '<input name=dest value="' .. h((pre and pre.dest) or "") .. '" placeholder="http://10.0.0.1:8080/" required></div>')

  -- Users (OIDC_Claim + Basic)
  local show_users = (cur == "vhost_proxy_oidc" or cur == "vhost_proxy_basic")
  local lbl_users  = cur == "vhost_proxy_basic" and "Passwort-Eintrag:" or "Benutzer (|getrennt):"
  r:puts('<div class="form-row" id=row_users style="display:' .. (show_users and "" or "none") .. '">')
  r:puts('<label id=lbl_users>' .. lbl_users .. '</label>')
  r:puts('<input name=users value="' .. h((pre and pre.users) or "") .. '" placeholder="alice|bob"></div>')

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
  show_list(r, "OK: Gelöscht (Konfigurationstest erfolgreich) — Konfiguration noch anwenden!")
end

-- ── Apply (POST) ──────────────────────────────────────────────────────────────

local function do_apply(r)
  -- apache2ctl graceful sends SIGUSR1 to the running master process
  local ret = os.execute("/usr/sbin/apache2ctl graceful 2>/dev/null")
  if ret == 0 or ret == true then
    show_list(r, "OK: Apache graceful reload ausgeführt")
  else
    show_list(r, "ERR: apache2ctl graceful fehlgeschlagen (Code: " .. tostring(ret) .. ")")
  end
end

-- ── AddOn form ────────────────────────────────────────────────────────────────

-- pre_override / post_override: when not nil, these override what's read from disk
-- (used to redisplay attempted content after a failed configtest)
local function show_addon_form(r, name, domain, errmsg, testout, pre_override, post_override)
  r:puts(page_head("AddOn: " .. name .. "." .. domain))
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
  show_list(r, "OK: AddOn auf letzte Version zurückgesetzt (Konfigurationstest erfolgreich) — noch anwenden!")
end

-- ── Domain creation form ──────────────────────────────────────────────────────

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

  show_list(r, "OK: Domain " .. domain .. " angelegt — Konfiguration noch anwenden!")
end

-- ── VHost config view ────────────────────────────────────────────────────────

-- Extract all <VirtualHost> blocks whose ServerName matches fqdn (case-insensitive).
-- Uses apache2ctl -t -DDUMP_CONFIG which outputs the fully macro-expanded config.
local function extract_vhost_blocks(full_config, fqdn)
  local blocks = {}
  local fqdn_pat = fqdn:lower():gsub("%-", "%%-"):gsub("%.", "%%.")
  local pos = 1
  while true do
    local s = full_config:find("<VirtualHost", pos, true)
    if not s then break end
    local e = full_config:find("</VirtualHost>", s, true)
    if not e then break end
    e = e + #"</VirtualHost>" - 1
    local block = full_config:sub(s, e)
    -- Match ServerName directive in this block
    if block:lower():match("servername%s+" .. fqdn_pat .. "%s") or
       block:lower():match("servername%s+" .. fqdn_pat .. "$") then
      table.insert(blocks, block)
    end
    pos = e + 1
  end
  return blocks
end

local function show_vhost_config_view(r, name, domain, rawline)
  local vhost_fqdn = name .. "." .. domain
  r:puts(page_head("Config: " .. vhost_fqdn))
  r:puts('<div class="main"><div class="card">')
  r:puts('<h2>Konfiguration — <code>' .. h(vhost_fqdn) .. '</code></h2>')

  -- Macro call line (source reference)
  r:puts('<p style="color:#aaa;font-size:.85em;margin-bottom:.4em">Macro-Aufruf in sites-admin:</p>')
  r:puts('<pre style="background:#060614;color:#7ecfff;padding:.7em;border-radius:3px;'
    .. 'font-size:.85em;margin-bottom:1.2em;overflow-x:auto">' .. h(rawline) .. '</pre>')

  -- Expanded VHost config via DUMP_CONFIG
  local p = io.popen("/usr/sbin/apache2ctl -t -DDUMP_CONFIG 2>&1")
  local full_config = p:read("*a")
  p:close()

  local blocks = extract_vhost_blocks(full_config, vhost_fqdn)
  if #blocks > 0 then
    r:puts('<p style="color:#aaa;font-size:.85em;margin-bottom:.4em">'
      .. 'Expandierte Apache-Konfiguration (' .. #blocks
      .. ' VirtualHost-Block' .. (#blocks > 1 and "s" or "") .. '):</p>')
    for i, block in ipairs(blocks) do
      if #blocks > 1 then
        -- Port hint from opening tag, e.g. <VirtualHost *:443>
        local port = block:match("<VirtualHost[^>]*:(%d+)") or tostring(i)
        r:puts('<p style="color:#666;font-size:.78em;margin:.6em 0 .2em">— Port ' .. port .. ' —</p>')
      end
      r:puts('<pre style="background:#060614;color:#ddd;padding:.7em;border-radius:3px;'
        .. 'font-size:.82em;margin-bottom:1em;overflow-x:auto;white-space:pre-wrap">'
        .. h(block) .. '</pre>')
    end
  else
    r:puts('<p style="color:#aa6600;font-size:.85em;margin-bottom:1.2em">'
      .. 'Kein VirtualHost-Block f\xC3\xBCr <strong>' .. h(vhost_fqdn) .. '</strong> gefunden.<br>'
      .. 'M\xC3\xB6glicherweise wurde die Konfiguration noch nicht angewendet '
      .. 'oder der Macro-Aufruf enth\xC3\xA4lt einen Fehler.</p>')
  end

  r:puts('<a class="btn b-cancel" href="/">&#8592;&nbsp;Zur\xC3\xBCck zur \xC3\x9Cbersicht</a>')
  r:puts('</div></div></body></html>')
end

-- ── Request dispatcher ────────────────────────────────────────────────────────

function handle(r)
  r.content_type = "text/html; charset=UTF-8"

  local get  = r:parseargs()
  local post = {}
  if r.method == "POST" then
    local _, body = r:parsebody(1024 * 64)
    if type(body) == "table" then post = body end
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

  else
    show_list(r)
  end
end
