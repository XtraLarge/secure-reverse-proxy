--
-- admin.lua — Proxy VHost Admin Interface
--
-- Served on admin.DOMAIN — OIDC-protected via CLIENTOIDC_CLAIM.
-- Reads/writes /etc/apache2/sites-enabled/*.conf files.
-- sites-enabled volume must be mounted read-write.
--

local SITES_DIR = "/etc/apache2/sites-enabled/"

local MACRO_TYPES = {
  "VHost_Proxy",
  "VHost_Proxy_OIDC",
  "VHost_Proxy_OIDC_Claim",
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

  if m == "vhost_proxy" or m == "vhost_proxy_oidc" or m == "vhost_alias" then
    return string.format("Use %-28s  %-20s  %-25s  %s", macro, name, domain, dest)
  elseif m == "vhost_proxy_oidc_claim" then
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

-- ── CSS / HTML ─────────────────────────────────────────────────────────────────

local CSS = [[<style>
*{box-sizing:border-box}
body{font-family:Arial,sans-serif;margin:0;padding:1.5em;background:#0d0d1a;color:#ddd}
h1{color:#00d4ff;margin:0 0 .3em}h1 a{color:inherit;text-decoration:none}
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
.topbar{display:flex;align-items:center;gap:1em;margin-bottom:1.2em;flex-wrap:wrap}
.dim{color:#666;font-size:.8em}
</style>]]

local JS = [[<script>
var NEEDS_USERS  = {vhost_proxy_oidc_claim:1, vhost_proxy_basic:1};
var NEEDS_AUTH   = {vhost_proxy_basic:1};
function onMacroChange(sel) {
  var m = sel.value.toLowerCase();
  document.getElementById('row_users').style.display  = NEEDS_USERS[m]  ? '' : 'none';
  document.getElementById('row_auth').style.display   = NEEDS_AUTH[m]   ? '' : 'none';
  document.getElementById('lbl_users').textContent    =
    m === 'vhost_proxy_basic' ? 'Passwort-Eintrag:' : 'Benutzer (|getrennt):';
}
</script>]]

local function page_head(title)
  return "<!DOCTYPE html><html lang=de><head><meta charset=UTF-8>"
    .. "<meta name=viewport content='width=device-width,initial-scale=1'>"
    .. "<title>" .. h(title) .. " — Proxy Admin</title>"
    .. CSS .. JS .. "</head><body>"
    .. '<h1><a href="/">&#9881; Proxy Admin</a></h1>'
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
  elseif ml:find("claim") then cls = cls .. " tag-claim"
  elseif ml:find("oidc")  then cls = cls .. " tag-oidc"
  elseif ml:find("alias") then cls = cls .. " tag-alias"
  else                         cls = cls .. " tag-proxy" end
  return '<span class="' .. cls .. '">' .. h(m) .. '</span>'
end

-- ── List page ─────────────────────────────────────────────────────────────────

local function show_list(r, msg)
  r:puts(page_head("Übersicht"))
  if msg then r:puts(msg_html(msg)) end

  r:puts('<div class="topbar">')
  r:puts('<form method="POST" action="/?action=apply">')
  r:puts('<button class="btn b-apply" type="submit">&#9654;&nbsp;Konfiguration anwenden</button>')
  r:puts('</form>')
  r:puts('<span class="dim">Änderungen erst nach "Anwenden" aktiv (graceful reload)</span>')
  r:puts('</div>')

  local files = list_conf_files()
  for _, fpath in ipairs(files) do
    local fname = fpath:match("([^/]+)$")
    local lines = read_lines(fpath)
    if not lines then goto continue end

    -- Count vhost entries
    local entries = 0
    for _, l in ipairs(lines) do
      if is_vhost_line(l) then entries = entries + 1 end
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
        if is_vhost_line(line) then
          local v = parse_vhost_line(line)
          if v then
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
  r:puts('</body></html>')
end

-- ── Entry form ────────────────────────────────────────────────────────────────

local function show_form(r, fname, lineno, pre, errmsg)
  local title = lineno and "Eintrag bearbeiten" or "Neuer Eintrag"
  r:puts(page_head(title))
  r:puts('<div class="card">')
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
  local show_users = (cur == "vhost_proxy_oidc_claim" or cur == "vhost_proxy_basic")
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
  r:puts('</div></form></div></body></html>')
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

  local ok, err = write_lines(fpath, lines)
  if ok then
    show_list(r, "OK: Gespeichert — Konfiguration noch anwenden!")
  else
    show_list(r, "ERR: Schreiben fehlgeschlagen — " .. (err or "sites-enabled nicht beschreibbar?"))
  end
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

  table.remove(lines, lineno)
  local ok, err = write_lines(fpath, lines)
  if ok then
    show_list(r, "OK: Gelöscht — Konfiguration noch anwenden!")
  else
    show_list(r, "ERR: Schreiben fehlgeschlagen — " .. (err or ""))
  end
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

  else
    show_list(r)
  end
end
