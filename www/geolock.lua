--
-- geolock.lua — GeoIP-Ländersperre, PIN-geschützt
--
-- GET  /  → Formular mit Länder-Multiselect + PIN
-- POST /  action=save → PIN prüfen, Länder speichern, Apache graceful reload
--
-- Dateien:
--   /etc/apache2/conf-runtime/geolock-pin.hash   SHA256 des PIN (entrypoint.sh)
--   /etc/apache2/conf-runtime/geolock.lock        Fehlversuche (0..n)
--   /etc/apache2/AddOn/.extra-countries.conf      SetEnvIf-Direktive (persistent)
--   /etc/apache2/sites-admin/*.conf               VHost-Konfiguration (Self-Disable)

local RUNTIME   = "/etc/apache2/conf-runtime/"
local PIN_FILE  = RUNTIME .. "geolock-pin.hash"
local LOCK_FILE = RUNTIME .. "geolock.lock"
local CONF_FILE = "/etc/apache2/AddOn/.extra-countries.conf"
local SITES_DIR = "/etc/apache2/sites-admin/"
local MAX_FAIL  = 3

local COUNTRIES = {
  {"AL","Albanien"},    {"AT","Österreich"},    {"AU","Australien"},   {"BA","Bosnien"},
  {"BE","Belgien"},     {"BG","Bulgarien"},     {"CA","Kanada"},       {"CH","Schweiz"},
  {"CY","Zypern"},      {"CZ","Tschechien"},    {"DE","Deutschland"},  {"DK","Dänemark"},
  {"EE","Estland"},     {"EG","Ägypten"},       {"ES","Spanien"},      {"FI","Finnland"},
  {"FR","Frankreich"},  {"GB","Großbritannien"},{"GR","Griechenland"}, {"HR","Kroatien"},
  {"HU","Ungarn"},      {"IE","Irland"},        {"IS","Island"},       {"IT","Italien"},
  {"JP","Japan"},       {"LT","Litauen"},       {"LU","Luxemburg"},    {"LV","Lettland"},
  {"MA","Marokko"},     {"ME","Montenegro"},    {"MT","Malta"},        {"MX","Mexiko"},
  {"NL","Niederlande"}, {"NO","Norwegen"},      {"NZ","Neuseeland"},   {"PL","Polen"},
  {"PT","Portugal"},    {"RO","Rumänien"},      {"RS","Serbien"},      {"SE","Schweden"},
  {"SI","Slowenien"},   {"SK","Slowakei"},      {"TH","Thailand"},     {"TN","Tunesien"},
  {"TR","Türkei"},      {"US","USA"},
}

local function read_file(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local s = f:read("*a"); f:close(); return s
end

local function read_lines(path)
  local f = io.open(path, "r")
  if not f then return nil end
  local lines = {}
  for l in f:lines() do table.insert(lines, l) end
  f:close()
  return lines
end

local function write_lines_atomic(path, lines)
  local tmp = path .. ".tmp"
  local f = io.open(tmp, "w")
  if not f then return false end
  for _, l in ipairs(lines) do f:write(l .. "\n") end
  f:close()
  return os.rename(tmp, path)
end

local function get_failures()
  return tonumber(read_file(LOCK_FILE) or "") or 0
end

local function set_failures(n)
  local f = io.open(LOCK_FILE, "w")
  if f then f:write(tostring(n) .. "\n"); f:close() end
end

local function sha256hex(s)
  if #s > 256 then return "" end
  -- Write to temp file — avoids any shell escaping issues
  local tmp = "/tmp/.geolock_pincheck"
  local f = io.open(tmp, "w")
  if not f then return "" end
  f:write(s); f:close()
  local p = io.popen("sha256sum " .. tmp .. " 2>/dev/null")
  if not p then os.remove(tmp); return "" end
  local out = p:read("*l") or ""; p:close()
  os.remove(tmp)
  return out:match("^([0-9a-f]+)") or ""
end

local function check_pin(pin)
  local stored = (read_file(PIN_FILE) or ""):match("^([0-9a-f]+)")
  if not stored or stored == "" then return false end
  return sha256hex(pin) == stored
end

local function get_extra()
  local c = read_file(CONF_FILE) or ""
  local set = {}
  local codes = c:match('"^%(([A-Z|]+)%)%$"')
  if codes then
    for code in codes:gmatch("[A-Z]+") do set[code] = true end
  end
  return set
end

local function save_extra(codes)
  local f = io.open(CONF_FILE, "w")
  if not f then return false end
  if #codes == 0 then
    f:write("# no extra countries\n")
  else
    f:write('SetEnvIf GEOIP_COUNTRY_CODE "^(' .. table.concat(codes, "|") .. ')$" AllowCountry\n')
  end
  f:close()
  return true
end

local function graceful_reload()
  os.execute("kill -USR1 $(pgrep -o -x apache2 2>/dev/null) 2>/dev/null &")
end

local function self_disable(domain)
  local domain_pat = domain:gsub("[%.%-%+%?%%%[%]%^%$%(%)%*]", "%%%1")
  local line_pat = "^%s*[Uu]se%s+[Gg]eo[Ll]ock_[Vv][Hh]ost%s+" .. domain_pat .. "%s*$"
  local p = io.popen("ls " .. SITES_DIR .. "*.conf 2>/dev/null")
  if not p then return false end
  local files = {}
  for fp in p:lines() do table.insert(files, fp) end
  p:close()
  for _, fpath in ipairs(files) do
    local lines = read_lines(fpath)
    if lines then
      for i, l in ipairs(lines) do
        if l:match(line_pat) then
          lines[i] = "# " .. l
          write_lines_atomic(fpath, lines)
          return true
        end
      end
    end
  end
  return false
end

local function urldecode(s)
  return s:gsub("+", " "):gsub("%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end)
end

local function parse_body(body)
  local t = {}
  for k, v in (body .. "&"):gmatch("([^=&]+)=([^&]*)&") do
    k, v = urldecode(k), urldecode(v)
    if t[k] then
      if type(t[k]) ~= "table" then t[k] = {t[k]} end
      table.insert(t[k], v)
    else
      t[k] = v
    end
  end
  return t
end

local function h(s)
  return tostring(s):gsub("&","&amp;"):gsub("<","&lt;"):gsub(">","&gt;"):gsub('"',"&quot;")
end

local CSS = [[
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#0d0d1a;color:#ddd;min-height:100vh;
  display:flex;align-items:flex-start;justify-content:center;padding:2rem 1rem}
.card{background:#0a0a22;border:1px solid #2a2a4e;border-radius:6px;
  width:100%;max-width:520px;overflow:hidden}
.card-head{background:#060614;border-bottom:1px solid #2a2a4e;padding:.9rem 1.3rem;
  display:flex;align-items:center;gap:.6rem}
.card-head h1{font-size:1rem;font-weight:bold;color:#00d4ff}
.card-body{padding:1.2rem 1.3rem}
.field+.field{margin-top:.95rem}
label{display:block;font-size:.78rem;color:#8888aa;margin-bottom:.28rem;font-weight:500;
  text-transform:uppercase;letter-spacing:.04em}
select[multiple]{width:100%;background:#060614;border:1px solid #2a2a4e;
  color:#ccc;border-radius:4px;padding:.3rem;font-size:.85rem;outline:none;height:195px}
select[multiple] option:checked{background:#1a3a6a;color:#9cc4ff}
input[type=password]{width:100%;background:#060614;border:1px solid #2a2a4e;
  color:#ccc;border-radius:4px;padding:.45rem .7rem;font-size:.9rem;outline:none}
input[type=password]:focus{border-color:#4466aa}
.btn-save{background:#003d3d;color:#99ffff;border:1px solid #005555;
  padding:.42rem 1.2rem;border-radius:4px;font-size:.9rem;cursor:pointer;font-weight:500}
.btn-save:hover{background:#004f4f}
.alert{border-radius:4px;padding:.6rem .9rem;font-size:.85rem;margin-bottom:.9rem;line-height:1.5}
.alert-err {background:#3d0000;color:#ff9999;border:1px solid #5a1a1a}
.alert-ok  {background:#003d00;color:#99ff99;border:1px solid #1a5a1a}
.alert-lock{background:#2a1800;color:#ffb060;border:1px solid #5a3a10}
.detected{font-size:.8rem;color:#6668a0;margin-bottom:.9rem}
.detected strong{color:#9cc4ff}
.hint{font-size:.74rem;color:#555570;margin-top:.22rem}
.badge{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.72rem}
.badge-warn{background:#2a1800;color:#ffb060;border:1px solid #5a3a10}
.base-countries{font-size:.78rem;background:#0d0d22;border:1px solid #2a2a4e;
  border-radius:4px;padding:.45rem .7rem;color:#6688aa;margin-bottom:.9rem}
.base-countries strong{color:#7799cc}
]]

function handle(r)
  local configured = (read_file(PIN_FILE) or ""):match("^[0-9a-f]+")
  local failures   = get_failures()
  local locked     = failures >= MAX_FAIL
  local own_domain = (r.hostname or ""):gsub("^geolock%.", "")

  r.content_type = "text/html; charset=utf-8"

  local function page(content)
    r:puts('<!DOCTYPE html><html lang="de"><head><meta charset="utf-8">')
    r:puts('<meta name="viewport" content="width=device-width,initial-scale=1">')
    r:puts('<meta name="robots" content="noindex,nofollow">')
    r:puts('<title>GeoLock</title><style>' .. CSS .. '</style></head><body>')
    r:puts('<div class="card">')
    r:puts('<div class="card-head"><span style="font-size:1.3rem">&#127757;</span>')
    r:puts('<h1>GeoLock \xe2\x80\x94 L\xc3\xa4nderfreigabe</h1></div>')
    r:puts('<div class="card-body">' .. content .. '</div></div></body></html>')
  end

  if not configured then
    page('<div class="alert alert-err">GeoLock nicht konfiguriert (GEOLOCK_PIN fehlt).</div>')
    return apache2.OK
  end

  if locked then
    page('<div class="alert alert-lock"><strong>Gesperrt.</strong> '
      .. 'Zu viele fehlerhafte PIN-Eingaben. '
      .. 'Entsperren \xc3\xbcber die Admin-Oberfl\xc3\xa4che.</div>')
    return apache2.OK
  end

  local post = {}
  if r.method == "POST" then
    post = parse_body(r:requestbody())
  end

  local alert = ""

  if r.method == "POST" and post["action"] == "save" then
    local pin = tostring(post["pin"] or "")
    if not check_pin(pin) then
      local new_fail = failures + 1
      set_failures(new_fail)
      if new_fail >= MAX_FAIL then
        self_disable(own_domain)
        graceful_reload()
        page('<div class="alert alert-lock"><strong>Gesperrt.</strong> '
          .. 'Zu viele fehlerhafte PIN-Eingaben. '
          .. 'Entsperren \xc3\xbcber die Admin-Oberfl\xc3\xa4che.</div>')
        return apache2.OK
      end
      local left = MAX_FAIL - new_fail
      alert = '<div class="alert alert-err">Falscher PIN \xe2\x80\x94 noch '
        .. left .. ' Versuch(e).</div>'
    else
      set_failures(0)
      local raw = post["countries"]
      local sel = type(raw) == "table" and raw or (raw and raw ~= "" and {raw} or {})
      local valid = {}
      for _, code in ipairs(sel) do
        if code:match("^[A-Z][A-Z]$") then table.insert(valid, code) end
      end
      save_extra(valid)
      graceful_reload()
      os.execute("sleep 0.5 2>/dev/null")
      local msg = #valid == 0
        and 'Keine zus\xc3\xa4tzlichen L\xc3\xa4nder aktiv \xe2\x80\x94 Konfiguration \xc3\xbcbernommen.'
        or  'Aktiv: ' .. h(table.concat(valid, ", ")) .. ' \xe2\x80\x94 Konfiguration \xc3\xbcbernommen.'
      alert = '<div class="alert alert-ok">' .. msg .. '</div>'
      failures = 0
    end
  end

  -- Render form
  local cc    = r.subprocess_env["GEOIP_COUNTRY_CODE"] or "??"
  local extra = get_extra()

  -- Build base-countries display from GEOIP_ALLOW_COUNTRIES env var
  local base_env  = os.getenv("GEOIP_ALLOW_COUNTRIES") or ""
  local base_list = {}
  for code in base_env:gmatch("[A-Z]+") do
    -- find country name from COUNTRIES table
    local name = code
    for _, c in ipairs(COUNTRIES) do
      if c[1] == code then name = code .. " \xe2\x80\x94 " .. c[2]; break end
    end
    table.insert(base_list, name)
  end
  local base_html = #base_list > 0
    and ('<div class="base-countries"><strong>Basis-L\xc3\xa4nder (immer aktiv):</strong> '
         .. h(table.concat(base_list, ", ")) .. '</div>')
    or ""

  local detected = '<p class="detected">Erkanntes Land: <strong>' .. h(cc) .. '</strong>'
  if failures > 0 then
    detected = detected .. ' &nbsp;<span class="badge badge-warn">noch '
      .. (MAX_FAIL - failures) .. ' Versuch(e)</span>'
  end
  detected = detected .. '</p>'

  local opts = {}
  for _, c in ipairs(COUNTRIES) do
    local sel = extra[c[1]] and ' selected' or ''
    table.insert(opts, '<option value="' .. c[1] .. '"' .. sel .. '>'
      .. c[1] .. ' \xe2\x80\x94 ' .. c[2] .. '</option>')
  end

  local form = '<form method="post" autocomplete="off">'
    .. '<input type="hidden" name="action" value="save">'
    .. base_html
    .. '<div class="field"><label>Zus\xc3\xa4tzliche L\xc3\xa4nder (Strg+Klick = Mehrfachauswahl)</label>'
    .. '<select name="countries" multiple>' .. table.concat(opts) .. '</select></div>'
    .. '<div class="field"><label>PIN</label>'
    .. '<input type="password" name="pin" autofocus placeholder="\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2" maxlength="128"></div>'
    .. '<div class="field"><button type="submit" class="btn-save">Speichern &amp; Aktivieren</button></div>'
    .. '</form>'

  page(alert .. detected .. form)
  return apache2.OK
end
