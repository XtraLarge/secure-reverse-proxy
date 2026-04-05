--
--
--  # INIT #
--
--

TITLE       = os.getenv("TOC_TITLE") or "Inhaltsverzeichnis der Server"
REMOTE_USER = os.getenv("TOC_REMOTE_USER_DEFAULT") or ""
T           = {"STATUS", "NAME", "DOMAIN", "TYP",  "DEST",        "IPROT",       "IIP",     "IPORT",     "SECURE",  "USERS"} 
TT          = {"Status", "Name", "Domain", "Type", "Destination", "Int. Proto.", "Int. IP", "Int. Port", "Secured", "Users"}
A           = {};


--
--
--  # Helper Functions #
--
--


-- remove pre and post blanks
function all_trim(s)
   return s:match( "^%s*(.-)%s*$" )
end

-- see if the file exists
function file_exists(file)
  local f = io.open(file, "rb")
  if f then f:close() end
  return f ~= nil
end

-- get n-th word of a string
function word (S,W)
  local T = {}
  for word in S:gmatch("%S+") do table.insert(T, word) end
  return T[W];
end

-- check that string starts with a given string
function startswith(S, str)
  -- Typprüfung, um nil oder Nicht-Strings abzufangen
  if type(S) ~= "string" or type(str) ~= "string" then
    return false
  end

  local len = #str
  if len == 0 then return true end           -- leerer Präfix passt immer
  if #S < len then return false end          -- zu kurz, kann nicht passen

  -- vergleiche den Anfang
  return S:sub(1, len) == str
end

-- check that string ends with a given string
function endswith(S, str)
  if type(S) ~= "string" or type(str) ~= "string" then
    return false
  end
  local len = #str
  if len == 0 then return true end           -- leerer Suffix passt immer
  if #S < len then return false end          -- kürzerer String kann nicht enden mit
  return S:sub(-len) == str
end


-- get string after other strings
function after(S, str1)
  local T
  local P1

  P1 = string.find(S,str1)
  if P1 == nil then T=""
  else 
    P1 = P1 + string.len(str1)
    T = string.sub(S, P1)
  end
  return T
end

-- get string before other strings
function before(S, str1)
  local T
  local P1

  P1 = string.find(S,str1)
  if P1 == nil then T=""
  else 
    T = string.sub(S, 1, P1-1)
  end
  return T
end

-- check is string in other string
function isin(S, str1)
  if string.find(S,str1) ~= nil then return true
                                else return false
  end
end

-- get string between two other strings
function between(S, str1, str2)
  local T
  local P1
  local P2

  P1 = string.find(S,str1)
  if P1 == nil then 
    P1 = 0; 
    P2 = 0; 
  else
    P1 = P1 + string.len(str1)
    P2 = string.find(S, str2, P1 )
    if P2 == nil then 
      P2 = 0;
    else
      P2 = P2 - string.len(str2);
    end
  end
    
  if (P2 - P1 <= 0) then T = "" 
    else T = string.sub(S, P1, P2 )
  end
  return T
end

-- get string shortbetween two other strings
function shortbetween(S, str1, str2)
  local T
  local P1
  local P2

  P1 = S:match(".*()" .. str1)

  if P1 == nil then 
    P1 = 0; 
    P2 = 0; 
  else
    P1 = P1 + 1
    P2 = string.find(S, str2, P1 )
    if P2 == nil then 
      P2 = 0;
    else
      P2 = P2 -1
    end
  end
    
  if (P2 - P1 <= 0) then T = "" 
    else T = string.sub(S, P1, P2 )
  end
  return T
end


-- check address type
function finalword(S, W)
  local I
  for I=1,W-1 do
    S=all_trim(S)
    if isin(S, " ") then S = all_trim(after(S, " ")) end
  end
  return S
end

-- check address type
function GetIPType(ip)
  local R = {ERROR = 0, IPV4 = 1, IPV6 = 2, STRING = 3}
  if type(ip) ~= "string" then return R.ERROR end

  -- check for format 1.11.111.111 for ipv4
  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks == 4 then
    for _,v in pairs(chunks) do
      if tonumber(v) > 255 then return R.STRING end
    end
    return R.IPV4
  end

  -- check for ipv6 format, should be 8 'chunks' of numbers/letters
  -- without leading/trailing chars
  -- or fewer than 8 chunks, but with only one `::` group
  local chunks = {ip:match("^"..(("([a-fA-F0-9]*):"):rep(8):gsub(":$","$")))}
  if #chunks == 8
  or #chunks < 8 and ip:match('::') and not ip:gsub("::","",1):match('::') then
    for _,v in pairs(chunks) do
      if #v > 0 and tonumber(v, 16) > 65535 then return R.STRING end
    end
    return R.IPV6
  end

  return R.STRING
end

-- parse webserver type
function stype (S)
  local T;
  if endswith(S,"alias") then T = "Redirect"
    elseif startswith(S,"vhost_proxy") then T = "Reverse Proxy"
    else T=" - Unknown -"
  end
  return T;
end

-- parse security type
function ssec (S)
  local T;
  if endswith(S,"alias") then T="-"
    elseif endswith(S,"oidc")  then T="OpenID Connect"
    elseif endswith(S,"basic") then T="Basic"
    elseif endswith(S,"ccert") then T="Client Certificate"
    elseif endswith(S,"otp")   then T="One Time Password"
    else T="-"
  end
  return T;
end

-- parse internal protocol type
function sprot (S)
  local T;
  if startswith(S,"https") then T="https"
                           else T="http"
  end
  return T;
end

-- parse destination
function sdest (S)
  local T = S;
  if endswith(T,";") then T = string.sub(T,1,string.len(T)-1) end
  if endswith(T,"/") then T = string.sub(T,1,string.len(T)-1) end
  return T
end
  
-- parse internal ip-address
function siip (S)
  local R = after(S,"://")
  if  isin(R,"/") then 
    R = before(R, "/") 
  end
  if  isin(R,":") then 
    R = before(R, ":") 
  end
  
  if GetIPType(R) == 1 then return R end
  if GetIPType(R) == 3 then 
    socket = require("socket")

    local T = socket.dns.toip(R)
    if (T == nil) then 
      return ""
    else
      return T
    end
  end
end

-- parse internal port
function siport (S)
  local P
    if startswith(S, "https") then 
      P = "443"
      S = string.sub(S,9)
    else 
      P = "80"
      S = string.sub(S,8)
    end

  local T = between(S, ":", "/")
  if T ~= "" then return T
    else return P
  end
end

local socket = require("socket")

-- Ports, die wir als "Host lebt wahrscheinlich" akzeptieren
local HOST_PROBE_PORTS = {80, 443, 22}

-- Versuch, über TCP festzustellen ob der Host überhaupt lebt.
-- Rückgabe: true wenn Host irgendeinen bekannten Port annimmt, sonst false.
local function ping_host(host)
  if not host then return false end

  local pending = {}
  local need_select = false

  -- 1) Für jeden Probe-Port non-blocking connect starten
  for _, p in ipairs(HOST_PROBE_PORTS) do
    local tcp = socket.tcp()
    tcp:settimeout(0)

    local ok, err = tcp:connect(host, p)

    if ok then
      -- Sofort verbunden -> Host ist definitiv erreichbar
      tcp:close()
      for _, s in ipairs(pending) do
        pcall(function() s:close() end)
      end
      return true
    else
      if err == "timeout" then
        table.insert(pending, tcp)
        need_select = true
      else
        tcp:close()
      end
    end
  end

  -- 2) Wenn keiner sofort "ok" war aber wir pending sockets haben:
  if need_select and #pending > 0 then
    local _, writable = socket.select(nil, pending, 0.05)
    if #writable > 0 then
      for _, s in ipairs(pending) do
        pcall(function() s:close() end)
      end
      return true
    end
  end

  -- 3) Aufräumen & false zurück
  for _, s in ipairs(pending) do
    pcall(function() s:close() end)
  end
  return false
end

-- Gesamt-Timeout für alle Dienst-Port-Checks (in Sekunden)
local GLOBAL_TIMEOUT = 0.3  -- 300 ms

function check_all_services()
  OK = "&#128994;"
  BAD = "&#128308;"
  HOSTUP = "&#128993;"
  socket = require("socket")
  if type(A) ~= "table" then
    error("Tabelle A wird benötigt und muss ein Array sein")
  end

  local write_list = {}
  local pending_by_sock = {}

  -- 1) Start non-blocking connects für alle Einträge
  for i, entry in ipairs(A) do
    local host = entry and entry.IIP
    local port = entry and entry.IPORT

    if not host or not port then
      if ping_host(host) then
        entry.STATUS = HOSTUP
      else
        entry.STATUS = BAD
      end
    else
      local tcp = socket.tcp()
      tcp:settimeout(0)

      local ok, err = tcp:connect(host, port)
      if ok then
        entry.STATUS = OK
        tcp:close()
      else
        if err == "timeout" then
          table.insert(write_list, tcp)
          pending_by_sock[tcp] = i
        else
          if ping_host(host) then
            entry.STATUS = HOSTUP
          else
            entry.STATUS = BAD
          end
          tcp:close()
        end
      end
    end
  end

  -- 2) Einmaliges Warten: welche Sockets werden schreibbar (Handshake fertig)?
  if #write_list > 0 then
    local _, writable = socket.select(nil, write_list, GLOBAL_TIMEOUT)
    local writable_set = {}
    for _, s in ipairs(writable) do
      writable_set[s] = true
    end

    -- 3) Alle pending sockets auswerten
    for _, sock in ipairs(write_list) do
      local idx = pending_by_sock[sock]
      if idx then
        local entry = A[idx]
        if writable_set[sock] then
          entry.STATUS = OK
        else
          if ping_host(entry.IIP) then
            entry.STATUS = HOSTUP
          else
            entry.STATUS = BAD
          end
        end
        sock:close()
        pending_by_sock[sock] = nil
      end
    end
  end

  -- 4) Unerwartete Sockets schließen & markieren
  for sock, idx in pairs(pending_by_sock) do
    if A[idx] then
      if ping_host(A[idx].IIP) then
        A[idx].STATUS = HOSTUP
      else
        A[idx].STATUS = BAD
      end
    end
    pcall(function() sock:close() end)
    pending_by_sock[sock] = nil
  end
end


function otable()
  local O = ""

  -- head
  O = O .. "<thead align=\"center\"><tr>\n"
  for E = 1, #TT do
    if ((TT[E] == "Secured") or (TT[E] == "Status") or (TT[E] == "Type") or (TT[E] == "Int. Proto.") or (TT[E] == "Int. IP") or (TT[E] == "Int. Port")) then
      O = O .. "<th align=\"center\">" .. T[E] .. "</th> "
    else
      O = O .. "<th align=\"left\">" .. T[E] .. "</th> "
    end
  end
  O = O .. "</tr>\n</thead>\n"
  

  -- body
  O = O .. "<tbody>\n"

  for CO = 1, #A do
    O = O .. "<tr>\n"
    for CE = 1, #T do
      local E = T[CE]
      local S = (A[CO][E])

      if S == "" then S = "-" end
      if E == "NAME" then
        O = O ..  "  <td><a href=\"" .. "https://" .. S .. "." .. A[CO]["DOMAIN"] .. "\">" .. S .. "</a>"
      elseif E == "STATUS" then
        O = O ..  "  <td align=\"center\">" .. S 
      elseif E == "SECURE" then
        O = O ..  "  <td align=\"center\">" .. S 
      elseif E == "DEST" then
        if A[CO]["TYP"] == "Proxy" then
          O = O .. "  <td><a href=\"" ..  A[CO]["IPROTO"] .. "://" .. A[CO]["IIP"] .. ":" ..  
              A[CO]["IPORT"] .. "/\">" .. A[CO]["IPROTO"] .. "://" ..A[CO]["IIP"] .. ":" .. A[CO]["IPORT"] .. "/ </a>"
        else
          O = O .. "  <td><a href=\"" ..  A[CO]["DEST"] .. "\">" .. A[CO]["DEST"] .. "</a>"
        end
      elseif E == "USERS" then
        O = O .. "  <td>" .. S
      elseif  E == "TYP" then
        O = O .. "  <td align=\"center\">" .. S
      elseif startswith(E,"I") then
        O = O .. "  <td align=\"center\">" .. S
      else 
        O = O .. "  <td>" .. S
      end
        O = O .. "</td>\n" 
    end
    O = O .. "</tr>\n\n"
  end
  O = O .. "</tbody>\n" 
  return O
end

function parse(line)
  --[[
  ["NAME"]    = "LOGOUT",
  ["DOMAIN"]  = DOMAIN,
  ["TYP"]     = "host",
  ["DEST"]    = "https://logout." .. DOMAIN,
  ["IPROT"]   = "",
  ["IIP"]     = "",
  ["IPORT"]   = "",
  ["SECURE"]  = "OneTimePassword",

# Example
#
# Frame start
# USE Domain_Init example.com LOGIN
#
#
#  1         2            3                        4         5                                                        6
# Use VHost_Alias       logoff                example.com  logout.example.com                              ''
# Use VHost_Proxy       gvm                   example.com  https://10.0.0.1:8006/                          'user alice'
# Use VHost_Proxy_OTP   gateway1             example.com  http://10.0.0.2/                                'user alice bob'
# Use VHost_Proxy_Basic camera                example.com  http://10.0.0.9:10090/                         'user alice bob'
# Use VHost_Proxy_OIDC  test1                 example.com  http://10.0.0.15:8080/                         'alice'
# USE VHost_Proxy_CCERT test                  example.com  http://127.0.0.1/                                ''
##
# Frame end
# USE Domain_Final example.com LOGIN

  --]]
  -- remove trash
  if  ( not ( startswith(string.lower(all_trim(line)), "use "))
    or ( startswith(string.lower(all_trim(line)), "use domain_") ) ) then return;
  end

  -- insert element
  table.insert(A,{
    ["NAME"]   = word(line,3);
    ["DOMAIN"] = word(line,4);
    ["TYP"]    = stype(word(line,2));
    ["DEST"]   = sdest(word(line,5)); 
    ["IPROT"]  = sprot(word(line,5)); 
    ["IIP"]    = siip(word(line,5));
    ["IPORT"]  = siport(word(line,5));
    ["SECURE"] = ssec(word(line,2));
    ["USERS"]  = finalword(line,7):gsub("'", ""):gsub("|", ", ");
  });

end


--
--
--  # Main Functions #
--
--

function input (FILE, DOMAIN)
  -- get all lines from a file, returns an empty 
  -- list/table if the file does not exist
  if not file_exists(FILE) then os.exit(); end
  local VORHER = #A
  for line in io.lines(FILE) do
    parse(string.lower(line));
  end

  -- Nur die Rahmeneinträg erzeugen, wenn die Konfiguration Einträge erzeugt hat
  if #A > VORHER then
    table.insert(A,{
         ["NAME"]    = "TOC",
         ["DOMAIN"]  = DOMAIN,
         ["TYP"]     = "WebHost",
         ["DEST"]    = "https://toc." .. DOMAIN,
         ["IPROT"]   = "https",
         ["IIP"]     = siip("https://toc.example.com"),
         ["IPORT"]   = "443",
         ["SECURE"]  = "OpenID Connect",
         ["USERS"]   = "- ALL -",
    });

    table.insert(A,{
         ["NAME"]    = "LOGOUT",
         ["DOMAIN"]  = DOMAIN,
         ["TYP"]     = "Redirect",
         ["DEST"]    = "https://logout." .. DOMAIN,
         ["IPROT"]   = "https",
         ["IIP"]     = siip("https://logout.example.com"),
         ["IPORT"]   = "443",
         ["SECURE"]  = "OpenID Connect",
         ["USERS"]   = "- ALL -",
    });
  end

end

function output(DOMAIN, TITLE)

  local STYLE =  "<style>\n" ..
                 "#XLTab {\n" ..
                 "  font-family: \"Trebuchet MS\", Arial, Helvetica, sans-serif;\n" ..
                 "  border-collapse: collapse;\n" ..
                 "  width: 100%;\n" ..
                 "}\n" ..
                 "#XLTab td, #XLTab th {\n" ..
                 "  border: 1px solid #ddd;\n" ..
                 "  padding: 8px;\n" ..
                 "}\n" ..
                 "#XLTab tr:nth-child(even){background-color: #f2f2f2;}\n" ..
                 "#XLTab tr:hover {background-color: #ddd;}\n" ..
                 "#XLTab th {\n" ..
                 "  padding-top: 12px;\n" ..
                 "  padding-bottom: 12px;\n" ..
                 "  background-color: #4CAF50;\n" ..
                 "  color: white;\n" ..
                 "}\n" ..
                 "</style>\n"

  local SCRIPT = "<script src=\"/tablefilter/tablefilter.js\"></script>\n\n" ..
                 "<script type=\"text/javascript\">\n" ..
                 "var tf = new TableFilter('XLTab', {\n" ..
                 "  base_path: '/tablefilter/',\n" ..
                 "  col_0: 'select', \n" ..
                 "  col_2: 'select', \n" ..
                 "  col_3: 'select', \n" ..
                 "  col_5: 'select', \n" ..
                 "  col_8: 'select', \n" ..
                 "  auto_filter: { \n" ..
                 "    delay: 300 \n" ..
                 "  }, \n" ..
                 "  extensions: [{ name: 'sort' }], \n" ..
                 "  case_sensitive: false, \n" ..
                 "  col_types: [\n" ..
                 "    'string',\n" ..
                 "    'string',\n" ..
                 "    'string',\n" ..
                 "    'string',\n" ..
                 "    'string',\n" ..
                 "    'string',\n" ..
                 "    'ipaddress',\n" ..
                 "    'Number',\n" ..
                 "    'string',\n" ..
                 "    'string',\n" ..
                 "  ],\n" ..
                 "});\n" ..
                 "tf.init();\n" ..
                 "</script>\n\n" ..
                 "<script type=\"text/javascript\">\n" ..
                 "window.onload = function() {\n" ..
                 "  document.getElementById(\"flt1_XLTab\").focus();\n" ..
                 "};\n" ..
                 "</script>\n\n"

  local TABLE = "<table id=\"XLTab\">\n" ..
                otable() ..
                "</table>"

  local PAGE = "<!DOCTYPE html>\n<html lang=de>\n" ..
               "<head>\n" ..
               "<title>" .. TITLE .. "</title>\n" ..
               "<link rel=\"icon\" type=\"image/x-icon\" href=\"https://login.".. DOMAIN .. "/favicon_toc.ico\">\n" ..
               "</head>\n\n" ..
               "<body>\n" .. STYLE .. "\n" ..
               "<h1 align=\"center\">" .. "<a href=\"/logout\">" .. TITLE .. " - " .. REMOTE_USER .. "</a> </h1>\n" .. 
               TABLE .. "\n" ..
               "\n" .. SCRIPT ..
               "</body>\n</html>\n"

  return PAGE
end

function handle(r)
  REMOTE_USER = r.user or REMOTE_USER
  -- Set MIME type to text/html:
  r.content_type = "text/html"

  -- return output
 r:puts( output(DOMAIN, TITLE ))
end

local i, t, popen = 0, {}, io.popen
local pfile = popen('ls -a /etc/apache2/sites-enabled/*.conf')
for filename in pfile:lines() do
  i = i + 1
  FILE = filename
  DOMAIN = (shortbetween(filename, "/", ".conf") )
  input(FILE, DOMAIN)
end
pfile:close()
check_all_services()


--DOMAIN      = "example.com";
--FILE        = "/etc/apache2/sites-enabled/example.com.conf";
--input(FILE, DOMAIN)

--DOMAIN      = "example.com";
--FILE        = "/etc/apache2/sites-enabled/example.com.conf";
--input(FILE, DOMAIN)

--DOMAIN      = "example.com";
--FILE        = "/etc/apache2/sites-enabled/example.com.conf";
--input(FILE, DOMAIN)

--DOMAIN      = "example.com";
--FILE        = "/etc/apache2/sites-enabled/example.com.conf";
--input(FILE, DOMAIN)


--  print( output(DOMAIN, TITLE ))
