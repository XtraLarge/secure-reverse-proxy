--
-- oidc-no-access.lua
-- Served when an OIDC-authenticated user lacks the required claim/group.
-- Shows who is currently logged in and offers a "switch account" button
-- that logs out via mod_auth_openidc and triggers a fresh login.
--

local function h(s)
  return tostring(s or ""):gsub("&","&amp;"):gsub("<","&lt;"):gsub(">","&gt;"):gsub('"','&quot;')
end

function handle(r)
  -- r.user is the OIDC-authenticated username set by mod_auth_openidc.
  -- In an ErrorDocument subrequest Apache exposes it via REDIRECT_REMOTE_USER.
  local user = r.user
  if not user or user == "" then
    user = r.subprocess_env["REDIRECT_REMOTE_USER"] or ""
  end

  -- Build the logout URL: mod_auth_openidc clears the session and redirects
  -- to the given URI, which immediately triggers a fresh OIDC login.
  local redirect_path = os.getenv("OIDC_REDIRECT_PATH") or "/protected"
  local host = r.hostname
  local logout_target = "https://" .. host .. "/"
  local logout_url    = "https://" .. host .. redirect_path
                        .. "?logout=" .. logout_target

  r.content_type = "text/html; charset=utf-8"

  r:puts('<!DOCTYPE html><html lang=de><head>')
  r:puts('<meta charset=UTF-8>')
  r:puts('<meta name=viewport content="width=device-width,initial-scale=1">')
  r:puts('<title>Kein Zugriff</title>')
  r:puts('<style>')
  r:puts('*{box-sizing:border-box;margin:0;padding:0}')
  r:puts('body{font-family:Arial,sans-serif;background:#0d0d1a;color:#ddd;')
  r:puts('     display:flex;align-items:center;justify-content:center;min-height:100vh}')
  r:puts('.card{background:#0a0a22;border:1px solid #2a2a4e;border-radius:6px;')
  r:puts('      padding:2em 2.5em;max-width:400px;width:92%;text-align:center}')
  r:puts('h1{color:#ff9999;font-size:1.1em;margin-bottom:.9em}')
  r:puts('p{color:#aaa;font-size:.9em;line-height:1.5;margin:.35em 0}')
  r:puts('.u{color:#7ecfff;font-weight:bold}')
  r:puts('.dim{font-size:.78em;color:#555;margin-top:.9em}')
  r:puts('a.btn{display:inline-block;margin-top:1.4em;padding:9px 22px;')
  r:puts('      background:#0f3460;color:#7ecfff;border:1px solid #2a5080;')
  r:puts('      border-radius:4px;text-decoration:none;font-size:.9em}')
  r:puts('a.btn:hover{background:#1a4a7a;color:#00d4ff}')
  r:puts('</style></head><body><div class="card">')
  r:puts('<h1>&#128274;&nbsp;Kein Zugriff</h1>')

  if user ~= "" then
    r:puts('<p>Angemeldet als <span class="u">' .. h(user) .. '</span>,<br>')
    r:puts('aber ohne Berechtigung f&uuml;r diese Seite.</p>')
  else
    r:puts('<p>Du hast keine Berechtigung f&uuml;r diese Seite.</p>')
  end

  r:puts('<p class=dim>Melde dich ab und melde dich mit dem richtigen Account an.</p>')
  r:puts('<a class=btn href="' .. h(logout_url) .. '">Anderen Account verwenden</a>')
  r:puts('</div></body></html>')

  return apache2.OK
end
