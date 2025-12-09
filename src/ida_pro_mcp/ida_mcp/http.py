import html
import json
import os
import ida_netnode
from urllib.parse import urlparse, parse_qs
from typing import TypeVar, cast
from http.server import HTTPServer

from .sync import idaread, idawrite
from .rpc import McpRpcRegistry, McpHttpRequestHandler, MCP_SERVER, MCP_UNSAFE


T = TypeVar("T")


@idaread
def config_json_get(key: str, default: T) -> T:
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    json_blob: bytes | None = node.getblob(0, "C")
    if json_blob is None:
        return default
    try:
        return json.loads(json_blob)
    except Exception as e:
        print(
            f"[WARNING] Invalid JSON stored in netnode '{key}': '{json_blob}' from netnode: {e}"
        )
        return default


@idawrite
def config_json_set(key: str, value):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}", 0, True)
    json_blob = json.dumps(value).encode("utf-8")
    node.setblob(json_blob, 0, "C")


def get_auth_token() -> str | None:
    """Get authentication token from config or environment variable"""
    # Priority: 1. IDA config, 2. Environment variable
    token = config_json_get("auth_token", None)
    if token:
        return token
    return os.environ.get("IDA_MCP_AUTH_TOKEN")


def get_bind_host() -> str:
    """Get server bind host from config or environment variable"""
    # Priority: 1. Environment variable (for compatibility), 2. IDA config, 3. Default
    env_host = os.environ.get("IDA_MCP_HOST")
    if env_host:
        return env_host
    return config_json_get("bind_host", "127.0.0.1")


def handle_enabled_tools(registry: McpRpcRegistry, config_key: str):
    """Changed to registry to enable configured tools, returns original tools."""
    original_tools = registry.methods.copy()
    enabled_tools = config_json_get(
        config_key, {name: True for name in original_tools.keys()}
    )
    new_tools = [name for name in original_tools if name not in enabled_tools]

    removed_tools = [name for name in enabled_tools if name not in original_tools]
    if removed_tools:
        for name in removed_tools:
            enabled_tools.pop(name)

    if new_tools:
        enabled_tools.update({name: True for name in new_tools})
        config_json_set(config_key, enabled_tools)

    registry.methods = {
        name: func for name, func in original_tools.items() if enabled_tools.get(name)
    }
    return original_tools


DEFAULT_CORS_POLICY = "local"


def get_cors_policy(port: int) -> str:
    """Retrieve the current CORS policy from configuration."""
    match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
        case "unrestricted":
            return "*"
        case "local":
            return "127.0.0.1 localhost"
        case "direct":
            return f"http://127.0.0.1:{port} http://localhost:{port}"
        case _:
            return "*"


ORIGINAL_TOOLS = handle_enabled_tools(MCP_SERVER.tools, "enabled_tools")


def apply_auth_token():
    """Apply authentication token from config/env to MCP server"""
    token = get_auth_token()
    if token:
        MCP_SERVER.auth_token = token
        print(f"[MCP] ✅ Authentication enabled")
        print(f"[MCP] Token: {token}")
        print(f"[MCP] Use in clients: Authorization: Bearer {token}")
    else:
        print("[MCP] ⚠️  WARNING: No authentication token set!")
        print("[MCP] Anyone who can access this port can control IDA Pro.")
        print("[MCP] Set via: http://127.0.0.1:PORT/config.html or IDA_MCP_AUTH_TOKEN env var")


# Apply auth token on module load
apply_auth_token()


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.update_cors_policy()

    def update_cors_policy(self):
        match config_json_get("cors_policy", DEFAULT_CORS_POLICY):
            case "unrestricted":
                self.mcp_server.cors_allowed_origins = "*"
            case "local":
                self.mcp_server.cors_allowed_origins = self.mcp_server.cors_localhost
            case "direct":
                self.mcp_server.cors_allowed_origins = None

    def do_POST(self):
        """Handles POST requests."""
        if urlparse(self.path).path == "/config":
            if not self._check_origin():
                return
            self._handle_config_post()
        else:
            super().do_POST()

    def do_GET(self):
        """Handles GET requests."""
        if urlparse(self.path).path == "/config.html":
            if not self._check_host():
                return
            self._handle_config_get()
        else:
            super().do_GET()

    @property
    def server_port(self) -> int:
        return cast(HTTPServer, self.server).server_port

    def _check_origin(self) -> bool:
        """
        Prevents CSRF and DNS rebinding attacks by ensuring POST requests
        originate from pages served by this server, not external websites.
        """
        origin = self.headers.get("Origin")
        port = self.server_port
        if origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            self.send_error(403, "Invalid Origin")
            return False
        return True

    def _check_host(self) -> bool:
        """
        Prevents DNS rebinding attacks where an attacker's domain (e.g., evil.com)
        resolves to 127.0.0.1, allowing their page to read localhost resources.
        
        Config interface should only be accessible from localhost for security.
        """
        host = self.headers.get("Host")
        port = self.server_port
        # Allow localhost access only, regardless of bind address
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self.send_error(403, "Config interface only accessible from localhost")
            return False
        return True

    def _send_html(self, status: int, text: str):
        """
        Prevents clickjacking by blocking iframes (X-Frame-Options for older
        browsers, frame-ancestors for modern ones). Other CSP directives
        provide defense-in-depth against content injection attacks.
        """
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "; ".join(
                [
                    "frame-ancestors 'none'",
                    "script-src 'self' 'unsafe-inline'",
                    "style-src 'self' 'unsafe-inline'",
                    "default-src 'self'",
                    "form-action 'self'",
                ]
            ),
        )
        self.end_headers()
        self.wfile.write(body)

    def _handle_config_get(self):
        """Sends the configuration page with checkboxes."""
        cors_policy = config_json_get("cors_policy", DEFAULT_CORS_POLICY)
        auth_token = config_json_get("auth_token", "")
        bind_host = config_json_get("bind_host", "127.0.0.1")

        body = """<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDA Pro MCP Config</title>
  <style>
:root {
  --bg: #ffffff;
  --text: #1a1a1a;
  --border: #e0e0e0;
  --accent: #0066cc;
  --hover: #f5f5f5;
  --warning: #ff6b35;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1a1a1a;
    --text: #e0e0e0;
    --border: #333333;
    --accent: #4da6ff;
    --hover: #2a2a2a;
    --warning: #ff8c5a;
  }
}

* {
  box-sizing: border-box;
}

body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  max-width: 800px;
  margin: 2rem auto;
  padding: 1rem;
  line-height: 1.4;
}

h1 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}

h2 {
  font-size: 1.1rem;
  margin-top: 1.5rem;
  margin-bottom: 0.5rem;
}

label {
  display: block;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  cursor: pointer;
}

label:hover {
  background: var(--hover);
}

input[type="checkbox"],
input[type="radio"] {
  margin-right: 0.5rem;
  accent-color: var(--accent);
}

input[type="text"],
input[type="password"],
select {
  width: 100%;
  padding: 0.5rem;
  margin: 0.5rem 0;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg);
  color: var(--text);
  font-family: monospace;
}

select {
  cursor: pointer;
}

input[type="submit"],
button {
  margin-top: 1rem;
  padding: 0.6rem 1.5rem;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

input[type="submit"]:hover,
button:hover {
  opacity: 0.9;
}

.tooltip {
  border-bottom: 1px dotted var(--text);
}

.warning {
  background: var(--warning);
  color: white;
  padding: 0.75rem;
  border-radius: 4px;
  margin: 1rem 0;
}

.info {
  background: var(--hover);
  padding: 0.75rem;
  border-radius: 4px;
  margin: 1rem 0;
  border-left: 3px solid var(--accent);
}
  </style>
  <script defer>
  function setTools(mode) {
    document.querySelectorAll('input[data-tool]').forEach(cb => {
        if (mode === 'all') cb.checked = true;
        else if (mode === 'none') cb.checked = false;
        else if (mode === 'disable-unsafe' && cb.hasAttribute('data-unsafe')) cb.checked = false;
    });
  }
  function generateToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let token = '';
    for (let i = 0; i < 32; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const input = document.getElementById('auth_token');
    input.value = token;
    // Show token temporarily by changing input type
    input.type = 'text';
    input.select(); // Select token for easy copying
    
    // Show copy notification
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = '✅ Token Generated! (Copy it now)';
    btn.style.background = '#28a745';
    
    // Reset button after 5 seconds
    setTimeout(() => {
      btn.textContent = originalText;
      btn.style.background = '';
      input.type = 'password';
    }, 5000);
  }
  
  function toggleTokenVisibility() {
    const input = document.getElementById('auth_token');
    const btn = document.getElementById('toggle_token_btn');
    if (input.type === 'password') {
      input.type = 'text';
      btn.textContent = '🙈 Hide';
    } else {
      input.type = 'password';
      btn.textContent = '👁️ Show';
    }
  }
  </script>
</head>
<body>
<h1>IDA Pro MCP Config</h1>

<form method="post" action="/config">

<h2>🌐 Network Settings</h2>
<label for="bind_host">Server Bind Address:</label>
<select id="bind_host" name="bind_host">
  <option value="127.0.0.1" """
        body += 'selected' if bind_host == "127.0.0.1" else ''
        body += """>127.0.0.1 (Local only - Most secure)</option>
  <option value="0.0.0.0" """
        body += 'selected' if bind_host == "0.0.0.0" else ''
        body += """>0.0.0.0 (All interfaces - Cloud deployment)</option>
</select>
<div class="info">
  <strong>⚠️ Important:</strong>
  <ul style="margin: 0.5rem 0; padding-left: 1.5rem;">
    <li><strong>127.0.0.1</strong>: Server only accessible from this machine (default, most secure)</li>
    <li><strong>0.0.0.0</strong>: Server accessible from network (required for cloud deployment)</li>
  </ul>
  <strong>🔴 When using 0.0.0.0, you MUST set an authentication token!</strong>
</div>

<h2>🔐 Authentication</h2>
"""
        if bind_host != "127.0.0.1" and not auth_token:
            body += '<div class="warning">🔴 <strong>CRITICAL SECURITY WARNING:</strong> Server is accessible from network but NO authentication is set! Anyone can control IDA Pro!</div>'
        elif not auth_token:
            body += '<div class="warning">⚠️ <strong>Security Warning:</strong> No authentication token is set! Anyone who can access this port can control IDA Pro.</div>'
        else:
            body += f'<div class="info">✅ Authentication is enabled (token length: {len(auth_token)} chars)</div>'
        
        body += """<label for="auth_token">Authorization Token:</label>
<div style="display: flex; gap: 0.5rem;">
<input type="password" id="auth_token" name="auth_token" placeholder="Leave empty to disable authentication" """
        body += f'value="{html.escape(auth_token)}"' if auth_token else ''
        body += """ style="flex: 1;">
<button type="button" id="toggle_token_btn" onclick="toggleTokenVisibility()" style="width: auto; margin: 0.5rem 0;">👁️ Show</button>
</div>
<button type="button" onclick="generateToken()">🎲 Generate Random Token</button>"""
        if auth_token:
            body += f"""
<div class="info" style="font-family: monospace; word-break: break-all; background: #f0f0f0; color: #333;">
  <strong>Current Token:</strong><br>
  <code style="user-select: all;">{html.escape(auth_token)}</code>
</div>"""
        body += """
<div class="info">
  <strong>Usage:</strong> Clients must include this token in the <code>Authorization</code> header:
  <br><code>Authorization: Bearer YOUR_TOKEN_HERE</code>
  <br>Or set environment variable: <code>IDA_MCP_AUTH_TOKEN=YOUR_TOKEN_HERE</code>
</div>

<h2>API Access</h2>
"""
        cors_options = [
            (
                "unrestricted",
                "⛔ Unrestricted",
                "Any website can make requests to this server. A malicious site you visit could access or modify your IDA database.",
            ),
            (
                "local",
                "🏠 Local apps only",
                "Only web apps running on localhost can connect. Remote websites are blocked, but local development tools work.",
            ),
            (
                "direct",
                "🔒 Direct connections only",
                "Browser-based requests are blocked. Only direct clients like curl, MCP tools, or Claude Desktop can connect.",
            ),
        ]
        for value, label, tooltip in cors_options:
            checked = "checked" if cors_policy == value else ""
            body += f'<label><input type="radio" name="cors_policy" value="{html.escape(value)}" {checked}><span class="tooltip" title="{html.escape(tooltip)}">{html.escape(label)}</span></label>'
        body += "<br><input type='submit' value='Save'>"

        quick_select = """<p style="font-size: 0.9rem; margin: 0.5rem 0;">
  Select:
  <a href="#" onclick="setTools('all'); return false;">All</a> ·
  <a href="#" onclick="setTools('none'); return false;">None</a> ·
  <a href="#" onclick="setTools('disable-unsafe'); return false;">Disable unsafe</a>
</p>"""

        body += "<h2>Enabled Tools</h2>"
        body += quick_select
        for name, func in ORIGINAL_TOOLS.items():
            description = (
                (func.__doc__ or "No description").strip().splitlines()[0].strip()
            )
            unsafe_prefix = "⚠️ " if name in MCP_UNSAFE else ""
            checked = " checked" if name in self.mcp_server.tools.methods else ""
            unsafe_attr = " data-unsafe" if name in MCP_UNSAFE else ""
            body += f"<label><input type='checkbox' name='{html.escape(name)}' value='{html.escape(name)}'{checked}{unsafe_attr} data-tool>{unsafe_prefix}{html.escape(name)}: {html.escape(description)}</label>"
        body += quick_select
        body += "<br><input type='submit' value='Save'>"
        body += "</form></body></html>"
        self._send_html(200, body)

    def _handle_config_post(self):
        """Handles the configuration form submission."""
        # Validate Content-Type
        content_type = self.headers.get("content-type", "").split(";")[0].strip()
        if content_type != "application/x-www-form-urlencoded":
            self.send_error(400, f"Unsupported Content-Type: {content_type}")
            return

        # Parse the form data
        length = int(self.headers.get("content-length", "0"))
        postvars = parse_qs(self.rfile.read(length).decode("utf-8"))

        # Update bind host
        bind_host = postvars.get("bind_host", ["127.0.0.1"])[0]
        if bind_host not in ("127.0.0.1", "0.0.0.0"):
            bind_host = "127.0.0.1"
        old_bind_host = config_json_get("bind_host", "127.0.0.1")
        config_json_set("bind_host", bind_host)

        # Update authentication token
        auth_token = postvars.get("auth_token", [""])[0].strip()
        config_json_set("auth_token", auth_token if auth_token else None)
        apply_auth_token()

        # Update CORS policy
        cors_policy = postvars.get("cors_policy", [DEFAULT_CORS_POLICY])[0]
        config_json_set("cors_policy", cors_policy)
        self.update_cors_policy()

        # Update the server's tools
        enabled_tools = {name: name in postvars for name in ORIGINAL_TOOLS.keys()}
        self.mcp_server.tools.methods = {
            name: func
            for name, func in ORIGINAL_TOOLS.items()
            if enabled_tools.get(name)
        }
        config_json_set("enabled_tools", enabled_tools)

        # Show restart warning if bind host changed
        if bind_host != old_bind_host:
            warning_html = f"""<html>
<head>
  <meta charset="UTF-8">
  <title>Restart Required</title>
  <style>
    body {{
      font-family: system-ui;
      max-width: 600px;
      margin: 4rem auto;
      padding: 2rem;
      text-align: center;
    }}
    .warning {{
      background: #ff6b35;
      color: white;
      padding: 2rem;
      border-radius: 8px;
      font-size: 1.2rem;
    }}
    button {{
      margin-top: 1rem;
      padding: 0.8rem 2rem;
      font-size: 1rem;
      background: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }}
  </style>
</head>
<body>
  <div class="warning">
    <h2>⚠️ Server Restart Required</h2>
    <p>Bind address changed from <strong>{html.escape(old_bind_host)}</strong> to <strong>{html.escape(bind_host)}</strong></p>
    <p>Please stop and restart the MCP server (Ctrl+Alt+M twice) for changes to take effect.</p>
    <button onclick="window.location='/config.html'">Back to Config</button>
  </div>
</body>
</html>"""
            self._send_html(200, warning_html)
        else:
            # Redirect back to the config page
            self.send_response(302)
            self.send_header("Location", "/config.html")
            self.end_headers()
