# 🔐 IDA Pro MCP 认证配置指南

本文档介绍如何为远程部署的 IDA Pro MCP 服务器配置认证机制。

## 📋 目录

- [为什么需要认证](#为什么需要认证)
- [配置方式](#配置方式)
- [客户端使用](#客户端使用)
- [安全建议](#安全建议)

---

## 🎯 为什么需要认证

当你将 IDA Pro 部署在云服务器上时，**任何能访问该端口的人都可以控制 IDA Pro**，包括：
- 执行任意代码
- 读取/修改 IDB 数据库
- 访问调试器功能

**强烈建议**为远程部署启用认证！

---

## ⚙️ 配置方式

### 前提：配置监听地址（云服务器部署必须）

如果你要在云服务器上部署 IDA Pro，**必须先让 IDA 插件监听外部网络**：

```bash
# 在启动 IDA Pro 之前设置环境变量
export IDA_MCP_HOST="0.0.0.0"  # 监听所有网络接口
export IDA_MCP_PORT="13337"    # 可选，默认 13337

# 然后启动 IDA Pro
ida64 /path/to/binary.exe
```

⚠️ **重要**：默认情况下 IDA 插件只监听 `127.0.0.1`（仅本地访问），云服务器部署必须改为 `0.0.0.0`。

详细部署指南请参考 [DEPLOYMENT.md](DEPLOYMENT.md)。

---

### 方法 1: 通过 Web 配置界面（推荐）

1. 在 IDA Pro 中启动 MCP 服务器 (`Ctrl+Alt+M` 或 `Ctrl+Option+M`)
2. 访问配置页面：`http://<服务器IP>:<端口>/config.html`
3. 在 **🔐 Authentication** 部分：
   - 手动输入 Token，或点击 **🎲 Generate Random Token** 生成随机 Token
   - 点击 **Save** 保存

**示例：**
```
http://127.0.0.1:13337/config.html
```

### 方法 2: 通过环境变量

在启动 IDA Pro 之前设置环境变量：

```bash
# Linux/macOS
export IDA_MCP_AUTH_TOKEN="your-secret-token-here"
ida64

# Windows (PowerShell)
$env:IDA_MCP_AUTH_TOKEN="your-secret-token-here"
ida64.exe
```

### 方法 3: 通过命令行参数（仅 SSE/HTTP 模式）

```bash
# server.py (代理模式)
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse --auth-token "your-secret-token"

# idalib-mcp (无头模式)
uv run idalib-mcp --host 0.0.0.0 --port 8745 --auth-token "your-secret-token" /path/to/binary
```

---

## 📡 客户端使用

配置认证后，客户端必须在 HTTP 请求头中包含 `Authorization` 字段。

### 方式 1: Bearer Token（推荐）

```bash
curl -H "Authorization: Bearer your-secret-token" \
     http://your-server:13337/sse
```

### 方式 2: 直接传递 Token

```bash
curl -H "Authorization: your-secret-token" \
     http://your-server:13337/sse
```

### Python 示例

```python
import requests

headers = {
    "Authorization": "Bearer your-secret-token"
}

# 建立 SSE 连接
response = requests.get(
    "http://your-server:13337/sse",
    headers=headers,
    stream=True
)

for line in response.iter_lines():
    if line:
        print(line.decode('utf-8'))
```

### JavaScript 示例

```javascript
// EventSource 不支持自定义 Header，需要使用 fetch + SSE 库
// 或者通过代理服务器添加 Header

const headers = {
  "Authorization": "Bearer your-secret-token"
};

fetch("http://your-server:13337/sse", {
  method: "GET",
  headers: headers
})
.then(response => {
  const reader = response.body.getReader();
  // 处理 SSE 流
});
```

### MCP 客户端配置

对于 Claude Desktop / Cline / Cursor 等 MCP 客户端，需要在配置中添加 Header：

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "type": "http",
      "url": "http://your-server:13337/mcp",
      "headers": {
        "Authorization": "Bearer your-secret-token"
      }
    }
  }
}
```

**注意**: 大部分 MCP 客户端目前不支持为 HTTP 传输添加自定义 Header，建议使用以下替代方案：
1. 通过 SSH 隧道转发端口（推荐）
2. 使用反向代理（如 nginx）添加认证层
3. 使用 VPN 限制网络访问

---

## 🔒 安全建议

### 1. 生成强密码

```bash
# 生成 32 字节随机 Token（Linux/macOS）
openssl rand -base64 32

# 或使用 Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 2. 使用 HTTPS/TLS

在生产环境中，**强烈建议**使用反向代理（如 nginx）添加 TLS 加密：

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:13337;
        proxy_set_header Authorization "Bearer your-secret-token";
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 3. 防火墙限制

只允许特定 IP 访问：

```bash
# iptables (Linux)
iptables -A INPUT -p tcp --dport 13337 -s <客户端IP> -j ACCEPT
iptables -A INPUT -p tcp --dport 13337 -j DROP

# ufw (Ubuntu)
ufw allow from <客户端IP> to any port 13337
ufw deny 13337
```

### 4. SSH 隧道（最安全）

通过 SSH 隧道转发端口，无需暴露到公网：

```bash
# 在客户端执行
ssh -L 8744:127.0.0.1:13337 user@remote-server

# 然后客户端连接 localhost:8744 即可
```

### 5. 定期轮换 Token

建议每 30-90 天更换一次认证 Token。

---

## 🧪 测试认证

### 测试认证是否生效

```bash
# 无 Token - 应返回 401 Unauthorized
curl http://your-server:13337/sse

# 错误 Token - 应返回 403 Forbidden
curl -H "Authorization: Bearer wrong-token" http://your-server:13337/sse

# 正确 Token - 应成功建立连接
curl -H "Authorization: Bearer your-secret-token" http://your-server:13337/sse
```

### 日志查看

IDA Pro 输出窗口会显示认证状态：

```
[MCP] Authentication enabled (token length: 32 chars)
[MCP] Server started:
  Streamable HTTP: http://0.0.0.0:13337/mcp
  SSE: http://0.0.0.0:13337/sse
  Config: http://0.0.0.0:13337/config.html
```

---

## ❓ 常见问题

### Q: 忘记了设置的 Token 怎么办？

A: 通过 Web 配置界面重新生成或设置新 Token：`http://<IP>:<端口>/config.html`

### Q: 如何查看当前是否启用了认证？

A: 访问配置页面或查看 IDA Pro 输出窗口的启动日志。

### Q: 可以同时使用多个 Token 吗？

A: 当前版本仅支持单个 Token。如需多用户访问，建议使用反向代理实现更复杂的认证。

### Q: Token 存储在哪里？

A: Token 存储在 IDA Pro 的 netnode 中（随 `.idb` 文件保存）和环境变量中。

### Q: stdio 模式需要认证吗？

A: 不需要。stdio 模式通过进程管道通信，仅限本地访问，无需认证。

---

## 📚 相关文档

- [README.md](README.md) - 项目主文档
- [CLAUDE.md](CLAUDE.md) - 开发指南
- [MCP 协议规范](https://modelcontextprotocol.io/)

---

## 🆘 遇到问题？

1. 检查 IDA Pro 输出窗口的日志
2. 使用 `curl -v` 查看详细的 HTTP 响应
3. 提交 Issue: https://github.com/mrexodia/ida-pro-mcp/issues
