# 🚀 IDA Pro MCP 云服务器部署指南

本文档介绍如何将 IDA Pro MCP 部署到云服务器，并从本地连接使用。

## 📋 目录

- [部署模式对比](#部署模式对比)
- [模式 1: 直接部署 IDA 插件](#模式-1-直接部署-ida-插件推荐)
- [模式 2: 无头模式 (idalib)](#模式-2-无头模式-idalib)
- [模式 3: 代理模式](#模式-3-代理模式)
- [安全配置](#安全配置)
- [常见问题](#常见问题)

---

## 🔍 部署模式对比

| 模式 | 适用场景 | 优点 | 缺点 | Web 配置 |
|------|---------|------|------|----------|
| **模式 1: IDA 插件直接部署** | 需要 IDA GUI 界面 | 完整功能，支持调试器 | 需要 X11 转发或远程桌面 | ✅ 支持 |
| **模式 2: 无头模式 (idalib)** | 纯分析任务 | 无需 GUI，资源占用低 | 不支持调试器 | ❌ 命令行 |
| **模式 3: 代理模式** | 本地 IDA + 远程访问 | 灵活，支持多客户端 | 需要两个进程 | ❌ 命令行 |

---

## 🎯 模式 1: 直接部署 IDA 插件（推荐）

### 架构图
```
云服务器 (IDA Pro + 插件)
    ↓ 监听 0.0.0.0:13337
    ↓ SSE/HTTP 接口
本地客户端 ← 通过公网/VPN 连接
```

### 步骤 1: 配置服务器监听地址和认证

**方法 A: 通过 Web 配置界面（最简单）**

1. 启动 IDA Pro 并加载 MCP 插件（Ctrl+Alt+M）
2. 在浏览器中打开配置页面：`http://127.0.0.1:13337/config.html`
3. 在"🌐 Network Settings"部分：
   - 选择 **"0.0.0.0 (All interfaces - Cloud deployment)"**
4. 在"🔐 Authentication"部分：
   - 点击"🎲 Generate Random Token"生成强密码
   - 或手动输入一个安全的 Token（建议 32+ 字符）
5. 点击 **Save** 保存配置
6. 重启 MCP 服务器（按 Ctrl+Alt+M 两次）

**方法 B: 通过环境变量**

```bash
# 在云服务器上设置环境变量（会覆盖 Web 配置）
export IDA_MCP_HOST="0.0.0.0"  # 监听所有网络接口
export IDA_MCP_PORT="13337"    # 可选，默认 13337
export IDA_MCP_AUTH_TOKEN="your-secure-token-here"  # 强烈建议设置

# 启动 IDA Pro
ida64 /path/to/binary.exe
```

**方法 C: 通过启动脚本**

创建 `start_ida_mcp.sh`:
```bash
#!/bin/bash
export IDA_MCP_HOST="0.0.0.0"
export IDA_MCP_AUTH_TOKEN="$(cat /secure/path/token.txt)"
exec ida64 "$@"
```

```bash
chmod +x start_ida_mcp.sh
./start_ida_mcp.sh /path/to/binary.exe
```

### 步骤 2: 在 IDA 中启动插件

1. 加载二进制文件后，按 `Ctrl+Alt+M`（macOS: `Ctrl+Option+M`）
2. 或者通过菜单：`Edit → Plugins → MCP`
3. 查看输出窗口确认监听地址：

```
[MCP] Plugin loaded
[MCP] WARNING: Server will listen on 0.0.0.0 (remotely accessible!)
[MCP] Authentication enabled (token length: 32 chars)
[MCP] Server started:
  Streamable HTTP: http://0.0.0.0:13337/mcp
  SSE: http://0.0.0.0:13337/sse
  Config: http://0.0.0.0:13337/config.html
```

### 步骤 3: 本地客户端连接

**测试连接：**
```bash
# 替换为你的服务器 IP 和 Token
curl -H "Authorization: Bearer your-token" \
     http://your-server-ip:13337/sse
```

**Python 客户端：**
```python
import requests

headers = {"Authorization": "Bearer your-token"}
response = requests.post(
    "http://your-server-ip:13337/mcp",
    headers=headers,
    json={
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    }
)
print(response.json())
```

---

## 🤖 模式 2: 无头模式 (idalib)

### 架构图
```
云服务器 (idalib-mcp)
    ↓ 无 GUI，自动分析
    ↓ 监听 0.0.0.0:8745
本地客户端 ← HTTP/SSE 连接
```

### 步骤 1: 安装 idalib

```bash
# 需要 IDA Pro 9.0+
pip install idalib
```

### 步骤 2: 启动无头服务器

```bash
uv run idalib-mcp \
    --host 0.0.0.0 \
    --port 8745 \
    --auth-token "your-secure-token" \
    /path/to/binary.exe
```

**后台运行（使用 systemd）：**

创建 `/etc/systemd/system/ida-mcp.service`:
```ini
[Unit]
Description=IDA Pro MCP Server
After=network.target

[Service]
Type=simple
User=ida-user
WorkingDirectory=/opt/ida-mcp
ExecStart=/usr/bin/uv run idalib-mcp \
    --host 0.0.0.0 \
    --port 8745 \
    --auth-token "your-token" \
    /data/binaries/target.exe
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable ida-mcp
sudo systemctl start ida-mcp
sudo systemctl status ida-mcp
```

### 步骤 3: 本地连接

```bash
curl -H "Authorization: Bearer your-token" \
     http://your-server-ip:8745/sse
```

---

## 🔄 模式 3: 代理模式

### 架构图
```
云服务器:
  - IDA Pro (127.0.0.1:13337)
  - server.py 代理 (0.0.0.0:8744)
      ↓ 转发请求
      ↓ 添加认证层
本地客户端 ← 连接代理
```

### 步骤 1: 启动 IDA Pro（本地监听）

```bash
# 不设置 IDA_MCP_HOST，默认 127.0.0.1
ida64 /path/to/binary.exe
# 在 IDA 中按 Ctrl+Alt+M 启动插件
```

### 步骤 2: 启动代理服务器

```bash
uv run ida-pro-mcp \
    --transport http://0.0.0.0:8744/sse \
    --ida-rpc http://127.0.0.1:13337 \
    --auth-token "your-secure-token"
```

**后台运行：**
```bash
nohup uv run ida-pro-mcp \
    --transport http://0.0.0.0:8744/sse \
    --auth-token "your-token" \
    > /var/log/ida-mcp.log 2>&1 &
```

### 步骤 3: 本地连接

```bash
curl -H "Authorization: Bearer your-token" \
     http://your-server-ip:8744/sse
```

---

## 🔒 安全配置

### 1. 防火墙配置

**Ubuntu/Debian (ufw):**
```bash
# 只允许特定 IP 访问
sudo ufw allow from YOUR_CLIENT_IP to any port 13337
sudo ufw deny 13337

# 或允许所有（需要强认证）
sudo ufw allow 13337
```

**CentOS/RHEL (firewalld):**
```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="YOUR_CLIENT_IP" port protocol="tcp" port="13337" accept'
sudo firewall-cmd --reload
```

### 2. 使用 nginx 反向代理 + TLS

**安装 nginx 和 Let's Encrypt:**
```bash
sudo apt install nginx certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

**配置 nginx (`/etc/nginx/sites-available/ida-mcp`):**
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # 基本认证（额外的安全层）
    auth_basic "IDA MCP Access";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:13337;
        proxy_http_version 1.1;
        
        # SSE 必需
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        
        # 转发真实 IP
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

**创建 HTTP 基本认证：**
```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd your-username
sudo systemctl reload nginx
```

**客户端访问：**
```bash
curl -u your-username:your-password \
     -H "Authorization: Bearer your-token" \
     https://your-domain.com/sse
```

### 3. SSH 隧道（最安全）

**在本地建立隧道：**
```bash
# 本地端口 8744 转发到服务器的 13337
ssh -L 8744:127.0.0.1:13337 user@your-server -N

# 在另一个终端连接本地端口
curl http://localhost:8744/sse
```

**永久隧道（使用 autossh）：**
```bash
sudo apt install autossh
autossh -M 0 -f -N -L 8744:127.0.0.1:13337 user@your-server
```

### 4. VPN 方案

**WireGuard 配置示例：**
```bash
# 服务器上
sudo apt install wireguard
wg genkey | tee privatekey | wg pubkey > publickey

# /etc/wireguard/wg0.conf
[Interface]
Address = 10.0.0.1/24
PrivateKey = <server-private-key>
ListenPort = 51820

[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
```

连接后通过 VPN IP 访问：
```bash
curl http://10.0.0.1:13337/sse
```

---

## 📊 性能优化

### 1. 资源限制

```bash
# 限制内存使用（systemd）
MemoryMax=4G
MemoryHigh=3G
```

### 2. 日志轮转

```bash
# /etc/logrotate.d/ida-mcp
/var/log/ida-mcp.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
```

### 3. 监控脚本

```bash
#!/bin/bash
# check_ida_mcp.sh
if ! curl -f -s -H "Authorization: Bearer $TOKEN" http://localhost:13337/mcp > /dev/null; then
    echo "IDA MCP is down, restarting..."
    systemctl restart ida-mcp
fi
```

添加到 crontab：
```bash
*/5 * * * * /path/to/check_ida_mcp.sh
```

---

## ❓ 常见问题

### Q1: 为什么无法从外部访问？

**检查清单：**
1. ✅ 确认设置了 `IDA_MCP_HOST="0.0.0.0"`
2. ✅ 检查防火墙规则 (`ufw status` / `firewall-cmd --list-all`)
3. ✅ 检查云服务商安全组设置（AWS/阿里云/腾讯云等）
4. ✅ 确认端口未被其他程序占用 (`netstat -tuln | grep 13337`)

### Q2: 如何查看当前监听的地址？

```bash
# 服务器上执行
netstat -tuln | grep 13337
# 或
ss -tuln | grep 13337

# 应该看到：
# tcp  0  0  0.0.0.0:13337  0.0.0.0:*  LISTEN
```

### Q3: 性能问题怎么办？

1. **网络延迟高**：使用就近的云服务器或 CDN
2. **IDA 响应慢**：增加服务器内存/CPU
3. **传输数据大**：启用 gzip 压缩（nginx）

### Q4: 如何支持多用户访问？

**方案 A: 每个用户一个 IDA 实例**
```bash
# 用户 1
export IDA_MCP_PORT=13337
ida64 binary1.exe &

# 用户 2
export IDA_MCP_PORT=13338
ida64 binary2.exe &
```

**方案 B: 使用 nginx 路由**
```nginx
location /user1/ {
    proxy_pass http://127.0.0.1:13337/;
}
location /user2/ {
    proxy_pass http://127.0.0.1:13338/;
}
```

### Q5: 可以使用 Docker 吗？

可以，但需要 X11 支持：

```dockerfile
FROM ubuntu:22.04

# 安装依赖
RUN apt-get update && apt-get install -y \
    python3 python3-pip xvfb

# 安装 IDA Pro（需要许可证）
COPY ida-pro.tar.gz /tmp/
RUN tar -xzf /tmp/ida-pro.tar.gz -C /opt/

# 安装 ida-pro-mcp
RUN pip3 install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip
RUN ida-pro-mcp --install

ENV IDA_MCP_HOST=0.0.0.0
ENV DISPLAY=:99

CMD xvfb-run -a /opt/ida/ida64 -A "$BINARY"
```

---

## 📚 相关文档

- [AUTHENTICATION.md](AUTHENTICATION.md) - 认证配置详解
- [README.md](README.md) - 项目主文档
- [test_auth.py](test_auth.py) - 认证测试脚本

---

## 🆘 遇到问题？

1. 查看日志：
   ```bash
   # IDA 输出窗口
   # systemd 日志
   sudo journalctl -u ida-mcp -f
   ```

2. 测试连接：
   ```bash
   # 本地测试
   curl -v http://localhost:13337/mcp
   
   # 远程测试
   curl -v http://your-server:13337/mcp
   ```

3. 提交 Issue: https://github.com/mrexodia/ida-pro-mcp/issues
