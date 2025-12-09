# 🎛️ IDA Pro MCP Web 配置界面使用指南

本文档介绍如何通过 Web 配置界面设置 IDA Pro MCP 服务器。

## 📍 访问配置界面

1. 在 IDA Pro 中加载任意二进制文件
2. 按 `Ctrl+Alt+M` 启动 MCP 服务器（macOS 上是 `Ctrl+Option+M`）
3. IDA 控制台会显示配置页面地址：
   ```
   [MCP] Server started on 127.0.0.1:13337
     Config: http://127.0.0.1:13337/config.html
   ```
4. 在浏览器中打开该地址

> **注意**: 配置页面只能从运行 IDA 的机器本地访问（安全限制）。如果在远程服务器上，需要通过 SSH 隧道或远程桌面访问。

---

## 🌐 Network Settings (网络设置)

### Server Bind Address（服务器绑定地址）

选择服务器监听的网络接口：

| 选项 | 说明 | 使用场景 | 安全性 |
|------|------|----------|--------|
| **127.0.0.1 (Local only)** | 仅本机可访问 | 本地开发、桌面使用 | 🟢 最安全 |
| **0.0.0.0 (All interfaces)** | 允许网络访问 | 云服务器部署、远程访问 | 🔴 需要认证 |

**重要提示**：
- 选择 `0.0.0.0` 时，服务器可以从网络上的任何机器访问
- **必须设置 Authentication Token** 才能安全使用 `0.0.0.0`
- 修改绑定地址后需要**重启 MCP 服务器**（按 Ctrl+Alt+M 两次）

---

## 🔐 Authentication (认证设置)

### Authorization Token（授权令牌）

设置一个强密码来保护 MCP 服务器：

**设置方法：**

1. **自动生成（推荐）**：点击 "🎲 Generate Random Token" 按钮
   - 自动生成 32 字符的安全随机密码
   - 示例：`K7xQm9pW_hN4vR2bL8cT5fY1gZ3jD6sA`

2. **手动输入**：在输入框中输入自定义密码
   - 建议至少 32 个字符
   - 使用字母、数字和特殊字符混合

**安全提示：**
- 🔴 **使用 0.0.0.0 时必须设置 Token**，否则任何人都可以控制 IDA
- 🟡 即使使用 127.0.0.1 也建议设置 Token
- 设置后立即生效，无需重启服务器

### 客户端使用 Token

**方法 1: HTTP Header**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" http://server:13337/sse
```

**方法 2: Environment Variable**
```bash
export IDA_MCP_AUTH_TOKEN="YOUR_TOKEN_HERE"
# 客户端会自动读取此环境变量
```

**方法 3: MCP 客户端配置**
```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "ida-pro-mcp",
      "args": ["--transport", "http://server:13337/sse"],
      "env": {
        "IDA_MCP_AUTH_TOKEN": "YOUR_TOKEN_HERE"
      }
    }
  }
}
```

---

## 🔌 API Access (API 访问控制)

控制浏览器中的跨域请求（CORS）策略：

### ⛔ Unrestricted (无限制)

- **说明**：允许任何网站通过浏览器向 MCP 服务器发送请求
- **风险**：你访问的恶意网站可能访问或修改你的 IDA 数据库
- **适用**：完全信任的内部网络环境

### 🏠 Local apps only (仅本地应用)

- **说明**：只允许 localhost 上运行的 Web 应用连接
- **优点**：阻止远程网站，但允许本地开发工具
- **推荐**：本地开发环境的默认选择

### 🔒 Direct connections only (仅直接连接)

- **说明**：完全阻止浏览器请求，只允许直接客户端（如 curl、MCP 工具）
- **优点**：最安全的 CORS 策略
- **推荐**：生产环境或云部署

---

## 🛠️ Enabled Tools (工具启用管理)

选择哪些 MCP 工具对客户端可用：

### 工具类型

- **普通工具**：常规分析工具（如 `ida_get_functions`、`ida_decompile`）
- **⚠️ 不安全工具**：可能修改数据库的工具（如 `ida_set_name`、`ida_make_comment`）

### 快速选择

- **Select: All** - 启用所有工具
- **Select: None** - 禁用所有工具
- **Select: Disable unsafe** - 只禁用标记为不安全的工具

**使用建议：**
- 只读分析：禁用所有 ⚠️ 不安全工具
- 完整功能：启用所有工具（默认）
- 自定义：根据需要勾选特定工具

---

## 📋 完整配置示例

### 示例 1: 本地开发（默认）

```
Network Settings:
  ✓ 127.0.0.1 (Local only)

Authentication:
  Token: (留空或设置可选密码)

API Access:
  ✓ Local apps only

Enabled Tools:
  ✓ All tools enabled
```

### 示例 2: 云服务器部署（推荐）

```
Network Settings:
  ✓ 0.0.0.0 (All interfaces)

Authentication:
  Token: K7xQm9pW_hN4vR2bL8cT5fY1gZ3jD6sA (自动生成)

API Access:
  ✓ Direct connections only

Enabled Tools:
  ✓ All tools enabled
```

### 示例 3: 只读分析服务器

```
Network Settings:
  ✓ 0.0.0.0 (All interfaces)

Authentication:
  Token: (必须设置)

API Access:
  ✓ Direct connections only

Enabled Tools:
  ✗ Disable all unsafe tools
  ✓ Only enable read-only tools
```

---

## 🔄 配置优先级

配置可以通过多种方式设置，优先级如下：

### Bind Host (绑定地址)
1. **环境变量 `IDA_MCP_HOST`**（最高优先级）
2. Web 配置界面
3. 默认值 `127.0.0.1`

### Auth Token (认证令牌)
1. IDA 数据库配置（Web 界面保存的值）
2. **环境变量 `IDA_MCP_AUTH_TOKEN`**
3. 无认证（不推荐）

### 示例：混合使用

```bash
# 环境变量会覆盖 Web 配置
export IDA_MCP_HOST="0.0.0.0"  # 强制使用 0.0.0.0

# 启动 IDA，Web 配置中的 bind_host 设置将被忽略
ida64 binary.exe
```

---

## 🔧 故障排除

### 配置页面无法访问

**问题**：浏览器显示"连接被拒绝"

**解决**：
1. 确认 MCP 服务器已启动（IDA 控制台应显示 "Server started"）
2. 检查端口是否正确（默认 13337）
3. 确认使用 `http://` 而不是 `https://`
4. 检查防火墙是否阻止连接

### 修改 Bind Host 后无法连接

**问题**：改为 `0.0.0.0` 后本地无法访问配置页面

**原因**：配置页面有安全检查，只接受 `Host: 127.0.0.1` 或 `localhost`

**解决**：
```bash
# 使用 SSH 隧道访问远程服务器的配置页面
ssh -L 13337:localhost:13337 user@remote-server

# 然后在本地浏览器访问
# http://localhost:13337/config.html
```

### Token 认证失败

**问题**：设置 Token 后客户端返回 401/403 错误

**检查**：
1. Header 格式是否正确：`Authorization: Bearer TOKEN`
2. Token 是否有前后空格
3. 环境变量是否正确设置

**测试命令**：
```bash
# 测试认证是否工作
curl -H "Authorization: Bearer YOUR_TOKEN" http://server:13337/sse

# 应返回：200 OK + session_id
```

---

## 🎯 最佳实践

### ✅ 推荐做法

1. **云部署必须设置 Token**
   ```
   Bind Host: 0.0.0.0
   Auth Token: (强随机密码)
   CORS: Direct connections only
   ```

2. **本地开发可选 Token**
   ```
   Bind Host: 127.0.0.1
   Auth Token: (可选)
   CORS: Local apps only
   ```

3. **定期更换 Token**
   - 每 30-90 天更换一次
   - 怀疑泄露时立即更换

4. **使用防火墙限制访问**
   ```bash
   # 只允许特定 IP 访问
   ufw allow from YOUR_IP to any port 13337
   ```

### ❌ 避免的做法

1. **不要**在公网环境下使用 `0.0.0.0` 而不设置 Token
2. **不要**使用弱密码（如 `123456`、`password`）
3. **不要**在公共代码仓库中提交 Token
4. **不要**对所有用户使用相同的 Token

---

## 📚 相关文档

- [AUTHENTICATION.md](AUTHENTICATION.md) - 认证机制详细说明
- [DEPLOYMENT.md](DEPLOYMENT.md) - 云服务器部署指南
- [README.md](README.md) - 项目总体说明

---

## 💡 提示

- **配置实时生效**：除了 Bind Host，其他配置保存后立即生效
- **数据持久化**：配置保存在 IDA 数据库的 netnode 中，随 `.idb` 文件一起
- **多数据库隔离**：每个 IDA 数据库可以有独立的配置
- **安全第一**：云部署时强烈建议结合 SSH 隧道使用
