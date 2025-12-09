#!/bin/bash
# IDA Pro MCP 云服务器快速部署脚本
# 使用方法: ./cloud_deploy.sh

set -e

echo "=================================="
echo "IDA Pro MCP 云服务器部署助手"
echo "=================================="
echo ""

# 检查是否在云服务器上
if [[ -n "$SSH_CONNECTION" ]] || [[ -n "$SSH_CLIENT" ]]; then
    echo "✅ 检测到 SSH 连接，看起来是云服务器环境"
else
    echo "⚠️  警告: 未检测到 SSH 连接，可能不是云服务器"
    read -p "是否继续? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""

# 生成安全 Token
echo "📝 步骤 1: 生成认证 Token"
if command -v openssl &> /dev/null; then
    TOKEN=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-32)
elif command -v python3 &> /dev/null; then
    TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32)[:32])")
else
    echo "❌ 错误: 需要 openssl 或 python3 来生成 Token"
    exit 1
fi

echo "✅ 已生成安全 Token: ${TOKEN:0:8}...${TOKEN: -4}"
echo ""

# 配置环境变量
echo "📝 步骤 2: 配置环境变量"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="${SCRIPT_DIR}/../.ida_mcp_env"

cat > "$CONFIG_FILE" <<EOF
# IDA Pro MCP 云服务器配置
# 使用方法: source .ida_mcp_env

export IDA_MCP_HOST="0.0.0.0"
export IDA_MCP_PORT="13337"
export IDA_MCP_AUTH_TOKEN="$TOKEN"

# 可选配置
# export IDA_PATH="/opt/ida/ida64"
EOF

echo "✅ 配置已写入: $CONFIG_FILE"
echo ""

# 添加到 .bashrc
echo "📝 步骤 3: 自动加载配置"
if ! grep -q ".ida_mcp_env" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# IDA Pro MCP 配置" >> ~/.bashrc
    echo "if [ -f \"$CONFIG_FILE\" ]; then" >> ~/.bashrc
    echo "    source \"$CONFIG_FILE\"" >> ~/.bashrc
    echo "fi" >> ~/.bashrc
    echo "✅ 已添加到 ~/.bashrc"
else
    echo "⚠️  配置已存在于 ~/.bashrc"
fi
echo ""

# 检查防火墙
echo "📝 步骤 4: 检查防火墙配置"
if command -v ufw &> /dev/null && sudo ufw status | grep -q "Status: active"; then
    echo "检测到 ufw 防火墙"
    echo "当前规则:"
    sudo ufw status | grep 13337 || echo "  未配置 13337 端口"
    echo ""
    read -p "是否打开 13337 端口? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo ufw allow 13337/tcp
        echo "✅ 已打开 13337 端口"
    fi
elif command -v firewall-cmd &> /dev/null && sudo firewall-cmd --state &> /dev/null; then
    echo "检测到 firewalld 防火墙"
    sudo firewall-cmd --list-ports | grep 13337 || echo "  未配置 13337 端口"
    echo ""
    read -p "是否打开 13337 端口? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo firewall-cmd --permanent --add-port=13337/tcp
        sudo firewall-cmd --reload
        echo "✅ 已打开 13337 端口"
    fi
else
    echo "⚠️  未检测到 ufw 或 firewalld，请手动配置防火墙"
fi
echo ""

# 创建启动脚本
echo "📝 步骤 5: 创建启动脚本"
START_SCRIPT="${SCRIPT_DIR}/start_ida_mcp.sh"
cat > "$START_SCRIPT" <<'EOF'
#!/bin/bash
# IDA Pro MCP 启动脚本

# 加载配置
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ -f "${SCRIPT_DIR}/../.ida_mcp_env" ]; then
    source "${SCRIPT_DIR}/../.ida_mcp_env"
fi

# 检查配置
if [ -z "$IDA_MCP_AUTH_TOKEN" ]; then
    echo "❌ 错误: 未设置 IDA_MCP_AUTH_TOKEN"
    echo "请运行: source ${SCRIPT_DIR}/../.ida_mcp_env"
    exit 1
fi

# 查找 IDA 可执行文件
if [ -n "$IDA_PATH" ] && [ -x "$IDA_PATH" ]; then
    IDA_BIN="$IDA_PATH"
elif command -v ida64 &> /dev/null; then
    IDA_BIN=$(command -v ida64)
elif [ -x "/opt/ida/ida64" ]; then
    IDA_BIN="/opt/ida/ida64"
elif [ -x "$HOME/ida/ida64" ]; then
    IDA_BIN="$HOME/ida/ida64"
else
    echo "❌ 错误: 找不到 IDA Pro"
    echo "请设置环境变量: export IDA_PATH=/path/to/ida64"
    exit 1
fi

echo "=================================="
echo "启动 IDA Pro MCP Server"
echo "=================================="
echo "IDA: $IDA_BIN"
echo "Host: $IDA_MCP_HOST:$IDA_MCP_PORT"
echo "Auth: ${IDA_MCP_AUTH_TOKEN:0:8}...${IDA_MCP_AUTH_TOKEN: -4}"
echo "=================================="
echo ""

if [ -z "$1" ]; then
    echo "使用方法: $0 <binary_path>"
    echo "示例: $0 /path/to/binary.exe"
    exit 1
fi

echo "加载二进制: $1"
echo ""
echo "⚠️  启动后请在 IDA 中按 Ctrl+Alt+M (macOS: Ctrl+Option+M) 启动 MCP 服务器"
echo ""

# 启动 IDA
exec "$IDA_BIN" "$@"
EOF

chmod +x "$START_SCRIPT"
echo "✅ 启动脚本已创建: $START_SCRIPT"
echo ""

# 创建测试脚本
echo "📝 步骤 6: 创建测试脚本"
TEST_SCRIPT="${SCRIPT_DIR}/test_connection.sh"
cat > "$TEST_SCRIPT" <<'EOF'
#!/bin/bash
# 测试 IDA Pro MCP 连接

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ -f "${SCRIPT_DIR}/../.ida_mcp_env" ]; then
    source "${SCRIPT_DIR}/../.ida_mcp_env"
fi

HOST="${IDA_MCP_HOST:-127.0.0.1}"
PORT="${IDA_MCP_PORT:-13337}"
TOKEN="${IDA_MCP_AUTH_TOKEN}"

echo "=================================="
echo "测试 IDA Pro MCP 连接"
echo "=================================="
echo "服务器: $HOST:$PORT"
echo "Token: ${TOKEN:0:8}...${TOKEN: -4}"
echo "=================================="
echo ""

# 测试 1: 无认证
echo "测试 1: 无认证请求 (应该失败)"
if curl -s -o /dev/null -w "%{http_code}" "http://$HOST:$PORT/sse" | grep -q "401"; then
    echo "✅ 正确拒绝无认证请求"
else
    echo "⚠️  未启用认证或服务器未运行"
fi
echo ""

# 测试 2: 正确认证
echo "测试 2: 带认证请求"
if [ -z "$TOKEN" ]; then
    echo "⚠️  未设置 IDA_MCP_AUTH_TOKEN"
else
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "http://$HOST:$PORT/sse")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "✅ 认证成功，服务器正常运行"
    else
        echo "❌ 认证失败，HTTP 状态码: $HTTP_CODE"
    fi
fi
echo ""

# 测试 3: 工具列表
echo "测试 3: 获取工具列表"
if [ -n "$TOKEN" ]; then
    curl -s -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' \
         "http://$HOST:$PORT/mcp" | python3 -m json.tool 2>/dev/null || echo "⚠️  请求失败"
else
    echo "⚠️  未设置 Token"
fi
echo ""

echo "=================================="
echo "测试完成"
echo "=================================="
EOF

chmod +x "$TEST_SCRIPT"
echo "✅ 测试脚本已创建: $TEST_SCRIPT"
echo ""

# 显示后续步骤
echo "=================================="
echo "✅ 部署配置完成！"
echo "=================================="
echo ""
echo "📋 后续步骤:"
echo ""
echo "1️⃣  重新加载环境变量:"
echo "   source $CONFIG_FILE"
echo ""
echo "2️⃣  启动 IDA Pro:"
echo "   $START_SCRIPT /path/to/binary.exe"
echo ""
echo "3️⃣  在 IDA 中启动 MCP 插件:"
echo "   - 按 Ctrl+Alt+M (macOS: Ctrl+Option+M)"
echo "   - 或通过菜单: Edit → Plugins → MCP"
echo ""
echo "4️⃣  测试连接:"
echo "   $TEST_SCRIPT"
echo ""
echo "5️⃣  本地客户端连接:"
echo "   export IDA_MCP_AUTH_TOKEN=\"$TOKEN\""
echo "   curl -H \"Authorization: Bearer \$IDA_MCP_AUTH_TOKEN\" \\"
echo "        http://YOUR_SERVER_IP:13337/sse"
echo ""
echo "🔐 安全提示:"
echo "   - 妥善保管 Token: ${TOKEN:0:8}...${TOKEN: -4}"
echo "   - Token 已保存在: $CONFIG_FILE"
echo "   - 建议配置防火墙限制访问 IP"
echo "   - 考虑使用 SSH 隧道或 VPN"
echo ""
echo "📚 详细文档:"
echo "   - 部署指南: $(dirname $SCRIPT_DIR)/DEPLOYMENT.md"
echo "   - 认证配置: $(dirname $SCRIPT_DIR)/AUTHENTICATION.md"
echo "=================================="
