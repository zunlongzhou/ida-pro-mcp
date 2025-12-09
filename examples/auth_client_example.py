#!/usr/bin/env python3
"""
IDA Pro MCP 认证客户端示例

演示如何使用认证连接到远程 IDA Pro MCP 服务器
"""

import json
import requests
from typing import Dict, Any


class IdaMcpClient:
    """IDA Pro MCP 客户端（支持认证）"""
    
    def __init__(self, base_url: str, auth_token: str = None):
        """
        初始化客户端
        
        Args:
            base_url: 服务器地址，如 "http://server:13337"
            auth_token: 认证 Token（可选）
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        if auth_token:
            self.session.headers.update({
                "Authorization": f"Bearer {auth_token}"
            })
    
    def call_tool(self, method: str, params: Any = None) -> Dict[str, Any]:
        """
        调用 MCP 工具
        
        Args:
            method: 方法名，如 "tools/call"
            params: 参数
        
        Returns:
            响应数据
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": 1
        }
        
        response = self.session.post(
            f"{self.base_url}/mcp",
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        
        result = response.json()
        if "error" in result:
            raise Exception(f"RPC Error: {result['error']}")
        
        return result.get("result", {})
    
    def list_tools(self) -> list:
        """列出所有可用工具"""
        result = self.call_tool("tools/list")
        return result.get("tools", [])
    
    def decompile(self, address: str) -> str:
        """反编译指定地址的函数"""
        result = self.call_tool("tools/call", {
            "name": "decompile",
            "arguments": {"addrs": address}
        })
        return result.get("content", [{}])[0].get("text", "")


def example_basic_usage():
    """示例 1: 基本使用（本地无认证）"""
    print("=" * 60)
    print("示例 1: 本地连接（无认证）")
    print("=" * 60)
    
    client = IdaMcpClient("http://127.0.0.1:13337")
    
    try:
        tools = client.list_tools()
        print(f"✅ 连接成功，共 {len(tools)} 个工具")
        print(f"工具示例: {tools[0]['name']}" if tools else "无工具")
    except Exception as e:
        print(f"❌ 连接失败: {e}")
    
    print()


def example_remote_with_auth():
    """示例 2: 远程连接（带认证）"""
    print("=" * 60)
    print("示例 2: 远程连接（带认证）")
    print("=" * 60)
    
    # 从环境变量或配置文件读取
    import os
    token = os.environ.get("IDA_MCP_AUTH_TOKEN", "your-secret-token")
    
    client = IdaMcpClient(
        base_url="http://your-server:13337",
        auth_token=token
    )
    
    try:
        tools = client.list_tools()
        print(f"✅ 认证成功，共 {len(tools)} 个工具")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print("❌ 认证失败: 缺少 Authorization 头")
        elif e.response.status_code == 403:
            print("❌ 认证失败: Token 无效")
        else:
            print(f"❌ 连接失败: {e}")
    except Exception as e:
        print(f"❌ 连接失败: {e}")
    
    print()


def example_decompile_function():
    """示例 3: 反编译函数"""
    print("=" * 60)
    print("示例 3: 反编译函数")
    print("=" * 60)
    
    client = IdaMcpClient("http://127.0.0.1:13337")
    
    try:
        # 反编译 main 函数
        code = client.decompile("main")
        print("✅ 反编译成功:")
        print("-" * 60)
        print(code[:500])  # 只显示前 500 字符
        print("-" * 60)
    except Exception as e:
        print(f"❌ 反编译失败: {e}")
    
    print()


def example_sse_with_auth():
    """示例 4: SSE 连接（带认证）"""
    print("=" * 60)
    print("示例 4: SSE 连接（带认证）")
    print("=" * 60)
    
    import os
    token = os.environ.get("IDA_MCP_AUTH_TOKEN", "your-secret-token")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(
            "http://127.0.0.1:13337/sse",
            headers=headers,
            stream=True,
            timeout=5
        )
        
        if response.status_code == 200:
            print("✅ SSE 连接建立成功")
            print("正在接收事件...")
            
            # 读取前几个事件
            count = 0
            for line in response.iter_lines():
                if line:
                    decoded = line.decode('utf-8')
                    print(f"  {decoded}")
                    count += 1
                    if count >= 5:  # 只读取前 5 行
                        break
        else:
            print(f"❌ 连接失败: HTTP {response.status_code}")
    
    except requests.exceptions.Timeout:
        print("✅ 连接超时（预期行为，SSE 是长连接）")
    except Exception as e:
        print(f"❌ 连接失败: {e}")
    
    print()


if __name__ == "__main__":
    print("\n🔐 IDA Pro MCP 认证客户端示例\n")
    
    # 运行所有示例
    example_basic_usage()
    example_remote_with_auth()
    example_decompile_function()
    example_sse_with_auth()
    
    print("=" * 60)
    print("提示:")
    print("  1. 确保 IDA Pro MCP 服务器正在运行")
    print("  2. 设置环境变量: export IDA_MCP_AUTH_TOKEN='your-token'")
    print("  3. 修改示例中的服务器地址和端口")
    print("=" * 60)
