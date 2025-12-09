#!/usr/bin/env python3
"""
测试 IDA Pro MCP 认证功能的脚本

使用方法:
    python test_auth.py --host 127.0.0.1 --port 13337 --token "your-token"
"""

import argparse
import requests
import sys
from typing import Tuple


def test_no_auth(url: str) -> Tuple[bool, str]:
    """测试没有 Authorization 头的请求"""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 401:
            return True, "✅ 正确拒绝无认证请求 (401 Unauthorized)"
        else:
            return False, f"❌ 应该返回 401，实际返回 {response.status_code}"
    except Exception as e:
        return False, f"❌ 请求失败: {e}"


def test_wrong_auth(url: str) -> Tuple[bool, str]:
    """测试错误的 Token"""
    try:
        headers = {"Authorization": "Bearer wrong-token-12345"}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 403:
            return True, "✅ 正确拒绝错误 Token (403 Forbidden)"
        else:
            return False, f"❌ 应该返回 403，实际返回 {response.status_code}"
    except Exception as e:
        return False, f"❌ 请求失败: {e}"


def test_correct_auth(url: str, token: str) -> Tuple[bool, str]:
    """测试正确的 Token"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=headers, timeout=5, stream=True)
        if response.status_code == 200:
            # 检查是否返回 SSE 流
            content_type = response.headers.get("Content-Type", "")
            if "text/event-stream" in content_type:
                return True, "✅ 认证成功，建立 SSE 连接"
            else:
                return True, f"✅ 认证成功 (Content-Type: {content_type})"
        else:
            return False, f"❌ 认证失败，返回 {response.status_code}"
    except Exception as e:
        return False, f"❌ 请求失败: {e}"


def test_no_bearer_prefix(url: str, token: str) -> Tuple[bool, str]:
    """测试不带 Bearer 前缀的 Token"""
    try:
        headers = {"Authorization": token}
        response = requests.get(url, headers=headers, timeout=5, stream=True)
        if response.status_code == 200:
            return True, "✅ 支持不带 Bearer 前缀的 Token"
        else:
            return False, f"❌ 不带 Bearer 前缀的 Token 失败: {response.status_code}"
    except Exception as e:
        return False, f"❌ 请求失败: {e}"


def main():
    parser = argparse.ArgumentParser(description="测试 IDA Pro MCP 认证功能")
    parser.add_argument("--host", default="127.0.0.1", help="服务器地址")
    parser.add_argument("--port", type=int, default=13337, help="服务器端口")
    parser.add_argument("--token", required=True, help="认证 Token")
    parser.add_argument("--endpoint", default="/sse", help="测试端点")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}{args.endpoint}"
    
    print("=" * 60)
    print(f"🔐 IDA Pro MCP 认证测试")
    print("=" * 60)
    print(f"服务器: {url}")
    print(f"Token: {args.token[:8]}..." if len(args.token) > 8 else f"Token: {args.token}")
    print("=" * 60)
    print()

    tests = [
        ("无认证请求", lambda: test_no_auth(url)),
        ("错误 Token", lambda: test_wrong_auth(url)),
        ("正确 Token (Bearer 格式)", lambda: test_correct_auth(url, args.token)),
        ("正确 Token (无 Bearer 前缀)", lambda: test_no_bearer_prefix(url, args.token)),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        print(f"测试: {name}")
        success, message = test_func()
        print(f"  {message}")
        print()
        
        if success:
            passed += 1
        else:
            failed += 1

    print("=" * 60)
    print(f"测试结果: {passed} 通过, {failed} 失败")
    print("=" * 60)

    if failed > 0:
        print()
        print("❗ 提示:")
        print("  1. 确保 IDA Pro MCP 服务器正在运行")
        print("  2. 确保已在配置页面或环境变量中设置了 Token")
        print("  3. 确认 Token 与命令行参数一致")
        print()
        sys.exit(1)
    else:
        print()
        print("✅ 所有测试通过！认证功能正常工作。")
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
