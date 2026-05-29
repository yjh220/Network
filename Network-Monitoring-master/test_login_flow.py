#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试登录和跳转功能
"""

import requests
import sys

BASE_URL = "http://127.0.0.1:8080"


def test_login():
    """测试登录功能"""
    print("=" * 50)
    print("测试登录和跳转功能")
    print("=" * 50)
    print()

    # 创建一个会话
    session = requests.Session()

    # 1. 测试访问登录页面
    print("1. 访问登录页面...")
    try:
        response = session.get(f"{BASE_URL}/login")
        if response.status_code == 200:
            print("   ✓ 登录页面加载成功")
        else:
            print(f"   ✗ 登录页面加载失败: {response.status_code}")
            return
    except Exception as e:
        print(f"   ✗ 无法连接到服务器: {e}")
        print("   请确保应用正在运行: python app2.py")
        return

    # 2. 测试登录
    print("\n2. 尝试登录...")
    login_data = {
        'username': 'admin',
        'password': 'admin123'
    }

    try:
        response = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=True)

        if response.status_code == 200:
            # 检查是否跳转到主页
            if '欢迎回来' in response.text or 'home' in response.url or response.url == f'{BASE_URL}/':
                print("   ✓ 登录成功，已跳转到主页")
            else:
                print(f"   ? 登录响应正常，但跳转到: {response.url}")
                print(f"   响应长度: {len(response.text)} 字符")
        else:
            print(f"   ✗ 登录失败: {response.status_code}")
    except Exception as e:
        print(f"   ✗ 登录请求失败: {e}")

    # 3. 测试访问受保护页面
    print("\n3. 测试访问受保护页面...")
    try:
        response = session.get(f"{BASE_URL}/dashboard")
        if response.status_code == 200:
            print("   ✓ 可以访问仪表板")
        else:
            print(f"   ✗ 无法访问仪表板: {response.status_code}")
    except Exception as e:
        print(f"   ✗ 访问仪表板失败: {e}")

    print("\n" + "=" * 50)
    print("测试完成！")
    print("=" * 50)


if __name__ == '__main__':
    try:
        test_login()
    except KeyboardInterrupt:
        print("\n测试已取消")
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
