#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试登录功能
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app2 import app, db
from models import User
from modules.auth.auth import AuthManager


def test_login():
    """测试登录功能"""
    with app.app_context():
        # 检查是否有用户
        users = User.query.all()
        print(f"数据库中的用户数量: {len(users)}")

        if len(users) == 0:
            print("警告：数据库中没有用户！")
            print("请先运行: python init_db.py")
            return

        # 显示所有用户
        print("\n用户列表:")
        for user in users:
            print(f"  - {user.username} ({user.email}) - {'激活' if user.is_active else '禁用'}")

        # 测试登录
        print("\n测试登录功能:")
        test_username = "admin"
        test_password = "admin123"

        success, user, message = AuthManager.authenticate_user(test_username, test_password)

        if success:
            print(f"✓ 登录成功: {user.username}")
            print(f"  角色: {user.role}")
            print(f"  ID: {user.id}")
        else:
            print(f"✗ 登录失败: {message}")

        # 测试密码验证
        print("\n测试密码验证:")
        admin_user = User.query.filter_by(username='admin').first()
        if admin_user:
            print(f"用户: {admin_user.username}")
            print(f"密码验证 (admin123): {admin_user.check_password('admin123')}")
            print(f"密码验证 (wrong): {admin_user.check_password('wrong')}")


if __name__ == '__main__':
    print("=" * 50)
    print("登录功能测试")
    print("=" * 50)
    print()

    try:
        test_login()
    except Exception as e:
        print(f"\n错误: {str(e)}")
        import traceback
        traceback.print_exc()
