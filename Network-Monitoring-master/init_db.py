#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据库初始化脚本
用于创建数据库表和默认管理员账户
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app2 import app
from models import db, User


def init_database():
    """初始化数据库"""
    with app.app_context():
        # 创建所有表
        db.create_all()
        print("✓ 数据库表创建成功")

        # 检查是否已存在管理员账户
        admin = User.query.filter_by(username='admin').first()

        if admin:
            print(f"✓ 管理员账户已存在: {admin.username}")
            print(f"  邮箱: {admin.email}")
            print(f"  角色: {admin.role}")
            print(f"  状态: {'激活' if admin.is_active else '禁用'}")
        else:
            # 创建默认管理员账户
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin',
                is_active=True
            )
            admin.set_password('admin123')

            db.session.add(admin)
            db.session.commit()

            print("✓ 默认管理员账户创建成功")
            print(f"  用户名: admin")
            print(f"  密码: admin123")
            print(f"  邮箱: admin@example.com")
            print("\n  ⚠️  重要提示: 首次登录后请立即修改默认密码！")

        # 显示所有用户
        print("\n当前系统用户列表:")
        users = User.query.all()
        for user in users:
            print(f"  - {user.username} ({user.role}): {'激活' if user.is_active else '禁用'}")

        print(f"\n总计: {len(users)} 个用户")


if __name__ == '__main__':
    print("=" * 50)
    print("网络入侵检测与防御系统 - 数据库初始化")
    print("=" * 50)
    print()

    try:
        init_database()
        print("\n" + "=" * 50)
        print("数据库初始化完成！")
        print("=" * 50)
    except Exception as e:
        print(f"\n错误: 数据库初始化失败")
        print(f"详细错误信息: {str(e)}")
        sys.exit(1)
