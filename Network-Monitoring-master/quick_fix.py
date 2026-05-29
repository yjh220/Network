#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
一键修复登录问题
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def fix_login():
    """修复登录问题"""
    print("=" * 50)
    print("登录问题一键修复工具")
    print("=" * 50)
    print()

    from app2 import app, db
    from models import User

    with app.app_context():
        # 检查现有用户
        users = User.query.all()
        print(f"当前用户数量: {len(users)}")

        if len(users) == 0:
            print("\n没有找到用户，正在创建默认管理员账户...")
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
        else:
            print("\n现有用户:")
            for user in users:
                print(f"  - {user.username} ({user.role})")

            # 确保admin用户存在
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                print("\n正在创建管理员账户...")
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    role='admin',
                    is_active=True
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("✓ 管理员账户创建成功")
            else:
                # 重置管理员密码
                admin.set_password('admin123')
                db.session.commit()
                print("\n✓ 管理员密码已重置为: admin123")

        print("\n" + "=" * 50)
        print("修复完成！")
        print("=" * 50)
        print("\n默认登录信息:")
        print("  用户名: admin")
        print("  密码: admin123")
        print("\n现在可以启动应用了:")
        print("  python app2.py")
        print("\n访问: http://127.0.0.1:8080")


if __name__ == '__main__':
    try:
        fix_login()
    except Exception as e:
        print(f"\n错误: {str(e)}")
        import traceback
        traceback.print_exc()
        print("\n请确保已安装所有依赖:")
        print("  pip install Flask-SQLAlchemy Flask-Login")
