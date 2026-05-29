#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
后台管理系统快速初始化脚本
一键初始化数据库、权限、角色和管理员账户
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app2_admin import app
from models_admin import db, User, Role
from modules.admin.permissions import PermissionManager
from modules.admin.admin_service import UserService


def init_database():
    """初始化数据库"""
    print("=" * 60)
    print("网络入侵检测系统 - 后台管理初始化")
    print("=" * 60)
    print()

    with app.app_context():
        # 1. 创建所有表
        print("1. 创建数据库表...")
        try:
            db.create_all()
            print("   ✓ 数据库表创建成功")
        except Exception as e:
            print(f"   ✗ 数据库表创建失败: {str(e)}")
            return False

        # 2. 初始化权限
        print("\n2. 初始化权限数据...")
        try:
            if PermissionManager.init_permissions():
                perm_count = len(PermissionManager.PERMISSIONS)
                print(f"   ✓ 权限初始化成功（{perm_count}个权限）")
            else:
                print("   ✗ 权限初始化失败")
                return False
        except Exception as e:
            print(f"   ✗ 权限初始化异常: {str(e)}")
            return False

        # 3. 初始化角色
        print("\n3. 初始化角色数据...")
        try:
            if PermissionManager.init_roles():
                role_count = Role.query.count()
                print(f"   ✓ 角色初始化成功（{role_count}个角色）")
            else:
                print("   ✗ 角色初始化失败")
                return False
        except Exception as e:
            print(f"   ✗ 角色初始化异常: {str(e)}")
            return False

        # 4. 检查是否需要创建管理员
        print("\n4. 检查管理员账户...")
        admin_exists = User.query.filter_by(username='admin').first()

        if admin_exists:
            print(f"   ℹ 管理员账户已存在: {admin_exists.username}")
            print(f"   - 邮箱: {admin_exists.email}")
            print(f"   - 状态: {'激活' if admin_exists.is_active else '禁用'}")

            # 询问是否重置密码
            print()
            try:
                reset = input("   是否重置管理员密码? (y/N): ").strip().lower()
                if reset == 'y':
                    new_password = input("   请输入新密码: ").strip()
                    if len(new_password) < 6:
                        print("   ✗ 密码至少需要6个字符")
                        return False

                    success, message = UserService.reset_password(
                        user_id=admin_exists.id,
                        new_password=new_password
                    )

                    if success:
                        print(f"   ✓ 密码重置成功")
                    else:
                        print(f"   ✗ 密码重置失败: {message}")
                        return False
            except EOFError:
                pass  # 非交互模式，跳过密码重置
        else:
            print("   ℹ 管理员账户不存在，开始创建...")

            # 获取admin角色
            admin_role = Role.query.filter_by(name='admin').first()
            if not admin_role:
                print("   ✗ 错误: admin角色不存在")
                return False

            # 获取管理员信息（非交互模式使用默认值）
            try:
                username = input("   请输入管理员用户名 [admin]: ").strip() or 'admin'
                email = input("   请输入管理员邮箱 [admin@example.com]: ").strip() or 'admin@example.com'
                password = input("   请输入管理员密码 [admin123]: ").strip() or 'admin123'
            except EOFError:
                # 非交互模式，使用默认值
                username = 'admin'
                email = 'admin@example.com'
                password = 'admin123'

            if len(password) < 6:
                print("   ✗ 密码至少需要6个字符")
                return False

            # 创建管理员
            success, user, message = UserService.create_user(
                username=username,
                email=email,
                password=password,
                role_id=admin_role.id
            )

            if success:
                print(f"   ✓ 管理员账户创建成功")
                print(f"   - 用户名: {username}")
                print(f"   - 密码: {password}")
            else:
                print(f"   ✗ 创建失败: {message}")
                return False

        # 5. 显示初始化摘要
        print()
        print("=" * 60)
        print("初始化完成！")
        print("=" * 60)

        user_count = User.query.count()
        role_count = Role.query.count()
        perm_count = len(PermissionManager.PERMISSIONS)

        print(f"\n系统统计:")
        print(f"  - 用户数: {user_count}")
        print(f"  - 角色数: {role_count}")
        print(f"  - 权限数: {perm_count}")

        print(f"\n访问地址:")
        print(f"  - 后台管理: http://127.0.0.1:8080/admin")

        print(f"\n默认账户:")
        print(f"  - 用户名: admin")
        print(f"  - 密码: admin123")
        print(f"\n  ⚠️  首次登录后请立即修改默认密码！")
        print()

        return True


if __name__ == '__main__':
    try:
        success = init_database()
        if success:
            print("\n现在可以运行以下命令启动系统:")
            print("  python app2_admin.py")
            sys.exit(0)
        else:
            print("\n初始化失败，请检查错误信息")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n初始化已取消")
        sys.exit(1)
    except Exception as e:
        print(f"\n初始化过程发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
