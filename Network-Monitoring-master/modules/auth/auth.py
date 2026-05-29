#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from datetime import datetime

# 支持两种User模型
try:
    from models_admin import db, User
    USING_ADMIN_MODELS = True
except ImportError:
    from models import db, User
    USING_ADMIN_MODELS = False

logger = logging.getLogger(__name__)


class AuthManager:
    """认证管理器"""

    @staticmethod
    def register_user(username, email, password, role='user'):
        """
        注册新用户

        Args:
            username: 用户名
            email: 邮箱
            password: 密码
            role: 角色，默认为 'user'

        Returns:
            (success, user, message): (是否成功, 用户对象, 消息)
        """
        try:
            # 检查用户名是否已存在
            if User.query.filter_by(username=username).first():
                return False, None, '用户名已存在'

            # 检查邮箱是否已存在
            if User.query.filter_by(email=email).first():
                return False, None, '邮箱已被使用'

            # 根据User模型类型创建用户
            if USING_ADMIN_MODELS:
                # models_admin.User - 需要role_id
                from models_admin import Role
                user_role = Role.query.filter_by(name='user').first()
                if not user_role:
                    # 如果user角色不存在，创建一个
                    user_role = Role(name='user', description='普通用户')
                    db.session.add(user_role)
                    db.session.commit()

                user = User(
                    username=username,
                    email=email,
                    role_id=user_role.id
                )
            else:
                # 原始models.User - role是字符串
                user = User(
                    username=username,
                    email=email,
                    role=role
                )

            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            logger.info(f"新用户注册成功: {username} ({email})")
            return True, user, '注册成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"用户注册失败: {str(e)}")
            return False, None, f'注册失败: {str(e)}'

    @staticmethod
    def authenticate_user(username, password):
        """
        验证用户登录

        Args:
            username: 用户名
            password: 密码

        Returns:
            (success, user, message): (是否成功, 用户对象, 消息)
        """
        try:
            # 查找用户
            user = User.query.filter_by(username=username).first()

            if not user:
                return False, None, '用户名或密码错误'

            if not user.is_active:
                return False, None, '账户已被禁用'

            # 验证密码
            if not user.check_password(password):
                return False, None, '用户名或密码错误'

            # 更新最后登录时间
            user.update_last_login()

            logger.info(f"用户登录成功: {username}")
            return True, user, '登录成功'

        except Exception as e:
            logger.error(f"用户登录失败: {str(e)}")
            return False, None, f'登录失败: {str(e)}'

    @staticmethod
    def get_user_by_id(user_id):
        """根据ID获取用户"""
        try:
            return User.query.get(user_id)
        except Exception as e:
            logger.error(f"获取用户失败: {str(e)}")
            return None

    @staticmethod
    def get_all_users():
        """获取所有用户"""
        try:
            return User.query.all()
        except Exception as e:
            logger.error(f"获取用户列表失败: {str(e)}")
            return []

    @staticmethod
    def delete_user(user_id):
        """删除用户"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False, '用户不存在'

            db.session.delete(user)
            db.session.commit()

            logger.info(f"用户已删除: {user.username}")
            return True, '用户已删除'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除用户失败: {str(e)}")
            return False, f'删除失败: {str(e)}'

    @staticmethod
    def update_user_role(user_id, new_role):
        """更新用户角色"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False, '用户不存在'

            if new_role not in ['user', 'admin']:
                return False, '无效的角色'

            user.role = new_role
            db.session.commit()

            logger.info(f"用户角色已更新: {user.username} -> {new_role}")
            return True, '角色已更新'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新用户角色失败: {str(e)}")
            return False, f'更新失败: {str(e)}'

    @staticmethod
    def toggle_user_active(user_id):
        """切换用户激活状态"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False, '用户不存在'

            user.is_active = not user.is_active
            db.session.commit()

            status = '激活' if user.is_active else '禁用'
            logger.info(f"用户状态已更新: {user.username} -> {status}")
            return True, f'用户已{status}'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新用户状态失败: {str(e)}")
            return False, f'更新失败: {str(e)}'
