#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
后台管理服务模块
提供用户、角色、权限等管理功能
"""

from datetime import datetime, timedelta
from models_admin import db, User, Role, Permission, LoginLog, OperationLog, SystemLog
from modules.admin.log_service import LoginLogger, OperationLogger
import logging

logger = logging.getLogger(__name__)


class UserService:
    """用户管理服务"""

    @staticmethod
    def get_users(page=1, per_page=20, search=None, role_id=None, is_active=None):
        """
        获取用户列表

        Args:
            page: 页码
            per_page: 每页数量
            search: 搜索关键词
            role_id: 角色筛选
            is_active: 状态筛选

        Returns:
            (users, total): 用户列表和总数
        """
        try:
            query = User.query

            # 搜索过滤
            if search:
                query = query.filter(
                    db.or_(
                        User.username.like(f'%{search}%'),
                        User.email.like(f'%{search}%')
                    )
                )

            # 角色过滤
            if role_id is not None:
                query = query.filter_by(role_id=role_id)

            # 状态过滤
            if is_active is not None:
                query = query.filter_by(is_active=is_active)

            # 分页
            pagination = query.order_by(User.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取用户列表失败: {str(e)}")
            return [], 0

    @staticmethod
    def get_user_by_id(user_id):
        """根据ID获取用户"""
        try:
            return User.query.get(user_id)
        except Exception as e:
            logger.error(f"获取用户失败: {str(e)}")
            return None

    @staticmethod
    def create_user(username, email, password, role_id, created_by_id=None):
        """
        创建用户

        Args:
            username: 用户名
            email: 邮箱
            password: 密码
            role_id: 角色ID
            created_by_id: 创建者ID

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

            # 检查角色是否存在
            role = Role.query.get(role_id)
            if not role:
                return False, None, '指定的角色不存在'

            # 创建用户
            user = User(
                username=username,
                email=email,
                role_id=role_id
            )
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='user',
                action='create',
                resource=f'user:{user.id}',
                details={'username': username, 'email': email, 'role': role.name}
            )

            logger.info(f"创建用户成功: {username}")
            return True, user, '创建成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建用户失败: {str(e)}")
            return False, None, f'创建失败: {str(e)}'

    @staticmethod
    def update_user(user_id, email=None, role_id=None, is_active=None, updated_by_id=None):
        """
        更新用户信息

        Args:
            user_id: 用户ID
            email: 新邮箱
            role_id: 新角色ID
            is_active: 激活状态
            updated_by_id: 更新者ID

        Returns:
            (success, message): (是否成功, 消息)
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return False, '用户不存在'

            changes = {}

            # 更新邮箱
            if email and email != user.email:
                if User.query.filter(User.email == email, User.id != user_id).first():
                    return False, '邮箱已被使用'
                user.email = email
                changes['email'] = email

            # 更新角色
            if role_id is not None and role_id != user.role_id:
                role = Role.query.get(role_id)
                if not role:
                    return False, '指定的角色不存在'
                old_role = user.role.name if user.role else 'None'
                user.role_id = role_id
                changes['role'] = f'{old_role} -> {role.name}'

            # 更新状态
            if is_active is not None and is_active != user.is_active:
                user.is_active = is_active
                changes['is_active'] = is_active

            if not changes:
                return False, '没有需要更新的内容'

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='user',
                action='update',
                resource=f'user:{user_id}',
                details=changes
            )

            logger.info(f"更新用户成功: {user.username}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新用户失败: {str(e)}")
            return False, f'更新失败: {str(e)}'

    @staticmethod
    def delete_user(user_id, deleted_by_id=None):
        """
        删除用户

        Args:
            user_id: 用户ID
            deleted_by_id: 删除者ID

        Returns:
            (success, message): (是否成功, 消息)
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return False, '用户不存在'

            if user_id == deleted_by_id:
                return False, '不能删除自己的账户'

            username = user.username
            db.session.delete(user)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='user',
                action='delete',
                resource=f'user:{user_id}',
                details={'username': username}
            )

            logger.info(f"删除用户成功: {username}")
            return True, '删除成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除用户失败: {str(e)}")
            return False, f'删除失败: {str(e)}'

    @staticmethod
    def reset_password(user_id, new_password, reset_by_id=None):
        """
        重置用户密码

        Args:
            user_id: 用户ID
            new_password: 新密码
            reset_by_id: 重置者ID

        Returns:
            (success, message): (是否成功, 消息)
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return False, '用户不存在'

            user.set_password(new_password)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='user',
                action='reset_password',
                resource=f'user:{user_id}',
                details={'username': user.username}
            )

            logger.info(f"重置密码成功: {user.username}")
            return True, '密码重置成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"重置密码失败: {str(e)}")
            return False, f'重置失败: {str(e)}'

    @staticmethod
    def get_login_logs(user_id=None, page=1, per_page=20, start_date=None, end_date=None):
        """
        获取登录日志

        Args:
            user_id: 用户ID（可选）
            page: 页码
            per_page: 每页数量
            start_date: 开始日期
            end_date: 结束日期

        Returns:
            (logs, total): 日志列表和总数
        """
        try:
            query = LoginLog.query

            if user_id:
                query = query.filter_by(user_id=user_id)

            if start_date:
                query = query.filter(LoginLog.login_time >= start_date)

            if end_date:
                query = query.filter(LoginLog.login_time <= end_date)

            # 只返回最近90天的日志
            query = query.filter(LoginLog.login_time >= datetime.utcnow() - timedelta(days=90))

            pagination = query.order_by(LoginLog.login_time.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取登录日志失败: {str(e)}")
            return [], 0


class RoleService:
    """角色管理服务"""

    @staticmethod
    def get_roles(include_system=False):
        """
        获取角色列表

        Args:
            include_system: 是否包含系统角色

        Returns:
            角色列表
        """
        try:
            query = Role.query
            if not include_system:
                query = query.filter_by(is_system=False)
            return query.order_by(Role.id).all()
        except Exception as e:
            logger.error(f"获取角色列表失败: {str(e)}")
            return []

    @staticmethod
    def get_role_by_id(role_id):
        """根据ID获取角色"""
        try:
            return Role.query.get(role_id)
        except Exception as e:
            logger.error(f"获取角色失败: {str(e)}")
            return None

    @staticmethod
    def create_role(name, description, permission_ids=None, created_by_id=None):
        """
        创建角色

        Args:
            name: 角色名
            description: 描述
            permission_ids: 权限ID列表
            created_by_id: 创建者ID

        Returns:
            (success, role, message): (是否成功, 角色对象, 消息)
        """
        try:
            # 检查角色名是否已存在
            if Role.query.filter_by(name=name).first():
                return False, None, '角色名已存在'

            # 创建角色
            role = Role(
                name=name,
                description=description
            )

            # 分配权限
            if permission_ids:
                permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all()
                role.permissions = permissions

            db.session.add(role)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='role',
                action='create',
                resource=f'role:{role.id}',
                details={'name': name, 'permissions': len(role.permissions)}
            )

            logger.info(f"创建角色成功: {name}")
            return True, role, '创建成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建角色失败: {str(e)}")
            return False, None, f'创建失败: {str(e)}'

    @staticmethod
    def update_role(role_id, name=None, description=None, permission_ids=None, updated_by_id=None):
        """
        更新角色

        Args:
            role_id: 角色ID
            name: 新角色名
            description: 新描述
            permission_ids: 权限ID列表
            updated_by_id: 更新者ID

        Returns:
            (success, message): (是否成功, 消息)
        """
        try:
            role = Role.query.get(role_id)
            if not role:
                return False, '角色不存在'

            if role.is_system:
                return False, '系统角色不能修改'

            changes = {}

            # 更新角色名
            if name and name != role.name:
                if Role.query.filter(Role.name == name, Role.id != role_id).first():
                    return False, '角色名已存在'
                role.name = name
                changes['name'] = name

            # 更新描述
            if description is not None and description != role.description:
                role.description = description
                changes['description'] = description

            # 更新权限
            if permission_ids is not None:
                old_permissions = {p.id for p in role.permissions}
                new_permissions = set(permission_ids)

                if old_permissions != new_permissions:
                    permissions = Permission.query.filter(Permission.id.in_(permission_ids)).all()
                    role.permissions = permissions
                    changes['permissions'] = f'{len(old_permissions)} -> {len(permissions)}'

            if not changes:
                return False, '没有需要更新的内容'

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='role',
                action='update',
                resource=f'role:{role_id}',
                details=changes
            )

            logger.info(f"更新角色成功: {role.name}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新角色失败: {str(e)}")
            return False, f'更新失败: {str(e)}'

    @staticmethod
    def delete_role(role_id, deleted_by_id=None):
        """
        删除角色

        Args:
            role_id: 角色ID
            deleted_by_id: 删除者ID

        Returns:
            (success, message): (是否成功, 消息)
        """
        try:
            role = Role.query.get(role_id)
            if not role:
                return False, '角色不存在'

            if role.is_system:
                return False, '系统角色不能删除'

            if role.users:
                return False, f'该角色下还有 {len(role.users)} 个用户，无法删除'

            role_name = role.name
            db.session.delete(role)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='role',
                action='delete',
                resource=f'role:{role_id}',
                details={'name': role_name}
            )

            logger.info(f"删除角色成功: {role_name}")
            return True, '删除成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除角色失败: {str(e)}")
            return False, f'删除失败: {str(e)}'


class LogService:
    """日志管理服务"""

    @staticmethod
    def get_operation_logs(page=1, per_page=50, module=None, action=None,
                          user_id=None, start_date=None, end_date=None):
        """
        获取操作日志

        Args:
            page: 页码
            per_page: 每页数量
            module: 模块筛选
            action: 操作类型筛选
            user_id: 用户筛选
            start_date: 开始日期
            end_date: 结束日期

        Returns:
            (logs, total): 日志列表和总数
        """
        try:
            query = OperationLog.query

            if module:
                query = query.filter_by(module=module)

            if action:
                query = query.filter_by(action=action)

            if user_id:
                query = query.filter_by(user_id=user_id)

            if start_date:
                query = query.filter(OperationLog.created_at >= start_date)

            if end_date:
                query = query.filter(OperationLog.created_at <= end_date)

            # 只返回最近30天的日志
            query = query.filter(OperationLog.created_at >= datetime.utcnow() - timedelta(days=30))

            pagination = query.order_by(OperationLog.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取操作日志失败: {str(e)}")
            return [], 0

    @staticmethod
    def get_system_logs(page=1, per_page=50, level=None, module=None,
                       start_date=None, end_date=None):
        """
        获取系统日志

        Args:
            page: 页码
            per_page: 每页数量
            level: 日志级别筛选
            module: 模块筛选
            start_date: 开始日期
            end_date: 结束日期

        Returns:
            (logs, total): 日志列表和总数
        """
        try:
            query = SystemLog.query

            if level:
                query = query.filter_by(level=level)

            if module:
                query = query.filter_by(module=module)

            if start_date:
                query = query.filter(SystemLog.created_at >= start_date)

            if end_date:
                query = query.filter(SystemLog.created_at <= end_date)

            # 只返回最近7天的日志
            query = query.filter(SystemLog.created_at >= datetime.utcnow() - timedelta(days=7))

            pagination = query.order_by(SystemLog.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取系统日志失败: {str(e)}")
            return [], 0

    @staticmethod
    def delete_old_logs(log_type='operation', days=90):
        """
        删除旧日志

        Args:
            log_type: 日志类型 (operation, system, login)
            days: 保留天数

        Returns:
            (success, count, message): (是否成功, 删除数量, 消息)
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            if log_type == 'operation':
                count = OperationLog.query.filter(OperationLog.created_at < cutoff_date).delete()
            elif log_type == 'system':
                count = SystemLog.query.filter(SystemLog.created_at < cutoff_date).delete()
            elif log_type == 'login':
                count = LoginLog.query.filter(LoginLog.login_time < cutoff_date).delete()
            else:
                return False, 0, '无效的日志类型'

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='log',
                action='delete',
                resource=f'{log_type}_logs',
                details={'days': days, 'count': count}
            )

            logger.info(f"删除旧日志成功: {log_type} - {count}条")
            return True, count, f'已删除 {count} 条日志'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除旧日志失败: {str(e)}")
            return False, 0, f'删除失败: {str(e)}'
