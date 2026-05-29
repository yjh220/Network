#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
后台管理权限控制模块
提供权限装饰器和权限检查功能
"""

from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user
from models_admin import db, User, Permission, Role
import logging

logger = logging.getLogger(__name__)


def permission_required(permission_name):
    """
    权限装饰器 - 检查用户是否有指定权限

    使用示例:
        @permission_required('user.view')
        def user_list():
            return render_template('admin/users.html')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 未登录用户重定向到登录页
            if not current_user.is_authenticated:
                flash('请先登录', 'warning')
                return redirect(url_for('login'))

            # 检查用户状态
            if not current_user.is_active:
                flash('账户已被禁用', 'error')
                return redirect(url_for('logout'))

            # 检查账户锁定
            if hasattr(current_user, 'is_locked') and current_user.is_locked():
                flash('账户已被锁定，请稍后再试', 'error')
                return redirect(url_for('logout'))

            # 检查权限
            # 1. 如果User模型有has_permission方法，使用它
            # 2. 否则，检查用户是否是管理员
            has_permission = False

            if hasattr(current_user, 'has_permission'):
                # models_admin.User模型
                has_permission = current_user.has_permission(permission_name)
            else:
                # 原始models.User模型 - 只有管理员可以访问后台
                if hasattr(current_user, 'is_admin'):
                    has_permission = current_user.is_admin()
                elif hasattr(current_user, 'role'):
                    if isinstance(current_user.role, str):
                        has_permission = current_user.role == 'admin'
                    elif hasattr(current_user.role, 'name'):
                        has_permission = current_user.role.name == 'admin'

            if not has_permission:
                logger.warning(f"用户 {current_user.username} 尝试访问需要权限 {permission_name} 的页面")
                flash('您没有权限访问此页面', 'error')
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """
    管理员权限装饰器 - 检查用户是否是管理员

    使用示例:
        @admin_required
        def admin_settings():
            return render_template('admin/settings.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))

        if not current_user.is_active:
            flash('账户已被禁用', 'error')
            return redirect(url_for('logout'))

        # 支持两种User模型：
        # 1. 原始models.User: role字段是字符串 'admin' 或 'user'
        # 2. models_admin.User: role是关系对象
        is_admin = False
        if hasattr(current_user, 'is_admin'):
            # 原始User模型有is_admin()方法
            is_admin = current_user.is_admin()
        elif hasattr(current_user, 'role'):
            if isinstance(current_user.role, str):
                # role是字符串字段
                is_admin = current_user.role == 'admin'
            elif hasattr(current_user.role, 'name'):
                # role是关系对象
                is_admin = current_user.role.name == 'admin'

        if not is_admin:
            flash('需要管理员权限', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function


class PermissionManager:
    """权限管理器"""

    # 预定义的权限列表
    PERMISSIONS = [
        # 用户管理权限
        {'name': 'user.view', 'display_name': '查看用户', 'module': 'user', 'description': '查看用户列表和详情'},
        {'name': 'user.create', 'display_name': '创建用户', 'module': 'user', 'description': '创建新用户'},
        {'name': 'user.edit', 'display_name': '编辑用户', 'module': 'user', 'description': '编辑用户信息'},
        {'name': 'user.delete', 'display_name': '删除用户', 'module': 'user', 'description': '删除用户'},
        {'name': 'user.reset_password', 'display_name': '重置密码', 'module': 'user', 'description': '重置用户密码'},

        # 角色权限管理
        {'name': 'role.view', 'display_name': '查看角色', 'module': 'role', 'description': '查看角色列表和详情'},
        {'name': 'role.create', 'display_name': '创建角色', 'module': 'role', 'description': '创建新角色'},
        {'name': 'role.edit', 'display_name': '编辑角色', 'module': 'role', 'description': '编辑角色信息'},
        {'name': 'role.delete', 'display_name': '删除角色', 'module': 'role', 'description': '删除角色'},
        {'name': 'role.assign_permission', 'display_name': '分配权限', 'module': 'role', 'description': '为角色分配权限'},

        # 日志管理权限
        {'name': 'log.view', 'display_name': '查看日志', 'module': 'log', 'description': '查看各类日志'},
        {'name': 'log.export', 'display_name': '导出日志', 'module': 'log', 'description': '导出日志数据'},
        {'name': 'log.delete', 'display_name': '删除日志', 'module': 'log', 'description': '清理历史日志'},

        # 监控管理权限
        {'name': 'monitor.view', 'display_name': '查看监控', 'module': 'monitor', 'description': '查看系统监控'},
        {'name': 'monitor.config', 'display_name': '配置监控', 'module': 'monitor', 'description': '配置监控参数'},
        {'name': 'monitor.control', 'display_name': '控制监控', 'module': 'monitor', 'description': '启动停止监控'},

        # 威胁检测管理
        {'name': 'threat.view', 'display_name': '查看威胁', 'module': 'threat', 'description': '查看威胁记录'},
        {'name': 'threat.handle', 'display_name': '处置威胁', 'module': 'threat', 'description': '处置威胁事件'},
        {'name': 'threat.rule', 'display_name': '检测规则', 'module': 'threat', 'description': '管理检测规则'},
        {'name': 'threat.model', 'display_name': '模型管理', 'module': 'threat', 'description': '管理检测模型'},

        # 告警管理权限
        {'name': 'alert.view', 'display_name': '查看告警', 'module': 'alert', 'description': '查看告警记录'},
        {'name': 'alert.config', 'display_name': '配置告警', 'module': 'alert', 'description': '配置告警规则'},
        {'name': 'alert.notify', 'display_name': '通知设置', 'module': 'alert', 'description': '配置通知方式'},

        # 防御管理权限
        {'name': 'defense.view', 'display_name': '查看防御', 'module': 'defense', 'description': '查看防御状态'},
        {'name': 'defense.block', 'display_name': 'IP封禁', 'module': 'defense', 'description': '封禁解封IP'},
        {'name': 'defense.rule', 'display_name': '防御策略', 'module': 'defense', 'description': '管理防御规则'},

        # 系统管理权限
        {'name': 'system.view', 'display_name': '查看系统', 'module': 'system', 'description': '查看系统信息'},
        {'name': 'system.config', 'display_name': '系统配置', 'module': 'system', 'description': '修改系统配置'},
        {'name': 'system.backup', 'display_name': '数据备份', 'module': 'system', 'description': '备份恢复数据'},
    ]

    @staticmethod
    def init_permissions():
        """初始化所有权限"""
        try:
            for perm_data in PermissionManager.PERMISSIONS:
                existing = Permission.query.filter_by(name=perm_data['name']).first()
                if not existing:
                    permission = Permission(
                        name=perm_data['name'],
                        display_name=perm_data['display_name'],
                        module=perm_data['module'],
                        description=perm_data['description']
                    )
                    db.session.add(permission)
            db.session.commit()
            logger.info("权限初始化完成")
            return True
        except Exception as e:
            logger.error(f"权限初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def init_roles():
        """初始化默认角色"""
        try:
            # 创建超级管理员角色（拥有所有权限）
            admin_role = Role.query.filter_by(name='admin').first()
            if not admin_role:
                admin_role = Role(
                    name='admin',
                    description='系统管理员，拥有所有权限',
                    is_system=True
                )
                db.session.add(admin_role)
                db.session.flush()

                # 分配所有权限给管理员
                all_permissions = Permission.query.all()
                admin_role.permissions = all_permissions

            # 创建操作员角色（只读权限）
            operator_role = Role.query.filter_by(name='operator').first()
            if not operator_role:
                operator_role = Role(
                    name='operator',
                    description='系统操作员，只读权限',
                    is_system=True
                )
                db.session.add(operator_role)
                db.session.flush()

                # 分配只读权限
                view_permissions = Permission.query.filter(
                    Permission.name.like('%.view')
                ).all()
                operator_role.permissions = view_permissions

            # 创建普通用户角色（基础权限）
            user_role = Role.query.filter_by(name='user').first()
            if not user_role:
                user_role = Role(
                    name='user',
                    description='普通用户，基础权限',
                    is_system=True
                )
                db.session.add(user_role)
                db.session.flush()

                # 分配基础只读权限
                basic_view_perms = Permission.query.filter(
                    Permission.name.in_([
                        'monitor.view',
                        'threat.view',
                        'alert.view',
                        'defense.view'
                    ])
                ).all()
                user_role.permissions = basic_view_perms

            db.session.commit()
            logger.info("角色初始化完成")
            return True
        except Exception as e:
            logger.error(f"角色初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def get_module_permissions(module_name):
        """获取指定模块的所有权限"""
        try:
            return Permission.query.filter_by(module=module_name).all()
        except Exception as e:
            logger.error(f"获取模块权限失败: {str(e)}")
            return []
