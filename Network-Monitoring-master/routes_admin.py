#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
后台管理路由
提供所有后台管理功能的API接口
"""

from flask import Blueprint, render_template, jsonify, request, url_for
from flask_login import login_required, current_user
from models_admin import db, User, Role, Permission, LoginLog, OperationLog, SystemLog
from modules.admin.permissions import permission_required, admin_required
from modules.admin.admin_service import UserService, RoleService, LogService
from modules.admin.log_service import OperationLogger
from datetime import datetime, timedelta
import logging
import time

logger = logging.getLogger(__name__)

# 创建蓝图
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# Admin首页重定向
@admin_bp.route('/')
@login_required
def admin_index():
    """后台管理首页 - 检查权限后重定向"""
    from flask import flash

    # 检查是否是管理员
    is_admin = False
    if hasattr(current_user, 'is_admin'):
        is_admin = current_user.is_admin()
    elif hasattr(current_user, 'role'):
        if isinstance(current_user.role, str):
            is_admin = current_user.role == 'admin'
        elif hasattr(current_user.role, 'name'):
            is_admin = current_user.role.name == 'admin'

    if not is_admin:
        flash('您无此权限，仅管理员可访问后台管理', 'error')
        return redirect(url_for('index'))

    from flask import redirect
    return redirect(url_for('admin.console'))


# ==================== 页面路由 ====================

@admin_bp.route('/console')
@login_required
@admin_required
def console():
    """控制台页面"""
    return render_template('admin/console.html')


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """用户管理页面"""
    return render_template('admin/users.html')


@admin_bp.route('/roles')
@login_required
@admin_required
def roles():
    """角色管理页面"""
    return render_template('admin/roles.html')


@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    """日志管理页面"""
    return render_template('admin/logs.html')


@admin_bp.route('/monitor')
@login_required
@admin_required
def monitor():
    """监控管理页面"""
    return render_template('admin/monitor.html')


@admin_bp.route('/threats')
@login_required
@admin_required
def threats():
    """威胁检测管理页面"""
    return render_template('admin/threats.html')


@admin_bp.route('/alerts')
@login_required
@admin_required
def alerts():
    """告警管理页面"""
    return render_template('admin/alerts.html')


@admin_bp.route('/defense')
@login_required
@admin_required
def defense():
    """防御管理页面"""
    return render_template('admin/defense.html')


@admin_bp.route('/settings')
@login_required
@admin_required
def settings():
    """系统设置页面"""
    return render_template('admin/settings.html')


# ==================== API: 控制台 ====================

@admin_bp.route('/api/console/stats')
@login_required
@admin_required
def console_stats():
    """获取控制台统计数据"""
    try:
        # 今日告警数
        today = datetime.utcnow().date()
        from models_admin import AlertRecord
        today_alerts = AlertRecord.query.filter(
            db.func.date(AlertRecord.created_at) == today
        ).count()

        # 活跃威胁数（被封禁的IP）
        from models_admin import BlockedIP
        active_threats = BlockedIP.query.filter_by(is_active=True).count()

        # 获取系统运行时间
        import psutil
        import os
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        system_uptime = f'{days}天 {hours}小时'

        # CPU、内存、磁盘使用率
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent

        stats = {
            'today_alerts': today_alerts,  # 今日告警
            'active_threats': active_threats,  # 活跃威胁
            'total_users': User.query.count(),
            'active_users': User.query.filter_by(is_active=True).count(),
            'total_roles': Role.query.count(),
            'system_uptime': system_uptime,  # 系统运行时长
            'cpu_usage': cpu_usage,  # CPU使用率
            'memory_usage': memory_usage,  # 内存使用率
            'disk_usage': disk_usage,  # 磁盘使用率
        }

        return jsonify({'success': True, 'data': stats})

    except Exception as e:
        logger.error(f"获取控制台统计失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/console/trends')
@login_required
@admin_required
def console_trends():
    """获取流量趋势数据"""
    try:
        from models_admin import AlertRecord, BlockedIP
        from sqlalchemy import func

        # 生成最近24小时的趋势数据
        trends = []
        now = datetime.utcnow()

        for i in range(24):
            hour = now - timedelta(hours=23-i)
            hour_start = hour.replace(minute=0, second=0, microsecond=0)
            hour_end = hour_start + timedelta(hours=1)

            # 获取该小时的告警数
            alerts = AlertRecord.query.filter(
                AlertRecord.created_at >= hour_start,
                AlertRecord.created_at < hour_end
            ).count()

            # 获取该小时新增的封禁IP数
            blocked_ips = BlockedIP.query.filter(
                BlockedIP.blocked_at >= hour_start,
                BlockedIP.blocked_at < hour_end
            ).count()

            # 模拟流量数据（实际应从流量统计表获取）
            import random
            traffic_in = random.randint(100000, 5000000)
            traffic_out = random.randint(50000, 2000000)

            trends.append({
                'timestamp': hour.isoformat(),
                'traffic_in': traffic_in,
                'traffic_out': traffic_out,
                'threats': alerts + blocked_ips
            })

        return jsonify({'success': True, 'data': trends})

    except Exception as e:
        logger.error(f"获取趋势数据失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 用户管理 ====================

@admin_bp.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    """获取用户列表"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search')
        role_id = request.args.get('role_id', type=int)
        is_active = request.args.get('is_active', type=str)

        # 转换is_active
        if is_active is not None:
            is_active = is_active.lower() == 'true'

        users, total = UserService.get_users(
            page=page,
            per_page=per_page,
            search=search,
            role_id=role_id,
            is_active=is_active
        )

        return jsonify({
            'success': True,
            'data': {
                'users': [u.to_dict() for u in users],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取用户列表失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
    """获取用户详情"""
    try:
        user = UserService.get_user_by_id(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        return jsonify({'success': True, 'data': user.to_dict()})

    except Exception as e:
        logger.error(f"获取用户详情失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    """创建用户"""
    try:
        data = request.get_json()

        success, user, message = UserService.create_user(
            username=data.get('username'),
            email=data.get('email'),
            password=data.get('password'),
            role_id=data.get('role_id'),
            created_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'data': user.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"创建用户失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
    """更新用户"""
    try:
        data = request.get_json()

        success, message = UserService.update_user(
            user_id=user_id,
            email=data.get('email'),
            role_id=data.get('role_id'),
            is_active=data.get('is_active'),
            updated_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新用户失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    """删除用户"""
    try:
        success, message = UserService.delete_user(
            user_id=user_id,
            deleted_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除用户失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    """重置用户密码"""
    try:
        data = request.get_json()
        new_password = data.get('new_password')

        if not new_password:
            return jsonify({'success': False, 'message': '请提供新密码'}), 400

        success, message = UserService.reset_password(
            user_id=user_id,
            new_password=new_password,
            reset_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"重置密码失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/users/<int:user_id>/login_logs', methods=['GET'])
@login_required
@admin_required
def get_user_login_logs(user_id):
    """获取用户登录日志"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        logs, total = UserService.get_login_logs(
            user_id=user_id,
            page=page,
            per_page=per_page
        )

        return jsonify({
            'success': True,
            'data': {
                'logs': [log.to_dict() for log in logs],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取登录日志失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 角色管理 ====================

@admin_bp.route('/api/roles', methods=['GET'])
@login_required
@admin_required
def get_roles():
    """获取角色列表"""
    try:
        include_system = request.args.get('include_system', 'false').lower() == 'true'
        roles = RoleService.get_roles(include_system=include_system)

        return jsonify({
            'success': True,
            'data': [r.to_dict() for r in roles]
        })

    except Exception as e:
        logger.error(f"获取角色列表失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/roles/<int:role_id>', methods=['GET'])
@login_required
@admin_required
def get_role(role_id):
    """获取角色详情"""
    try:
        role = RoleService.get_role_by_id(role_id)
        if not role:
            return jsonify({'success': False, 'message': '角色不存在'}), 404

        return jsonify({'success': True, 'data': role.to_dict()})

    except Exception as e:
        logger.error(f"获取角色详情失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/roles', methods=['POST'])
@login_required
@admin_required
def create_role():
    """创建角色"""
    try:
        data = request.get_json()

        success, role, message = RoleService.create_role(
            name=data.get('name'),
            description=data.get('description'),
            permission_ids=data.get('permission_ids'),
            created_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'data': role.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"创建角色失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/roles/<int:role_id>', methods=['PUT'])
@login_required
@admin_required
def update_role(role_id):
    """更新角色"""
    try:
        data = request.get_json()

        success, message = RoleService.update_role(
            role_id=role_id,
            name=data.get('name'),
            description=data.get('description'),
            permission_ids=data.get('permission_ids'),
            updated_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新角色失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/roles/<int:role_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_role(role_id):
    """删除角色"""
    try:
        success, message = RoleService.delete_role(
            role_id=role_id,
            deleted_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除角色失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/permissions', methods=['GET'])
@login_required
@admin_required
def get_permissions():
    """获取所有权限（按模块分组）"""
    try:
        permissions = Permission.query.order_by(Permission.module, Permission.id).all()

        # 按模块分组
        grouped = {}
        for perm in permissions:
            if perm.module not in grouped:
                grouped[perm.module] = []
            grouped[perm.module].append(perm.to_dict())

        return jsonify({
            'success': True,
            'data': grouped
        })

    except Exception as e:
        logger.error(f"获取权限列表失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 日志管理 ====================

@admin_bp.route('/api/logs/operation', methods=['GET'])
@login_required
@admin_required
def get_operation_logs():
    """获取操作日志"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        module = request.args.get('module')
        action = request.args.get('action')
        user_id = request.args.get('user_id', type=int)

        logs, total = LogService.get_operation_logs(
            page=page,
            per_page=per_page,
            module=module,
            action=action,
            user_id=user_id
        )

        return jsonify({
            'success': True,
            'data': {
                'logs': [log.to_dict() for log in logs],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取操作日志失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/logs/system', methods=['GET'])
@login_required
@admin_required
def get_system_logs():
    """获取系统日志"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        level = request.args.get('level')
        module = request.args.get('module')

        logs, total = LogService.get_system_logs(
            page=page,
            per_page=per_page,
            level=level,
            module=module
        )

        return jsonify({
            'success': True,
            'data': {
                'logs': [log.to_dict() for log in logs],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取系统日志失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/logs/delete_old', methods=['POST'])
@login_required
@admin_required
def delete_old_logs():
    """删除旧日志"""
    try:
        data = request.get_json()
        log_type = data.get('log_type', 'operation')
        days = data.get('days', 90)

        success, count, message = LogService.delete_old_logs(
            log_type=log_type,
            days=days
        )

        if success:
            return jsonify({'success': True, 'message': message, 'count': count})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除旧日志失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/logs/login', methods=['GET'])
@login_required
@admin_required
def get_login_logs():
    """获取登录日志"""
    try:
        from models_admin import LoginLog
        from sqlalchemy import or_

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search')
        status = request.args.get('status')

        query = LoginLog.query

        if search:
            query = query.filter(LoginLog.username.contains(search))

        if status:
            query = query.filter_by(status=status)

        # 只返回最近30天的记录
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(days=30)
        query = query.filter(LoginLog.login_time >= since)

        pagination = query.order_by(LoginLog.login_time.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return jsonify({
            'success': True,
            'data': {
                'logs': [log.to_dict() for log in pagination.items],
                'total': pagination.total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取登录日志失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 系统初始化 ====================

@admin_bp.route('/api/init/permissions', methods=['POST'])
@login_required
@admin_required
def init_permissions():
    """初始化权限数据"""
    try:
        success = PermissionManager.init_permissions()
        if success:
            return jsonify({'success': True, 'message': '权限初始化成功'})
        else:
            return jsonify({'success': False, 'message': '权限初始化失败'}), 500
    except Exception as e:
        logger.error(f"初始化权限失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/init/roles', methods=['POST'])
@login_required
@admin_required
def init_roles():
    """初始化角色数据"""
    try:
        success = PermissionManager.init_roles()
        if success:
            return jsonify({'success': True, 'message': '角色初始化成功'})
        else:
            return jsonify({'success': False, 'message': '角色初始化失败'}), 500
    except Exception as e:
        logger.error(f"初始化角色失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 监控管理 ====================

@admin_bp.route('/api/monitor/configs', methods=['GET'])
@login_required
@admin_required
def get_monitor_configs():
    """获取监控配置"""
    try:
        from modules.admin.monitor_service import MonitorConfigService
        category = request.args.get('category')
        configs = MonitorConfigService.get_configs(category=category)
        return jsonify({
            'success': True,
            'data': [c.to_dict() for c in configs]
        })
    except Exception as e:
        logger.error(f"获取监控配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/configs/<key>', methods=['PUT'])
@login_required
@admin_required
def update_monitor_config(key):
    """更新监控配置"""
    try:
        from modules.admin.monitor_service import MonitorConfigService
        data = request.get_json()
        value = data.get('value')

        success, message = MonitorConfigService.update_config(
            key=key,
            value=value,
            updated_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新监控配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/interfaces', methods=['GET'])
@login_required
@admin_required
def get_monitor_interfaces():
    """获取网卡列表"""
    try:
        from modules.admin.monitor_service import NetworkInterfaceService

        # 同步系统网卡
        NetworkInterfaceService.sync_interfaces()

        interfaces = NetworkInterfaceService.get_interfaces()
        return jsonify({
            'success': True,
            'data': [i.to_dict() for i in interfaces]
        })

    except Exception as e:
        logger.error(f"获取网卡列表失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/interfaces/<int:interface_id>/monitor', methods=['POST'])
@login_required
@admin_required
def set_monitoring_interface(interface_id):
    """设置监控网卡"""
    try:
        from modules.admin.monitor_service import NetworkInterfaceService

        data = request.get_json()
        is_monitoring = data.get('is_monitoring', True) if data else True

        success, message = NetworkInterfaceService.set_monitoring_interface(
            interface_id=interface_id,
            is_monitoring=is_monitoring,
            updated_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"设置监控网卡失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/protocols', methods=['GET'])
@login_required
@admin_required
def get_protocol_configs():
    """获取协议配置"""
    try:
        from modules.admin.monitor_service import ProtocolConfigService

        protocols = ProtocolConfigService.get_protocols()
        return jsonify({
            'success': True,
            'data': [p.to_dict() for p in protocols]
        })

    except Exception as e:
        logger.error(f"获取协议配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/protocols/<int:protocol_id>', methods=['PUT'])
@login_required
@admin_required
def update_protocol_config(protocol_id):
    """更新协议配置"""
    try:
        from modules.admin.monitor_service import ProtocolConfigService

        data = request.get_json()
        success, message = ProtocolConfigService.update_protocol(
            protocol_id=protocol_id,
            is_enabled=data.get('is_enabled'),
            port_range=data.get('port_range'),
            inspection_level=data.get('inspection_level')
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新协议配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/whitelist', methods=['GET'])
@login_required
@admin_required
def get_ip_whitelist():
    """获取IP白名单"""
    try:
        from modules.admin.monitor_service import IPWhitelistService

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search')

        whitelist, total = IPWhitelistService.get_whitelist(
            page=page,
            per_page=per_page,
            search=search
        )

        return jsonify({
            'success': True,
            'data': {
                'whitelist': [w.to_dict() for w in whitelist],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取白名单失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/whitelist', methods=['POST'])
@login_required
@admin_required
def add_to_whitelist():
    """添加到白名单"""
    try:
        from modules.admin.monitor_service import IPWhitelistService

        data = request.get_json()
        success, message = IPWhitelistService.add_to_whitelist(
            ip_address=data.get('ip_address'),
            description=data.get('description'),
            ip_range=data.get('ip_range'),
            expires_at=None,  # TODO: 解析expires_at
            added_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"添加白名单失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/whitelist/<int:whitelist_id>', methods=['DELETE'])
@login_required
@admin_required
def remove_from_whitelist(whitelist_id):
    """从白名单移除"""
    try:
        from modules.admin.monitor_service import IPWhitelistService

        success, message = IPWhitelistService.remove_from_whitelist(
            whitelist_id=whitelist_id,
            removed_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"移除白名单失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/traffic/stats', methods=['GET'])
@login_required
@admin_required
def get_traffic_stats():
    """获取流量统计"""
    try:
        from modules.admin.monitor_service import TrafficStatsService

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        source_ip = request.args.get('source_ip')
        protocol = request.args.get('protocol')
        is_threat = request.args.get('is_threat')

        stats, total = TrafficStatsService.get_stats(
            page=page,
            per_page=per_page,
            source_ip=source_ip,
            protocol=protocol,
            is_threat=is_threat
        )

        return jsonify({
            'success': True,
            'data': {
                'stats': [s.to_dict() for s in stats],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取流量统计失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/traffic/summary', methods=['GET'])
@login_required
@admin_required
def get_traffic_summary():
    """获取流量汇总统计"""
    try:
        from modules.admin.monitor_service import TrafficStatsService

        summary = TrafficStatsService.get_summary_stats()
        return jsonify({
            'success': True,
            'data': summary
        })

    except Exception as e:
        logger.error(f"获取流量汇总失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/traffic/cleanup', methods=['POST'])
@login_required
@admin_required
def cleanup_traffic_data():
    """清理流量数据"""
    try:
        from modules.admin.monitor_service import TrafficStatsService

        data = request.get_json()
        cleanup_type = data.get('cleanup_type', 'before_date')
        days = data.get('days', 30)

        success, count, message = TrafficStatsService.cleanup_old_records(
            cleanup_type=cleanup_type,
            days=days,
            created_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message, 'count': count})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"清理流量数据失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/monitor/init', methods=['POST'])
@login_required
@admin_required
def init_monitor_data():
    """初始化监控数据"""
    try:
        from modules.admin.monitor_service import MonitorConfigService, ProtocolConfigService

        results = []

        # 初始化监控配置
        if MonitorConfigService.init_configs():
            results.append('监控配置初始化成功')
        else:
            results.append('监控配置初始化失败')

        # 初始化协议配置
        if ProtocolConfigService.init_protocols():
            results.append('协议配置初始化成功')
        else:
            results.append('协议配置初始化失败')

        return jsonify({
            'success': True,
            'message': ' | '.join(results)
        })

    except Exception as e:
        logger.error(f"初始化监控数据失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 威胁检测管理 ====================

@admin_bp.route('/api/threat/records', methods=['GET'])
@login_required
@admin_required
def get_threat_records():
    """获取威胁记录"""
    try:
        from modules.admin.threat_service import ThreatRecordService

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        threat_type = request.args.get('threat_type')
        severity = request.args.get('severity')

        records, total = ThreatRecordService.get_threat_records(
            page=page,
            per_page=per_page,
            threat_type=threat_type,
            severity=severity
        )

        return jsonify({
            'success': True,
            'data': {
                'records': records,
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取威胁记录失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/stats', methods=['GET'])
@login_required
@admin_required
def get_threat_stats():
    """获取威胁统计"""
    try:
        from modules.admin.threat_service import ThreatRecordService

        stats = ThreatRecordService.get_threat_stats()
        return jsonify({
            'success': True,
            'data': stats
        })

    except Exception as e:
        logger.error(f"获取威胁统计失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/rules', methods=['GET'])
@login_required
@admin_required
def get_detection_rules():
    """获取检测规则"""
    try:
        from modules.admin.threat_service import DetectionRuleService

        rules = DetectionRuleService.get_rules()
        return jsonify({
            'success': True,
            'data': [r.to_dict() for r in rules]
        })

    except Exception as e:
        logger.error(f"获取检测规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/rules', methods=['POST'])
@login_required
@admin_required
def create_detection_rule():
    """创建检测规则"""
    try:
        from modules.admin.threat_service import DetectionRuleService

        data = request.get_json()
        success, rule, message = DetectionRuleService.create_rule(
            name=data.get('name'),
            rule_type=data.get('rule_type'),
            condition=data.get('condition'),
            action=data.get('action'),
            severity=data.get('severity'),
            created_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'data': rule.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"创建检测规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/rules/<int:rule_id>', methods=['PUT'])
@login_required
@admin_required
def update_detection_rule(rule_id):
    """更新检测规则"""
    try:
        from modules.admin.threat_service import DetectionRuleService

        data = request.get_json()
        success, message = DetectionRuleService.update_rule(
            rule_id=rule_id,
            name=data.get('name'),
            condition=data.get('condition'),
            action=data.get('action'),
            severity=data.get('severity'),
            is_enabled=data.get('is_enabled')
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新检测规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/rules/<int:rule_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_detection_rule(rule_id):
    """删除检测规则"""
    try:
        from modules.admin.threat_service import DetectionRuleService

        success, message = DetectionRuleService.delete_rule(rule_id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除检测规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/handle/<int:threat_id>', methods=['POST'])
@login_required
@admin_required
def handle_threat(threat_id):
    """处置威胁"""
    try:
        from modules.admin.threat_service import ThreatHandlerService

        data = request.get_json()
        action = data.get('action')
        notes = data.get('notes')

        success, message = ThreatHandlerService.handle_threat(
            threat_id=threat_id,
            action=action,
            notes=notes,
            handled_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"处置威胁失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/model/info', methods=['GET'])
@login_required
@admin_required
def get_model_info():
    """获取模型信息"""
    try:
        from modules.admin.threat_service import ModelManagementService

        info = ModelManagementService.get_model_info()
        return jsonify({
            'success': True,
            'data': info
        })

    except Exception as e:
        logger.error(f"获取模型信息失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/model/params', methods=['GET'])
@login_required
@admin_required
def get_model_params():
    """获取模型参数"""
    try:
        from modules.admin.threat_service import ModelManagementService

        params = ModelManagementService.get_model_params()
        return jsonify({
            'success': True,
            'data': params
        })

    except Exception as e:
        logger.error(f"获取模型参数失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/model/retrain', methods=['POST'])
@login_required
@admin_required
def retrain_model():
    """重新训练模型"""
    try:
        from modules.admin.threat_service import ModelManagementService

        data = request.get_json()
        train_data_path = data.get('train_data_path')

        success, message = ModelManagementService.retrain_model(train_data_path)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"重新训练模型失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/threat/init', methods=['POST'])
@login_required
@admin_required
def init_threat_data():
    """初始化威胁检测数据"""
    try:
        from modules.admin.threat_service import DetectionRuleService

        if DetectionRuleService.init_rules():
            return jsonify({
                'success': True,
                'message': '检测规则初始化成功'
            })
        else:
            return jsonify({
                'success': False,
                'message': '检测规则初始化失败'
            }), 500

    except Exception as e:
        logger.error(f"初始化威胁数据失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 告警管理 ====================

@admin_bp.route('/api/alert/rules', methods=['GET'])
@login_required
@admin_required
def get_alert_rules():
    """获取告警规则"""
    try:
        from modules.admin.alert_service import AlertRuleService

        rules = AlertRuleService.get_alert_rules()
        return jsonify({
            'success': True,
            'data': [r.to_dict() for r in rules]
        })

    except Exception as e:
        logger.error(f"获取告警规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/rules', methods=['POST'])
@login_required
@admin_required
def create_alert_rule():
    """创建告警规则"""
    try:
        from modules.admin.alert_service import AlertRuleService

        data = request.get_json()
        success, rule, message = AlertRuleService.create_alert_rule(
            name=data.get('name'),
            metric=data.get('metric'),
            condition=data.get('condition'),
            threshold=data.get('threshold'),
            severity=data.get('severity'),
            silence_duration=data.get('silence_duration', 0),
            created_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'data': rule.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"创建告警规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/rules/<int:rule_id>', methods=['PUT'])
@login_required
@admin_required
def update_alert_rule(rule_id):
    """更新告警规则"""
    try:
        from modules.admin.alert_service import AlertRuleService

        data = request.get_json()
        success, message = AlertRuleService.update_alert_rule(
            rule_id=rule_id,
            name=data.get('name'),
            threshold=data.get('threshold'),
            severity=data.get('severity'),
            is_enabled=data.get('is_enabled'),
            silence_duration=data.get('silence_duration')
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新告警规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/rules/<int:rule_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_alert_rule(rule_id):
    """删除告警规则"""
    try:
        from modules.admin.alert_service import AlertRuleService

        success, message = AlertRuleService.delete_alert_rule(rule_id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除告警规则失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/records', methods=['GET'])
@login_required
@admin_required
def get_alert_records():
    """获取告警记录"""
    try:
        from modules.admin.alert_service import AlertRecordService

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        severity = request.args.get('severity')
        status = request.args.get('status')

        records, total = AlertRecordService.get_alert_records(
            page=page,
            per_page=per_page,
            severity=severity,
            status=status
        )

        return jsonify({
            'success': True,
            'data': {
                'records': [r.to_dict() for r in records],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取告警记录失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/records/<int:alert_id>/confirm', methods=['POST'])
@login_required
@admin_required
def confirm_alert(alert_id):
    """确认告警"""
    try:
        from modules.admin.alert_service import AlertRecordService

        success, message = AlertRecordService.confirm_alert(alert_id, current_user.id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"确认告警失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/records/<int:alert_id>/resolve', methods=['POST'])
@login_required
@admin_required
def resolve_alert(alert_id):
    """解决告警"""
    try:
        from modules.admin.alert_service import AlertRecordService

        success, message = AlertRecordService.resolve_alert(alert_id, current_user.id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"解决告警失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/recipients', methods=['GET'])
@login_required
@admin_required
def get_alert_recipients():
    """获取告警接收人"""
    try:
        from modules.admin.alert_service import NotificationService

        recipients = NotificationService.get_recipients()
        return jsonify({
            'success': True,
            'data': [r.to_dict() for r in recipients]
        })

    except Exception as e:
        logger.error(f"获取告警接收人失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/recipients', methods=['POST'])
@login_required
@admin_required
def add_alert_recipient():
    """添加告警接收人"""
    try:
        from modules.admin.alert_service import NotificationService

        data = request.get_json()
        success, recipient, message = NotificationService.add_recipient(
            name=data.get('name'),
            email=data.get('email'),
            dingtalk_webhook=data.get('dingtalk_webhook'),
            wechat_webhook=data.get('wechat_webhook')
        )

        if success:
            return jsonify({'success': True, 'data': recipient.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"添加告警接收人失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/recipients/<int:recipient_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_alert_recipient(recipient_id):
    """删除告警接收人"""
    try:
        from modules.admin.alert_service import NotificationService

        success, message = NotificationService.delete_recipient(recipient_id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除告警接收人失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/stats', methods=['GET'])
@login_required
@admin_required
def get_alert_stats():
    """获取告警统计"""
    try:
        from models_admin import AlertRecord
        from sqlalchemy import func
        from datetime import datetime, timedelta

        # 今日告警数
        today = datetime.utcnow().date()
        today_alerts = AlertRecord.query.filter(
            db.func.date(AlertRecord.created_at) == today
        ).count()

        # 按状态统计
        status_stats = db.session.query(
            AlertRecord.status,
            func.count(AlertRecord.id).label('count')
        ).group_by(AlertRecord.status).all()

        stats = {
            'today_alerts': today_alerts,
            'pending': 0,
            'confirmed': 0,
            'resolved': 0,
            'ignored': 0
        }

        for status, count in status_stats:
            if status in stats:
                stats[status] = count

        return jsonify({
            'success': True,
            'data': stats
        })

    except Exception as e:
        logger.error(f"获取告警统计失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/alert/init', methods=['POST'])
@login_required
@admin_required
def init_alert_data():
    """初始化告警数据"""
    try:
        from modules.admin.alert_service import AlertRuleService

        if AlertRuleService.init_alert_rules():
            return jsonify({
                'success': True,
                'message': '告警规则初始化成功'
            })
        else:
            return jsonify({
                'success': False,
                'message': '告警规则初始化失败'
            }), 500

    except Exception as e:
        logger.error(f"初始化告警数据失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 防御管理 ====================

@admin_bp.route('/api/defense/blocked_ips', methods=['GET'])
@login_required
@admin_required
def get_blocked_ips():
    """获取封禁IP列表"""
    try:
        from modules.admin.defense_service import IPBlockService

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        ip_address = request.args.get('ip_address')
        threat_type = request.args.get('threat_type')
        is_active = request.args.get('is_active')

        if is_active is not None:
            is_active = is_active.lower() == 'true'

        ips, total = IPBlockService.get_blocked_ips(
            page=page,
            per_page=per_page,
            ip_address=ip_address,
            threat_type=threat_type,
            is_active=is_active
        )

        return jsonify({
            'success': True,
            'data': {
                'ips': [ip.to_dict() for ip in ips],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取封禁IP列表失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/block_ip', methods=['POST'])
@login_required
@admin_required
def block_ip():
    """封禁IP"""
    try:
        from modules.admin.defense_service import IPBlockService

        data = request.get_json()
        success, blocked_ip, message = IPBlockService.block_ip(
            ip_address=data.get('ip_address'),
            reason=data.get('reason'),
            threat_type=data.get('threat_type', 'manual'),
            blocked_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'data': blocked_ip.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"封禁IP失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/unblock_ip/<int:block_id>', methods=['POST'])
@login_required
@admin_required
def unblock_ip(block_id):
    """解封IP"""
    try:
        from modules.admin.defense_service import IPBlockService

        data = request.get_json()
        success, message = IPBlockService.unblock_ip(
            block_id=block_id,
            unblock_reason=data.get('unblock_reason'),
            unblocked_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"解封IP失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/batch_unblock', methods=['POST'])
@login_required
@admin_required
def batch_unblock_ips():
    """批量解封IP"""
    try:
        from modules.admin.defense_service import IPBlockService

        data = request.get_json()
        block_ids = data.get('block_ids', [])

        success, message = IPBlockService.batch_unblock_ip(
            block_ids=block_ids,
            unblocked_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"批量解封IP失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/policies', methods=['GET'])
@login_required
@admin_required
def get_defense_policies():
    """获取防御策略列表"""
    try:
        from modules.admin.defense_service import DefensePolicyService

        policies = DefensePolicyService.get_policies()
        return jsonify({
            'success': True,
            'data': [p.to_dict() for p in policies]
        })

    except Exception as e:
        logger.error(f"获取防御策略失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/policies', methods=['POST'])
@login_required
@admin_required
def create_defense_policy():
    """创建防御策略"""
    try:
        from modules.admin.defense_service import DefensePolicyService

        data = request.get_json()
        success, policy, message = DefensePolicyService.create_policy(
            name=data.get('name'),
            policy_type=data.get('policy_type'),
            condition=data.get('condition'),
            action=data.get('action'),
            duration=data.get('duration'),
            severity=data.get('severity', 'medium'),
            created_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'data': policy.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"创建防御策略失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/policies/<int:policy_id>', methods=['PUT'])
@login_required
@admin_required
def update_defense_policy(policy_id):
    """更新防御策略"""
    try:
        from modules.admin.defense_service import DefensePolicyService

        data = request.get_json()
        success, message = DefensePolicyService.update_policy(
            policy_id=policy_id,
            name=data.get('name'),
            condition=data.get('condition'),
            action=data.get('action'),
            severity=data.get('severity'),
            is_enabled=data.get('is_enabled')
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新防御策略失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/policies/<int:policy_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_defense_policy(policy_id):
    """删除防御策略"""
    try:
        from modules.admin.defense_service import DefensePolicyService

        success, message = DefensePolicyService.delete_policy(policy_id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除防御策略失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/execution_logs', methods=['GET'])
@login_required
@admin_required
def get_defense_execution_logs():
    """获取防御执行日志"""
    try:
        from modules.admin.defense_service import DefenseExecutionService

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        action = request.args.get('action')

        logs, total = DefenseExecutionService.get_execution_logs(
            page=page,
            per_page=per_page,
            action=action
        )

        return jsonify({
            'success': True,
            'data': {
                'logs': [log.to_dict() for log in logs],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取防御执行日志失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/execution_stats', methods=['GET'])
@login_required
@admin_required
def get_defense_execution_stats():
    """获取防御执行统计"""
    try:
        from modules.admin.defense_service import DefenseExecutionService

        stats = DefenseExecutionService.get_execution_stats()
        return jsonify({
            'success': True,
            'data': stats
        })

    except Exception as e:
        logger.error(f"获取防御执行统计失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/defense/init', methods=['POST'])
@login_required
@admin_required
def init_defense_data():
    """初始化防御数据"""
    try:
        from modules.admin.defense_service import DefensePolicyService

        if DefensePolicyService.init_policies():
            return jsonify({
                'success': True,
                'message': '防御策略初始化成功'
            })
        else:
            return jsonify({
                'success': False,
                'message': '防御策略初始化失败'
            }), 500

    except Exception as e:
        logger.error(f"初始化防御数据失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== API: 系统管理 ====================

@admin_bp.route('/api/system/configs', methods=['GET'])
@login_required
@admin_required
def get_system_configs():
    """获取系统配置"""
    try:
        from modules.admin.system_service import SystemConfigService

        configs = SystemConfigService.get_all_configs()
        return jsonify({
            'success': True,
            'data': configs
        })

    except Exception as e:
        logger.error(f"获取系统配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/configs/<key>', methods=['PUT'])
@login_required
@admin_required
def update_system_config(key):
    """更新系统配置"""
    try:
        from modules.admin.system_service import SystemConfigService

        data = request.get_json()
        value = data.get('value')

        success, message = SystemConfigService.set_config(
            key=key,
            value=value
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新系统配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/configs/batch', methods=['PUT'])
@login_required
@admin_required
def batch_update_system_configs():
    """批量更新系统配置"""
    try:
        from modules.admin.system_service import SystemConfigService

        data = request.get_json()
        configs = data.get('configs', {})

        success, message = SystemConfigService.batch_set_configs(configs)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"批量更新系统配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/configs/reset', methods=['POST'])
@login_required
@admin_required
def reset_system_configs():
    """重置系统配置"""
    try:
        from modules.admin.system_service import SystemConfigService

        success, message = SystemConfigService.reset_to_default()

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"重置系统配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/mail/config', methods=['GET'])
@login_required
@admin_required
def get_mail_config():
    """获取邮件配置"""
    try:
        from modules.admin.system_service import MailConfigService

        config = MailConfigService.get_mail_config()
        return jsonify({
            'success': True,
            'data': config
        })

    except Exception as e:
        logger.error(f"获取邮件配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/mail/config', methods=['PUT'])
@login_required
@admin_required
def update_mail_config():
    """更新邮件配置"""
    try:
        from modules.admin.system_service import MailConfigService

        data = request.get_json()
        success, message = MailConfigService.set_mail_config(
            smtp_server=data.get('smtp_server'),
            smtp_port=data.get('smtp_port'),
            username=data.get('username'),
            password=data.get('password'),
            mail_from=data.get('mail_from'),
            use_tls=data.get('use_tls', True),
            enabled=data.get('enabled', False)
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"更新邮件配置失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/mail/test', methods=['POST'])
@login_required
@admin_required
def test_mail():
    """发送测试邮件"""
    try:
        from modules.admin.system_service import MailConfigService

        data = request.get_json()
        to_email = data.get('to_email')

        if not to_email:
            return jsonify({'success': False, 'message': '请提供收件人邮箱'}), 400

        success, message = MailConfigService.send_test_mail(to_email)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"发送测试邮件失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/backups', methods=['GET'])
@login_required
@admin_required
def get_backups():
    """获取备份记录"""
    try:
        from modules.admin.system_service import BackupService

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        backups, total = BackupService.get_backup_records(
            page=page,
            per_page=per_page
        )

        return jsonify({
            'success': True,
            'data': {
                'backups': [b.to_dict() for b in backups],
                'total': total,
                'page': page,
                'per_page': per_page
            }
        })

    except Exception as e:
        logger.error(f"获取备份记录失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/backups', methods=['POST'])
@login_required
@admin_required
def create_backup():
    """创建数据备份"""
    try:
        from modules.admin.system_service import BackupService

        data = request.get_json()
        success, backup, message = BackupService.create_backup(
            description=data.get('description'),
            created_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'data': backup.to_dict(), 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"创建数据备份失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/backups/<int:backup_id>/restore', methods=['POST'])
@login_required
@admin_required
def restore_backup(backup_id):
    """恢复数据备份"""
    try:
        from modules.admin.system_service import BackupService

        success, message = BackupService.restore_backup(
            backup_id=backup_id,
            restored_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"恢复数据备份失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/backups/<int:backup_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_backup(backup_id):
    """删除备份"""
    try:
        from modules.admin.system_service import BackupService

        success, message = BackupService.delete_backup(backup_id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"删除备份失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/maintenance/status', methods=['GET'])
@login_required
@admin_required
def get_maintenance_status():
    """获取维护模式状态"""
    try:
        from modules.admin.system_service import MaintenanceService

        status = MaintenanceService.get_maintenance_status()
        return jsonify({
            'success': True,
            'data': status
        })

    except Exception as e:
        logger.error(f"获取维护模式状态失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/maintenance', methods=['PUT'])
@login_required
@admin_required
def set_maintenance_mode():
    """设置维护模式"""
    try:
        from modules.admin.system_service import MaintenanceService

        data = request.get_json()
        success, message = MaintenanceService.set_maintenance_mode(
            enabled=data.get('enabled', False),
            message=data.get('message'),
            set_by_id=current_user.id
        )

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400

    except Exception as e:
        logger.error(f"设置维护模式失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@admin_bp.route('/api/system/init', methods=['POST'])
@login_required
@admin_required
def init_system_data():
    """初始化系统数据"""
    try:
        from modules.admin.system_service import SystemConfigService

        if SystemConfigService.init_configs():
            return jsonify({
                'success': True,
                'message': '系统配置初始化成功'
            })
        else:
            return jsonify({
                'success': False,
                'message': '系统配置初始化失败'
            }), 500

    except Exception as e:
        logger.error(f"初始化系统数据失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
