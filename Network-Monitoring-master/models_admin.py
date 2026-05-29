#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
后台管理数据库模型
包含用户、权限、日志、防御、告警等所有后台管理相关模型
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()


# ==================== 用户与权限模型 ====================

class User(UserMixin, db.Model):
    """用户模型"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(50))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    # 关联关系
    role = db.relationship('Role', back_populates='users')
    login_logs = db.relationship('LoginLog', back_populates='user', cascade='all, delete-orphan')
    operation_logs = db.relationship('OperationLog', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password):
        """设置密码哈希"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        """检查用户是否有指定权限"""
        if self.role and self.role.permissions:
            return any(p.name == permission_name for p in self.role.permissions)
        return False

    def is_locked(self):
        """检查账户是否被锁定"""
        if self.locked_until:
            return datetime.utcnow() < self.locked_until
        return False

    def update_last_login(self, ip_address=None):
        """更新最后登录时间"""
        self.last_login = datetime.utcnow()
        self.last_login_ip = ip_address
        self.failed_login_attempts = 0
        self.locked_until = None
        db.session.commit()

    def increment_failed_attempts(self):
        """增加失败登录次数"""
        self.failed_login_attempts += 1
        # 失败5次锁定30分钟
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role.name if self.role else None,
            'role_id': self.role_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'last_login_ip': self.last_login_ip,
            'is_locked': self.is_locked()
        }

    def __repr__(self):
        return f'<User {self.username} ({self.role.name if self.role else "No Role"})>'


class Role(db.Model):
    """角色模型"""
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    is_system = db.Column(db.Boolean, default=False)  # 系统内置角色不可删除
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 关联关系
    users = db.relationship('User', back_populates='role')
    permissions = db.relationship('Permission', secondary='role_permissions', back_populates='roles')

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_system': self.is_system,
            'permissions': [p.name for p in self.permissions],
            'user_count': len(self.users)
        }

    def __repr__(self):
        return f'<Role {self.name}>'


class Permission(db.Model):
    """权限模型"""
    __tablename__ = 'permissions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    module = db.Column(db.String(50), nullable=False)  # 所属模块
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 关联关系
    roles = db.relationship('Role', secondary='role_permissions', back_populates='permissions')

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name,
            'module': self.module,
            'description': self.description
        }

    def __repr__(self):
        return f'<Permission {self.name}>'


# 角色权限关联表
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)


# ==================== 日志模型 ====================

class LoginLog(db.Model):
    """登录日志模型"""
    __tablename__ = 'login_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=False)  # 即使用户被删除也保留用户名
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    status = db.Column(db.String(20), nullable=False)  # success, failed, blocked
    failure_reason = db.Column(db.String(200))
    login_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # 关联关系
    user = db.relationship('User', back_populates='login_logs')

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'ip_address': self.ip_address,
            'status': self.status,
            'failure_reason': self.failure_reason,
            'login_time': self.login_time.isoformat() if self.login_time else None
        }

    def __repr__(self):
        return f'<LoginLog {self.username} - {self.status}>'


class OperationLog(db.Model):
    """操作日志模型"""
    __tablename__ = 'operation_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    module = db.Column(db.String(50), nullable=False)  # 操作模块
    action = db.Column(db.String(100), nullable=False)  # 操作类型
    resource = db.Column(db.String(100))  # 操作资源
    details = db.Column(db.Text)  # 操作详情（JSON格式）
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(20), default='success')  # success, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # 关联关系
    user = db.relationship('User', back_populates='operation_logs')

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'module': self.module,
            'action': self.action,
            'resource': self.resource,
            'details': json.loads(self.details) if self.details else None,
            'ip_address': self.ip_address,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<OperationLog {self.username} - {self.action}>'


class SystemLog(db.Model):
    """系统日志模型"""
    __tablename__ = 'system_logs'

    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.String(20), nullable=False, index=True)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    module = db.Column(db.String(50), nullable=False, index=True)  # 日志所属模块
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)  # 详细信息（JSON格式）
    file_path = db.Column(db.String(500))  # 代码文件路径
    line_number = db.Column(db.Integer)  # 代码行号
    function = db.Column(db.String(100))  # 函数名
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'level': self.level,
            'module': self.module,
            'message': self.message,
            'details': json.loads(self.details) if self.details else None,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'function': self.function,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<SystemLog [{self.level}] {self.message[:50]}>'


# ==================== 防御模型 ====================

class BlockedIP(db.Model):
    """封禁IP模型"""
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False, unique=True, index=True)
    reason = db.Column(db.String(200))
    threat_type = db.Column(db.String(50))  # DDoS, PortScan等
    source = db.Column(db.String(50))  # manual, auto, rule
    blocked_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime)  # None表示永久封禁
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # 关联关系
    blocker = db.relationship('User', foreign_keys=[blocked_by])

    def is_expired(self):
        """检查封禁是否过期"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'threat_type': self.threat_type,
            'source': self.source,
            'blocked_by': self.blocker,
            'blocked_at': self.blocked_at.isoformat() if self.blocked_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }

    def __repr__(self):
        return f'<BlockedIP {self.ip_address}>'


class DefenseRule(db.Model):
    """防御规则模型"""
    __tablename__ = 'defense_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    rule_type = db.Column(db.String(50), nullable=False)  # auto_block, rate_limit, geo_filter
    condition = db.Column(db.Text, nullable=False)  # 触发条件（JSON格式）
    action = db.Column(db.String(50), nullable=False)  # block, alert, throttle
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    execute_count = db.Column(db.Integer, default=0)  # 执行次数
    last_executed = db.Column(db.DateTime)

    # 关联关系
    creator = db.relationship('User', foreign_keys=[created_by])

    def to_dict(self):
        """转换为字典"""
        # 尝试解析condition字段（可能是JSON或Python字典字符串）
        condition_dict = None
        if self.condition:
            try:
                # 先尝试JSON解析
                condition_dict = json.loads(self.condition)
            except json.JSONDecodeError:
                try:
                    # 如果JSON解析失败，尝试解析Python字典字符串
                    import ast
                    condition_dict = ast.literal_eval(self.condition)
                except (ValueError, SyntaxError):
                    # 如果都失败，直接返回字符串
                    condition_dict = self.condition

        return {
            'id': self.id,
            'name': self.name,
            'rule_type': self.rule_type,
            'condition': condition_dict,
            'action': self.action,
            'severity': self.severity,
            'is_enabled': self.is_enabled,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'execute_count': self.execute_count,
            'last_executed': self.last_executed.isoformat() if self.last_executed else None
        }

    def __repr__(self):
        return f'<DefenseRule {self.name}>'


# ==================== 告警模型 ====================

class AlertRule(db.Model):
    """告警规则模型"""
    __tablename__ = 'alert_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    metric = db.Column(db.String(50), nullable=False)  # 监控指标
    condition = db.Column(db.String(50), nullable=False)  # >, <, =, >=, <=
    threshold = db.Column(db.Float, nullable=False)  # 阈值
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    is_enabled = db.Column(db.Boolean, default=True)
    silence_duration = db.Column(db.Integer, default=0)  # 静默时长（分钟）
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 关联关系
    creator = db.relationship('User', foreign_keys=[created_by])

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'metric': self.metric,
            'condition': self.condition,
            'threshold': self.threshold,
            'severity': self.severity,
            'is_enabled': self.is_enabled,
            'silence_duration': self.silence_duration
        }

    def __repr__(self):
        return f'<AlertRule {self.name}>'


class AlertRecord(db.Model):
    """告警记录模型"""
    __tablename__ = 'alert_records'

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('alert_rules.id'))
    rule_name = db.Column(db.String(100))
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)  # 详细信息（JSON格式）
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, resolved, ignored
    confirmed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    confirmed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # 关联关系
    rule = db.relationship('AlertRule', foreign_keys=[rule_id])
    confirmer = db.relationship('User', foreign_keys=[confirmed_by])

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'message': self.message,
            'details': json.loads(self.details) if self.details else None,
            'status': self.status,
            'confirmed_by': self.confirmed_by,
            'confirmed_at': self.confirmed_at.isoformat() if self.confirmed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<AlertRecord [{self.severity}] {self.message[:30]}>'


class AlertRecipient(db.Model):
    """告警接收人模型"""
    __tablename__ = 'alert_recipients'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    dingtalk_webhook = db.Column(db.String(500))  # 钉钉机器人webhook
    wechat_webhook = db.Column(db.String(500))  # 企业微信webhook
    is_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'dingtalk_webhook': self.dingtalk_webhook,
            'wechat_webhook': self.wechat_webhook,
            'is_enabled': self.is_enabled
        }

    def __repr__(self):
        return f'<AlertRecipient {self.name}>'


# ==================== 系统配置模型 ====================

class SystemConfig(db.Model):
    """系统配置模型"""
    __tablename__ = 'system_configs'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')  # string, int, float, bool, json
    category = db.Column(db.String(50))  # 配置分类
    description = db.Column(db.String(200))
    is_public = db.Column(db.Boolean, default=False)  # 是否可被前端读取
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 关联关系
    updater = db.relationship('User', foreign_keys=[updated_by])

    def get_value(self):
        """获取解析后的值"""
        if self.value_type == 'int':
            return int(self.value) if self.value else None
        elif self.value_type == 'float':
            return float(self.value) if self.value else None
        elif self.value_type == 'bool':
            return self.value.lower() == 'true' if self.value else False
        elif self.value_type == 'json':
            return json.loads(self.value) if self.value else None
        return self.value

    def set_value(self, value):
        """设置值"""
        if self.value_type == 'json':
            self.value = json.dumps(value)
        else:
            self.value = str(value)

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'key': self.key,
            'value': self.get_value(),
            'value_type': self.value_type,
            'category': self.category,
            'description': self.description,
            'is_public': self.is_public
        }

    def __repr__(self):
        return f'<SystemConfig {self.key}>'


class BackupRecord(db.Model):
    """备份记录模型"""
    __tablename__ = 'backup_records'

    id = db.Column(db.Integer, primary_key=True)
    backup_type = db.Column(db.String(50), nullable=False)  # database, files, full
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger)
    status = db.Column(db.String(20), default='success')  # success, failed
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    description = db.Column(db.String(200))

    # 关联关系
    creator = db.relationship('User', foreign_keys=[created_by])

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'backup_type': self.backup_type,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'description': self.description
        }

    def __repr__(self):
        return f'<BackupRecord {self.backup_type} - {self.created_at}>'
