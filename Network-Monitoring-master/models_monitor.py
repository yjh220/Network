#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
监控管理数据库模型
包含监控配置、IP黑白名单、流量统计等
"""

from datetime import datetime
import json

# 从models_admin导入db和User，避免循环导入
from models_admin import db, User


class MonitorConfig(db.Model):
    """监控配置模型"""
    __tablename__ = 'monitor_configs'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')  # string, int, float, bool, json
    category = db.Column(db.String(50))  # 配置分类: capture, protocol, storage
    description = db.Column(db.String(200))
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
            self.value = json.dumps(value, ensure_ascii=False)
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
            'description': self.description
        }

    def __repr__(self):
        return f'<MonitorConfig {self.key}>'


class IPWhitelist(db.Model):
    """IP白名单模型"""
    __tablename__ = 'ip_whitelist'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False, unique=True, index=True)
    ip_range = db.Column(db.String(100))  # 支持CIDR格式，如192.168.1.0/24
    description = db.Column(db.String(200))
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    added_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime)  # None表示永久
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # 关联关系
    adder = db.relationship('User', foreign_keys=[added_by])

    def is_expired(self):
        """检查是否过期"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'ip_range': self.ip_range,
            'description': self.description,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }

    def __repr__(self):
        return f'<IPWhitelist {self.ip_address}>'


class TrafficStats(db.Model):
    """流量统计模型"""
    __tablename__ = 'traffic_stats'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    source_ip = db.Column(db.String(50))
    dest_ip = db.Column(db.String(50))
    source_port = db.Column(db.Integer)
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))  # TCP, UDP, ICMP, HTTP
    packet_count = db.Column(db.Integer, default=0)
    byte_count = db.Column(db.BigInteger, default=0)
    duration = db.Column(db.Integer)  # 持续时间（秒）
    is_threat = db.Column(db.Boolean, default=False)
    threat_type = db.Column(db.String(50))

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'protocol': self.protocol,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'duration': self.duration,
            'is_threat': self.is_threat,
            'threat_type': self.threat_type
        }

    def __repr__(self):
        return f'<TrafficStats {self.source_ip}:{self.source_port} -> {self.dest_ip}:{self.dest_port}>'


class NetworkInterface(db.Model):
    """网卡配置模型"""
    __tablename__ = 'network_interfaces'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # 网卡名称，如eth0, wlan0
    display_name = db.Column(db.String(100))  # 显示名称
    ip_address = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    is_monitoring = db.Column(db.Boolean, default=False)  # 是否正在监控
    is_enabled = db.Column(db.Boolean, default=True)  # 是否启用
    capture_filter = db.Column(db.Text)  # 抓包过滤器（BPF语法）
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name or self.name,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'is_monitoring': self.is_monitoring,
            'is_enabled': self.is_enabled,
            'capture_filter': self.capture_filter
        }

    def __repr__(self):
        return f'<NetworkInterface {self.name}>'


class ProtocolConfig(db.Model):
    """协议配置模型"""
    __tablename__ = 'protocol_configs'

    id = db.Column(db.Integer, primary_key=True)
    protocol = db.Column(db.String(20), unique=True, nullable=False)  # TCP, UDP, HTTP, DNS, etc.
    is_enabled = db.Column(db.Boolean, default=True)
    port_range = db.Column(db.String(100))  # 端口范围，如"80,443,8080-8090"
    description = db.Column(db.String(200))
    inspection_level = db.Column(db.String(20), default='basic')  # basic, deep, full
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'protocol': self.protocol,
            'is_enabled': self.is_enabled,
            'port_range': self.port_range,
            'description': self.description,
            'inspection_level': self.inspection_level
        }

    def __repr__(self):
        return f'<ProtocolConfig {self.protocol}>'


class TrafficCleanup(db.Model):
    """流量清理记录模型"""
    __tablename__ = 'traffic_cleanups'

    id = db.Column(db.Integer, primary_key=True)
    cleanup_type = db.Column(db.String(50), nullable=False)  # all, before_date, threat_only
    record_count = db.Column(db.Integer, default=0)
    freed_space = db.Column(db.BigInteger)  # 释放的空间（字节）
    before_date = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # 关联关系
    creator = db.relationship('User', foreign_keys=[created_by])

    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id,
            'cleanup_type': self.cleanup_type,
            'record_count': self.record_count,
            'freed_space': self.freed_space,
            'before_date': self.before_date.isoformat() if self.before_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f'<TrafficCleanup {self.cleanup_type} - {self.created_at}>'
