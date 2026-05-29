#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
监控管理服务模块
提供监控配置、IP黑白名单、流量统计等管理功能
"""

from datetime import datetime, timedelta
from models_admin import db, BlockedIP
from models_monitor import (
    MonitorConfig, IPWhitelist, TrafficStats,
    NetworkInterface, ProtocolConfig, TrafficCleanup
)
from modules.admin.log_service import OperationLogger
import logging
import socket

logger = logging.getLogger(__name__)


class MonitorConfigService:
    """监控配置服务"""

    # 预定义配置项
    DEFAULT_CONFIGS = {
        # 抓包配置
        'capture.interface': {'value': 'eth0', 'type': 'string', 'category': 'capture', 'desc': '默认抓包网卡'},
        'capture.buffer_size': {'value': '10485760', 'type': 'int', 'category': 'capture', 'desc': '抓包缓冲区大小（字节）'},
        'capture.snaplen': {'value': '65535', 'type': 'int', 'category': 'capture', 'desc': '抓包长度'},
        'capture.filter': {'value': '', 'type': 'string', 'category': 'capture', 'desc': 'BPF过滤器'},
        'capture.timeout': {'value': '100', 'type': 'int', 'category': 'capture', 'desc': '抓包超时（毫秒）'},

        # 存储配置
        'storage.retention_days': {'value': '30', 'type': 'int', 'category': 'storage', 'desc': '数据保留天数'},
        'storage.max_records': {'value': '1000000', 'type': 'int', 'category': 'storage', 'desc': '最大记录数'},
        'storage.auto_cleanup': {'value': 'true', 'type': 'bool', 'category': 'storage', 'desc': '自动清理过期数据'},
        'storage.cleanup_time': {'value': '03:00', 'type': 'string', 'category': 'storage', 'desc': '每日清理时间'},

        # 分析配置
        'analysis.enable_ml': {'value': 'true', 'type': 'bool', 'category': 'analysis', 'desc': '启用机器学习检测'},
        'analysis.threshold_score': {'value': '0.7', 'type': 'float', 'category': 'analysis', 'desc': '威胁阈值分数'},
        'analysis.auto_block': {'value': 'false', 'type': 'bool', 'category': 'analysis', 'desc': '自动封禁威胁IP'},
    }

    @staticmethod
    def init_configs():
        """初始化默认配置"""
        try:
            for key, config in MonitorConfigService.DEFAULT_CONFIGS.items():
                existing = MonitorConfig.query.filter_by(key=key).first()
                if not existing:
                    monitor_config = MonitorConfig(
                        key=key,
                        value=config['value'],
                        value_type=config['type'],
                        category=config['category'],
                        description=config['desc']
                    )
                    db.session.add(monitor_config)
            db.session.commit()
            logger.info("监控配置初始化完成")
            return True
        except Exception as e:
            logger.error(f"监控配置初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def get_configs(category=None):
        """获取配置列表"""
        try:
            query = MonitorConfig.query
            if category:
                query = query.filter_by(category=category)
            return query.order_by(MonitorConfig.category, MonitorConfig.key).all()
        except Exception as e:
            logger.error(f"获取配置失败: {str(e)}")
            return []

    @staticmethod
    def get_config(key):
        """获取单个配置"""
        try:
            return MonitorConfig.query.filter_by(key=key).first()
        except Exception as e:
            logger.error(f"获取配置失败: {str(e)}")
            return None

    @staticmethod
    def update_config(key, value, updated_by_id=None):
        """更新配置"""
        try:
            config = MonitorConfig.query.filter_by(key=key).first()
            if not config:
                return False, '配置项不存在'

            old_value = config.get_value()
            config.set_value(value)
            config.updated_by = updated_by_id
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='monitor',
                action='update_config',
                resource=f'config:{key}',
                details={'old_value': old_value, 'new_value': value}
            )

            logger.info(f"配置更新成功: {key}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新配置失败: {str(e)}")
            return False, f'更新失败: {str(e)}'


class IPWhitelistService:
    """IP白名单服务"""

    @staticmethod
    def get_whitelist(page=1, per_page=20, search=None):
        """获取白名单列表"""
        try:
            query = IPWhitelist.query

            if search:
                query = query.filter(
                    db.or_(
                        IPWhitelist.ip_address.like(f'%{search}%'),
                        IPWhitelist.ip_range.like(f'%{search}%')
                    )
                )

            pagination = query.order_by(IPWhitelist.added_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取白名单失败: {str(e)}")
            return [], 0

    @staticmethod
    def add_to_whitelist(ip_address, description=None, ip_range=None, expires_at=None, added_by_id=None):
        """添加到白名单"""
        try:
            # 检查是否已存在
            existing = IPWhitelist.query.filter_by(ip_address=ip_address).first()
            if existing:
                return False, 'IP地址已在白名单中'

            whitelist = IPWhitelist(
                ip_address=ip_address,
                ip_range=ip_range,
                description=description,
                expires_at=expires_at,
                added_by=added_by_id
            )

            db.session.add(whitelist)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='monitor',
                action='add_whitelist',
                resource=f'ip:{ip_address}',
                details={'description': description, 'expires_at': expires_at.isoformat() if expires_at else None}
            )

            logger.info(f"添加白名单成功: {ip_address}")
            return True, '添加成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"添加白名单失败: {str(e)}")
            return False, f'添加失败: {str(e)}'

    @staticmethod
    def remove_from_whitelist(whitelist_id, removed_by_id=None):
        """从白名单移除"""
        try:
            whitelist = IPWhitelist.query.get(whitelist_id)
            if not whitelist:
                return False, '记录不存在'

            ip_address = whitelist.ip_address
            db.session.delete(whitelist)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='monitor',
                action='remove_whitelist',
                resource=f'ip:{ip_address}'
            )

            logger.info(f"从白名单移除成功: {ip_address}")
            return True, '移除成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"移除白名单失败: {str(e)}")
            return False, f'移除失败: {str(e)}'

    @staticmethod
    def is_whitelisted(ip_address):
        """检查IP是否在白名单中"""
        try:
            # 精确匹配
            if IPWhitelist.query.filter_by(ip_address=ip_address, is_active=True).first():
                return True

            # 范围匹配（简化版，实际应该使用ipaddress模块）
            whitelists = IPWhitelist.query.filter(
                IPWhitelist.ip_range.isnot(None),
                IPWhitelist.is_active == True
            ).all()

            for whitelist in whitelists:
                if whitelist.is_expired():
                    continue
                # TODO: 实现CIDR范围匹配

            return False

        except Exception as e:
            logger.error(f"检查白名单失败: {str(e)}")
            return False


class NetworkInterfaceService:
    """网卡管理服务"""

    @staticmethod
    def get_interfaces():
        """获取网卡列表"""
        try:
            return NetworkInterface.query.order_by(NetworkInterface.name).all()
        except Exception as e:
            logger.error(f"获取网卡列表失败: {str(e)}")
            return []

    @staticmethod
    def get_system_interfaces():
        """获取系统实际网卡列表"""
        try:
            import psutil
            interfaces = []

            for name, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': name,
                    'ip_address': None,
                    'mac_address': None
                }

                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        interface_info['ip_address'] = addr.address
                    elif addr.family == 17:  # MAC
                        interface_info['mac_address'] = addr.address

                interfaces.append(interface_info)

            return interfaces

        except ImportError:
            # 如果没有psutil，返回模拟数据
            return [
                {'name': 'eth0', 'ip_address': '192.168.1.100', 'mac_address': '00:11:22:33:44:55'},
                {'name': 'wlan0', 'ip_address': '192.168.1.101', 'mac_address': '00:11:22:33:44:56'},
            ]
        except Exception as e:
            logger.error(f"获取系统网卡失败: {str(e)}")
            return []

    @staticmethod
    def sync_interfaces():
        """同步系统网卡到数据库"""
        try:
            system_interfaces = NetworkInterfaceService.get_system_interfaces()

            for sys_iface in system_interfaces:
                existing = NetworkInterface.query.filter_by(name=sys_iface['name']).first()
                if not existing:
                    interface = NetworkInterface(
                        name=sys_iface['name'],
                        display_name=sys_iface['name'],
                        ip_address=sys_iface.get('ip_address'),
                        mac_address=sys_iface.get('mac_address')
                    )
                    db.session.add(interface)

            db.session.commit()
            logger.info("网卡同步完成")
            return True, '同步成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"网卡同步失败: {str(e)}")
            return False, f'同步失败: {str(e)}'

    @staticmethod
    def set_monitoring_interface(interface_id, is_monitoring=True, updated_by_id=None):
        """设置监控网卡"""
        try:
            # 先关闭所有网卡的监控
            NetworkInterface.query.update({'is_monitoring': False})

            # 启用指定网卡
            interface = NetworkInterface.query.get(interface_id)
            if interface:
                interface.is_monitoring = is_monitoring
                db.session.commit()

                # 记录操作日志
                OperationLogger.log(
                    module='monitor',
                    action='set_interface',
                    resource=f'interface:{interface.name}',
                    details={'is_monitoring': is_monitoring}
                )

                return True, f'已设置 {interface.name} 为监控网卡'
            else:
                return False, '网卡不存在'

        except Exception as e:
            db.session.rollback()
            logger.error(f"设置监控网卡失败: {str(e)}")
            return False, f'设置失败: {str(e)}'


class ProtocolConfigService:
    """协议配置服务"""

    # 预定义协议
    DEFAULT_PROTOCOLS = [
        {'protocol': 'TCP', 'ports': '', 'desc': '传输控制协议', 'level': 'deep'},
        {'protocol': 'UDP', 'ports': '', 'desc': '用户数据报协议', 'level': 'basic'},
        {'protocol': 'ICMP', 'ports': '', 'desc': '互联网控制消息协议', 'level': 'basic'},
        {'protocol': 'HTTP', 'ports': '80,8080,8000', 'desc': '超文本传输协议', 'level': 'full'},
        {'protocol': 'HTTPS', 'ports': '443', 'desc': 'HTTP安全版', 'level': 'basic'},
        {'protocol': 'DNS', 'ports': '53', 'desc': '域名系统', 'level': 'deep'},
        {'protocol': 'FTP', 'ports': '20,21', 'desc': '文件传输协议', 'level': 'full'},
        {'protocol': 'SSH', 'ports': '22', 'desc': '安全外壳协议', 'level': 'basic'},
        {'protocol': 'TELNET', 'ports': '23', 'desc': '远程登录协议', 'level': 'basic'},
        {'protocol': 'SMTP', 'ports': '25,587', 'desc': '简单邮件传输', 'level': 'deep'},
    ]

    @staticmethod
    def init_protocols():
        """初始化默认协议配置"""
        try:
            for proto in ProtocolConfigService.DEFAULT_PROTOCOLS:
                existing = ProtocolConfig.query.filter_by(protocol=proto['protocol']).first()
                if not existing:
                    protocol_config = ProtocolConfig(
                        protocol=proto['protocol'],
                        port_range=proto['ports'],
                        description=proto['desc'],
                        inspection_level=proto['level']
                    )
                    db.session.add(protocol_config)
            db.session.commit()
            logger.info("协议配置初始化完成")
            return True
        except Exception as e:
            logger.error(f"协议配置初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def get_protocols():
        """获取协议配置列表"""
        try:
            return ProtocolConfig.query.order_by(ProtocolConfig.protocol).all()
        except Exception as e:
            logger.error(f"获取协议配置失败: {str(e)}")
            return []

    @staticmethod
    def update_protocol(protocol_id, is_enabled=None, port_range=None, inspection_level=None):
        """更新协议配置"""
        try:
            protocol = ProtocolConfig.query.get(protocol_id)
            if not protocol:
                return False, '协议不存在'

            changes = {}

            if is_enabled is not None:
                protocol.is_enabled = is_enabled
                changes['is_enabled'] = is_enabled

            if port_range is not None:
                protocol.port_range = port_range
                changes['port_range'] = port_range

            if inspection_level is not None:
                protocol.inspection_level = inspection_level
                changes['inspection_level'] = inspection_level

            if not changes:
                return False, '没有需要更新的内容'

            protocol.updated_at = datetime.utcnow()
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='monitor',
                action='update_protocol',
                resource=f'protocol:{protocol.protocol}',
                details=changes
            )

            logger.info(f"协议配置更新成功: {protocol.protocol}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新协议配置失败: {str(e)}")
            return False, f'更新失败: {str(e)}'


class TrafficStatsService:
    """流量统计服务"""

    @staticmethod
    def get_stats(page=1, per_page=50, start_date=None, end_date=None,
                   source_ip=None, protocol=None, is_threat=None):
        """获取流量统计"""
        try:
            query = TrafficStats.query

            if start_date:
                query = query.filter(TrafficStats.timestamp >= start_date)

            if end_date:
                query = query.filter(TrafficStats.timestamp <= end_date)

            if source_ip:
                query = query.filter_by(source_ip=source_ip)

            if protocol:
                query = query.filter_by(protocol=protocol)

            if is_threat is not None:
                query = query.filter_by(is_threat=is_threat)

            # 只返回最近7天的数据
            query = query.filter(TrafficStats.timestamp >= datetime.utcnow() - timedelta(days=7))

            pagination = query.order_by(TrafficStats.timestamp.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取流量统计失败: {str(e)}")
            return [], 0

    @staticmethod
    def cleanup_old_records(cleanup_type='before_date', days=30, created_by_id=None):
        """清理旧记录"""
        try:
            before_date = datetime.utcnow() - timedelta(days=days)

            if cleanup_type == 'before_date':
                count = TrafficStats.query.filter(TrafficStats.timestamp < before_date).delete()
            elif cleanup_type == 'threat_only':
                # 只保留威胁记录
                count = TrafficStats.query.filter(
                    TrafficStats.timestamp < before_date,
                    TrafficStats.is_threat == False
                ).delete()
            elif cleanup_type == 'all':
                count = TrafficStats.query.filter(TrafficStats.timestamp < before_date).delete()
            else:
                return False, 0, '无效的清理类型'

            # 记录清理
            cleanup = TrafficCleanup(
                cleanup_type=cleanup_type,
                record_count=count,
                before_date=before_date,
                created_by=created_by_id
            )
            db.session.add(cleanup)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='monitor',
                action='cleanup_traffic',
                resource=f'traffic_stats',
                details={'cleanup_type': cleanup_type, 'days': days, 'count': count}
            )

            logger.info(f"清理流量记录成功: {cleanup_type} - {count}条")
            return True, count, f'已清理 {count} 条记录'

        except Exception as e:
            db.session.rollback()
            logger.error(f"清理流量记录失败: {str(e)}")
            return False, 0, f'清理失败: {str(e)}'

    @staticmethod
    def get_summary_stats():
        """获取汇总统计"""
        try:
            # 最近24小时统计
            since = datetime.utcnow() - timedelta(hours=24)

            total_packets = db.session.query(db.func.sum(TrafficStats.packet_count)).filter(
                TrafficStats.timestamp >= since
            ).scalar() or 0

            total_bytes = db.session.query(db.func.sum(TrafficStats.byte_count)).filter(
                TrafficStats.timestamp >= since
            ).scalar() or 0

            threat_count = TrafficStats.query.filter(
                TrafficStats.timestamp >= since,
                TrafficStats.is_threat == True
            ).count()

            # 按协议统计
            protocol_stats = db.session.query(
                TrafficStats.protocol,
                db.func.count(TrafficStats.id).label('count')
            ).filter(
                TrafficStats.timestamp >= since
            ).group_by(TrafficStats.protocol).all()

            return {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'threat_count': threat_count,
                'protocol_stats': {p.protocol: p.count for p in protocol_stats}
            }

        except Exception as e:
            logger.error(f"获取汇总统计失败: {str(e)}")
            return {}
