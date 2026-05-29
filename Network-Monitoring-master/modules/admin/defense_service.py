#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
防御管理服务模块
提供IP封禁管理、防御策略、执行日志等功能
"""

from datetime import datetime, timedelta
from models_admin import db, BlockedIP, DefenseRule
from modules.admin.log_service import OperationLogger
import logging
import ipaddress

logger = logging.getLogger(__name__)


class IPBlockService:
    """IP封禁管理服务"""

    @staticmethod
    def get_blocked_ips(page=1, per_page=50, ip_address=None, threat_type=None, is_active=None, start_date=None, end_date=None):
        """获取封禁IP列表"""
        try:
            query = BlockedIP.query

            if ip_address:
                query = query.filter(BlockedIP.ip_address.contains(ip_address))

            if threat_type:
                query = query.filter_by(threat_type=threat_type)

            if is_active is not None:
                query = query.filter_by(is_active=is_active)

            if start_date:
                query = query.filter(BlockedIP.blocked_at >= start_date)

            if end_date:
                query = query.filter(BlockedIP.blocked_at <= end_date)

            pagination = query.order_by(BlockedIP.blocked_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取封禁IP列表失败: {str(e)}")
            return [], 0

    @staticmethod
    def block_ip(ip_address, reason=None, threat_type='manual', duration_hours=None, blocked_by_id=None):
        """封禁IP"""
        try:
            # 验证IP地址
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                return False, None, '无效的IP地址'

            # 检查是否已存在
            existing = BlockedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
            if existing:
                return False, None, '该IP已被封禁'

            blocked_ip = BlockedIP(
                ip_address=ip_address,
                reason=reason or '手动封禁',
                threat_type=threat_type,
                source='manual',
                blocked_at=datetime.utcnow()
            )

            db.session.add(blocked_ip)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='defense',
                action='block_ip',
                resource=f'ip:{ip_address}',
                details={'reason': reason, 'threat_type': threat_type}
            )

            logger.info(f"封禁IP成功: {ip_address}")
            return True, blocked_ip, '封禁成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"封禁IP失败: {str(e)}")
            return False, None, f'封禁失败: {str(e)}'

    @staticmethod
    def unblock_ip(block_id, unblock_reason=None, unblocked_by_id=None):
        """解封IP"""
        try:
            blocked_ip = BlockedIP.query.get(block_id)
            if not blocked_ip:
                return False, '封禁记录不存在'

            if not blocked_ip.is_active:
                return False, '该IP已解封'

            blocked_ip.is_active = False
            if unblock_reason:
                blocked_ip.reason = f"{blocked_ip.reason} | 解封原因: {unblock_reason}"

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='defense',
                action='unblock_ip',
                resource=f'ip:{blocked_ip.ip_address}',
                details={'block_id': block_id, 'unblock_reason': unblock_reason}
            )

            logger.info(f"解封IP成功: {blocked_ip.ip_address}")
            return True, '解封成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"解封IP失败: {str(e)}")
            return False, f'解封失败: {str(e)}'

    @staticmethod
    def batch_unblock_ip(block_ids, unblocked_by_id=None):
        """批量解封IP"""
        try:
            count = 0
            for block_id in block_ids:
                blocked_ip = BlockedIP.query.get(block_id)
                if blocked_ip and blocked_ip.is_active:
                    blocked_ip.is_active = False
                    count += 1

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='defense',
                action='batch_unblock',
                resource='ip_batch',
                details={'count': count, 'block_ids': block_ids}
            )

            logger.info(f"批量解封IP成功: {count}条")
            return True, f'已解封 {count} 个IP'

        except Exception as e:
            db.session.rollback()
            logger.error(f"批量解封IP失败: {str(e)}")
            return False, f'批量解封失败: {str(e)}'

    @staticmethod
    def cleanup_expired_blocks():
        """清理过期封禁（可根据实际需求实现）"""
        try:
            # 这里可以根据blocked_at时间和其他条件清理过期记录
            # 目前实现为清理超过30天的已解封记录
            expired_date = datetime.utcnow() - timedelta(days=30)
            expired = BlockedIP.query.filter(
                BlockedIP.is_active == False,
                BlockedIP.blocked_at < expired_date
            ).all()

            count = len(expired)
            for item in expired:
                db.session.delete(item)

            db.session.commit()
            logger.info(f"清理过期封禁记录: {count}条")
            return count

        except Exception as e:
            db.session.rollback()
            logger.error(f"清理过期封禁失败: {str(e)}")
            return 0


class DefensePolicyService:
    """防御策略服务"""

    # 预定义防御策略
    DEFAULT_POLICIES = [
        {
            'name': '自动封禁策略',
            'policy_type': 'auto_block',
            'condition': {'threat_count': 5, 'time_window': 300},
            'action': 'block',
            'duration': 3600,
            'severity': 'high',
            'description': '5分钟内检测到5次威胁自动封禁1小时'
        },
        {
            'name': '限流策略',
            'policy_type': 'rate_limit',
            'condition': {'requests': 1000, 'time_window': 60},
            'action': 'rate_limit',
            'duration': 300,
            'severity': 'medium',
            'description': '每分钟超过1000请求时限流5分钟'
        },
        {
            'name': '端口扫描防御',
            'policy_type': 'port_scan',
            'condition': {'port_count': 20, 'time_window': 60},
            'action': 'block',
            'duration': 1800,
            'severity': 'high',
            'description': '1分钟内扫描超过20端口自动封禁30分钟'
        }
    ]

    @staticmethod
    def init_policies():
        """初始化默认防御策略"""
        try:
            for policy_data in DefensePolicyService.DEFAULT_POLICIES:
                existing = DefenseRule.query.filter_by(name=policy_data['name']).first()
                if not existing:
                    policy = DefenseRule(
                        name=policy_data['name'],
                        rule_type=policy_data['policy_type'],
                        condition=str(policy_data['condition']),
                        action=policy_data['action'],
                        severity=policy_data['severity']
                    )
                    db.session.add(policy)
            db.session.commit()
            logger.info("防御策略初始化完成")
            return True
        except Exception as e:
            logger.error(f"防御策略初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def get_policies():
        """获取防御策略列表"""
        try:
            return DefenseRule.query.order_by(DefenseRule.created_at.desc()).all()
        except Exception as e:
            logger.error(f"获取防御策略失败: {str(e)}")
            return []

    @staticmethod
    def get_policy_by_id(policy_id):
        """根据ID获取策略"""
        try:
            return DefenseRule.query.get(policy_id)
        except Exception as e:
            logger.error(f"获取策略失败: {str(e)}")
            return None

    @staticmethod
    def create_policy(name, policy_type, condition, action, duration=None, severity='medium', description=None, created_by_id=None):
        """创建防御策略"""
        try:
            # 检查策略名是否已存在
            if DefenseRule.query.filter_by(name=name).first():
                return False, None, '策略名已存在'

            policy = DefenseRule(
                name=name,
                rule_type=policy_type,
                condition=str(condition),
                action=action,
                severity=severity
            )

            db.session.add(policy)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='defense',
                action='create_policy',
                resource=f'policy:{policy.id}',
                details={'name': name, 'policy_type': policy_type, 'action': action}
            )

            logger.info(f"创建防御策略成功: {name}")
            return True, policy, '创建成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建防御策略失败: {str(e)}")
            return False, None, f'创建失败: {str(e)}'

    @staticmethod
    def update_policy(policy_id, name=None, condition=None, action=None, severity=None, is_enabled=None):
        """更新防御策略"""
        try:
            policy = DefenseRule.query.get(policy_id)
            if not policy:
                return False, '策略不存在'

            changes = {}

            if name and name != policy.name:
                policy.name = name
                changes['name'] = name

            if condition is not None and str(condition) != policy.condition:
                policy.condition = str(condition)
                changes['condition'] = 'updated'

            if action and action != policy.action:
                policy.action = action
                changes['action'] = action

            if severity and severity != policy.severity:
                policy.severity = severity
                changes['severity'] = severity

            if is_enabled is not None and is_enabled != policy.is_enabled:
                policy.is_enabled = is_enabled
                changes['is_enabled'] = is_enabled

            if not changes:
                return False, '没有需要更新的内容'

            policy.updated_at = datetime.utcnow()
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='defense',
                action='update_policy',
                resource=f'policy:{policy_id}',
                details=changes
            )

            logger.info(f"更新防御策略成功: {policy.name}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新防御策略失败: {str(e)}")
            return False, f'更新失败: {str(e)}'

    @staticmethod
    def delete_policy(policy_id):
        """删除防御策略"""
        try:
            policy = DefenseRule.query.get(policy_id)
            if not policy:
                return False, '策略不存在'

            policy_name = policy.name
            db.session.delete(policy)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='defense',
                action='delete_policy',
                resource=f'policy:{policy_id}',
                details={'name': policy_name}
            )

            logger.info(f"删除防御策略成功: {policy_name}")
            return True, '删除成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除防御策略失败: {str(e)}")
            return False, f'删除失败: {str(e)}'


class DefenseExecutionService:
    """防御执行日志服务"""

    @staticmethod
    def get_execution_logs(page=1, per_page=50, action=None, result=None, start_date=None, end_date=None):
        """获取防御执行日志"""
        try:
            # 从操作日志中获取防御相关日志
            from models_admin import OperationLog

            query = OperationLog.query.filter_by(module='defense')

            if action:
                query = query.filter_by(action=action)

            if start_date:
                query = query.filter(OperationLog.created_at >= start_date)

            if end_date:
                query = query.filter(OperationLog.created_at <= end_date)

            # 只返回最近30天的记录
            query = query.filter(OperationLog.created_at >= datetime.utcnow() - timedelta(days=30))

            pagination = query.order_by(OperationLog.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取防御执行日志失败: {str(e)}")
            return [], 0

    @staticmethod
    def get_execution_stats():
        """获取防御执行统计"""
        try:
            from models_admin import OperationLog
            from sqlalchemy import func

            # 最近24小时统计
            since = datetime.utcnow() - timedelta(hours=24)

            # 总执行次数
            total_executions = OperationLog.query.filter(
                OperationLog.module == 'defense',
                OperationLog.created_at >= since
            ).count()

            # 按操作类型统计
            action_stats = db.session.query(
                OperationLog.action,
                func.count(OperationLog.id).label('count')
            ).filter(
                OperationLog.module == 'defense',
                OperationLog.created_at >= since
            ).group_by(OperationLog.action).all()

            stats = {
                'total_executions': total_executions,
                'action_stats': {stat.action: stat.count for stat in action_stats}
            }

            # 当前活跃封禁数
            stats['active_blocks'] = BlockedIP.query.filter_by(is_active=True).count()

            return stats

        except Exception as e:
            logger.error(f"获取防御执行统计失败: {str(e)}")
            return {}

    @staticmethod
    def get_recent_activity(limit=20):
        """获取最近防御活动"""
        try:
            from models_admin import OperationLog

            activities = OperationLog.query.filter_by(
                module='defense'
            ).order_by(
                OperationLog.created_at.desc()
            ).limit(limit).all()

            return activities

        except Exception as e:
            logger.error(f"获取最近防御活动失败: {str(e)}")
            return []
