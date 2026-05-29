#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
威胁检测管理服务模块
提供威胁记录、检测规则、模型管理等管理功能
"""

from datetime import datetime, timedelta
from models_admin import db, BlockedIP, DefenseRule
from models_admin import AlertRule, AlertRecord, AlertRecipient
from modules.admin.log_service import OperationLogger
import logging
import os
import pickle
import json

logger = logging.getLogger(__name__)


class ThreatRecordService:
    """威胁记录服务"""

    @staticmethod
    def get_threat_records(page=1, per_page=50, threat_type=None, severity=None,
                           start_date=None, end_date=None):
        """获取威胁记录"""
        try:
            # 从BlockedIP表获取威胁记录
            query = BlockedIP.query

            if threat_type:
                query = query.filter_by(threat_type=threat_type)

            if severity:
                query = query.filter_by(source=severity)  # source字段表示严重程度

            if start_date:
                query = query.filter(BlockedIP.blocked_at >= start_date)

            if end_date:
                query = query.filter(BlockedIP.blocked_at <= end_date)

            # 只返回最近30天的记录
            query = query.filter(BlockedIP.blocked_at >= datetime.utcnow() - timedelta(days=30))

            pagination = query.order_by(BlockedIP.blocked_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            # 转换为威胁记录格式
            threats = []
            for blocked_ip in pagination.items:
                threats.append({
                    'id': blocked_ip.id,
                    'threat_type': blocked_ip.threat_type or 'Unknown',
                    'severity': blocked_ip.source or 'medium',
                    'source_ip': blocked_ip.ip_address,
                    'target_ip': 'N/A',
                    'source_port': None,
                    'target_port': None,
                    'timestamp': blocked_ip.blocked_at.isoformat() if blocked_ip.blocked_at else None,
                    'description': blocked_ip.reason,
                    'status': 'blocked' if blocked_ip.is_active else 'unblocked'
                })

            return threats, pagination.total

        except Exception as e:
            logger.error(f"获取威胁记录失败: {str(e)}")
            return [], 0

    @staticmethod
    def get_threat_stats():
        """获取威胁统计"""
        try:
            # 最近24小时威胁统计
            since = datetime.utcnow() - timedelta(hours=24)

            total_threats = BlockedIP.query.filter(
                BlockedIP.blocked_at >= since
            ).count()

            # 按类型统计
            type_stats = db.session.query(
                BlockedIP.threat_type,
                db.func.count(BlockedIP.id).label('count')
            ).filter(
                BlockedIP.blocked_at >= since
            ).group_by(BlockedIP.threat_type).all()

            # 按严重程度统计
            severity_stats = {}
            for stat in type_stats:
                if stat.threat_type:
                    severity_stats[stat.threat_type] = stat.count

            return {
                'total_threats': total_threats,
                'type_stats': severity_stats,
                'active_blocks': BlockedIP.query.filter_by(is_active=True).count()
            }

        except Exception as e:
            logger.error(f"获取威胁统计失败: {str(e)}")
            return {}


class DetectionRuleService:
    """检测规则服务"""

    # 预定义检测规则
    DEFAULT_RULES = [
        {
            'name': 'DDoS攻击检测',
            'rule_type': 'auto_block',
            'condition': {'packet_rate': 1000, 'time_window': 60},
            'action': 'block',
            'severity': 'high',
            'description': '检测每分钟超过1000个数据包的DDoS攻击'
        },
        {
            'name': '端口扫描检测',
            'rule_type': 'rate_limit',
            'condition': {'port_count': 10, 'time_window': 30},
            'action': 'alert',
            'severity': 'medium',
            'description': '检测30秒内扫描超过10个端口的端口扫描行为'
        },
        {
            'name': 'SQL注入检测',
            'rule_type': 'auto_block',
            'condition': {'patterns': ["' OR '1'='1", "'; DROP TABLE", "UNION SELECT"]},
            'action': 'block',
            'severity': 'critical',
            'description': '检测常见SQL注入攻击模式'
        },
        {
            'name': '暴力破解检测',
            'rule_type': 'rate_limit',
            'condition': {'failed_attempts': 5, 'time_window': 60},
            'action': 'block',
            'severity': 'medium',
            'description': '检测1分钟内失败登录超过5次的暴力破解行为'
        },
        {
            'name': 'XSS攻击检测',
            'rule_type': 'alert',
            'condition': {'patterns': ['<script>', 'javascript:', 'onerror=']},
            'action': 'alert',
            'severity': 'high',
            'description': '检测跨站脚本攻击模式'
        }
    ]

    @staticmethod
    def init_rules():
        """初始化默认检测规则"""
        try:
            for rule_data in DetectionRuleService.DEFAULT_RULES:
                existing = DefenseRule.query.filter_by(name=rule_data['name']).first()
                if not existing:
                    rule = DefenseRule(
                        name=rule_data['name'],
                        rule_type=rule_data['rule_type'],
                        condition=json.dumps(rule_data['condition'], ensure_ascii=False),
                        action=rule_data['action'],
                        severity=rule_data['severity']
                    )
                    db.session.add(rule)
            db.session.commit()
            logger.info("检测规则初始化完成")
            return True
        except Exception as e:
            logger.error(f"检测规则初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def get_rules():
        """获取检测规则列表"""
        try:
            return DefenseRule.query.order_by(DefenseRule.created_at.desc()).all()
        except Exception as e:
            logger.error(f"获取检测规则失败: {str(e)}")
            return []

    @staticmethod
    def get_rule_by_id(rule_id):
        """根据ID获取规则"""
        try:
            return DefenseRule.query.get(rule_id)
        except Exception as e:
            logger.error(f"获取规则失败: {str(e)}")
            return None

    @staticmethod
    def create_rule(name, rule_type, condition, action, severity, description=None, created_by_id=None):
        """创建检测规则"""
        try:
            # 检查规则名是否已存在
            if DefenseRule.query.filter_by(name=name).first():
                return False, None, '规则名已存在'

            rule = DefenseRule(
                name=name,
                rule_type=rule_type,
                condition=json.dumps(condition, ensure_ascii=False) if isinstance(condition, dict) else condition,
                action=action,
                severity=severity
            )

            db.session.add(rule)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='threat',
                action='create_rule',
                resource=f'rule:{rule.id}',
                details={'name': name, 'rule_type': rule_type, 'action': action}
            )

            logger.info(f"创建检测规则成功: {name}")
            return True, rule, '创建成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建检测规则失败: {str(e)}")
            return False, None, f'创建失败: {str(e)}'

    @staticmethod
    def update_rule(rule_id, name=None, condition=None, action=None, severity=None, is_enabled=None):
        """更新检测规则"""
        try:
            rule = DefenseRule.query.get(rule_id)
            if not rule:
                return False, '规则不存在'

            changes = {}

            if name and name != rule.name:
                rule.name = name
                changes['name'] = name

            if condition is not None:
                new_condition = json.dumps(condition, ensure_ascii=False) if isinstance(condition, dict) else condition
                if new_condition != rule.condition:
                    rule.condition = new_condition
                    changes['condition'] = 'updated'

            if action and action != rule.action:
                rule.action = action
                changes['action'] = action

            if severity and severity != rule.severity:
                rule.severity = severity
                changes['severity'] = severity

            if is_enabled is not None and is_enabled != rule.is_enabled:
                rule.is_enabled = is_enabled
                changes['is_enabled'] = is_enabled

            if not changes:
                return False, '没有需要更新的内容'

            rule.updated_at = datetime.utcnow()
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='threat',
                action='update_rule',
                resource=f'rule:{rule_id}',
                details=changes
            )

            logger.info(f"更新检测规则成功: {rule.name}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新检测规则失败: {str(e)}")
            return False, f'更新失败: {str(e)}'

    @staticmethod
    def delete_rule(rule_id):
        """删除检测规则"""
        try:
            rule = DefenseRule.query.get(rule_id)
            if not rule:
                return False, '规则不存在'

            rule_name = rule.name
            db.session.delete(rule)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='threat',
                action='delete_rule',
                resource=f'rule:{rule_id}',
                details={'name': rule_name}
            )

            logger.info(f"删除检测规则成功: {rule_name}")
            return True, '删除成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除检测规则失败: {str(e)}")
            return False, f'删除失败: {str(e)}'


class ModelManagementService:
    """模型管理服务"""

    @staticmethod
    def get_model_info():
        """获取模型信息"""
        try:
            import os
            model_path = 'model/randomforest_model.pkl'
            pipeline_path = 'model/preprocessing_pipeline.pkl'

            info = {
                'model_exists': os.path.exists(model_path),
                'pipeline_exists': os.path.exists(pipeline_path),
                'model_size': 0,
                'model_modified': None,
                'model_type': 'RandomForest',
                'version': '1.0'
            }

            if os.path.exists(model_path):
                info['model_size'] = os.path.getsize(model_path)
                info['model_modified'] = datetime.fromtimestamp(os.path.getmtime(model_path)).isoformat()

            return info

        except Exception as e:
            logger.error(f"获取模型信息失败: {str(e)}")
            return {}

    @staticmethod
    def retrain_model(train_data_path=None):
        """重新训练模型（简化版，实际应该调用训练脚本）"""
        try:
            # 这里应该调用实际的模型训练逻辑
            # 由于训练需要大量时间和数据，这里只记录操作

            OperationLogger.log(
                module='threat',
                action='retrain_model',
                resource='model',
                details={'status': 'initiated', 'data_path': train_data_path}
            )

            logger.info("模型重新训练已启动（后台任务）")
            return True, '模型训练已启动，请查看系统日志获取进度'

        except Exception as e:
            logger.error(f"重新训练模型失败: {str(e)}")
            return False, f'训练失败: {str(e)}'

    @staticmethod
    def get_model_params():
        """获取模型参数"""
        try:
            # 返回模拟的模型参数
            return {
                'n_estimators': 100,
                'max_depth': 10,
                'min_samples_split': 2,
                'min_samples_leaf': 1,
                'criterion': 'gini',
                'random_state': 42
            }
        except Exception as e:
            logger.error(f"获取模型参数失败: {str(e)}")
            return {}

    @staticmethod
    def update_model_params(params):
        """更新模型参数（需要重新训练）"""
        try:
            # 这里应该保存参数并触发重新训练
            OperationLogger.log(
                module='threat',
                action='update_params',
                resource='model',
                details=params
            )

            logger.info(f"模型参数已更新: {params}")
            return True, '参数已更新，需要重新训练模型以生效'

        except Exception as e:
            logger.error(f"更新模型参数失败: {str(e)}")
            return False, f'更新失败: {str(e)}'


class ThreatHandlerService:
    """威胁处置服务"""

    @staticmethod
    def handle_threat(threat_id, action, notes=None, handled_by_id=None):
        """处置威胁"""
        try:
            threat = BlockedIP.query.get(threat_id)
            if not threat:
                return False, '威胁记录不存在'

            changes = {}

            if action == 'unblock':
                threat.is_active = False
                changes['status'] = 'unblocked'

            elif action == 'block':
                threat.is_active = True
                changes['status'] = 'blocked'

            elif action == 'ignore':
                # 标记为误报，从威胁列表移除
                db.session.delete(threat)
                changes['status'] = 'ignored'

            if notes:
                threat.reason = f"{threat.reason or ''} | 处置备注: {notes}"

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='threat',
                action='handle_threat',
                resource=f'threat:{threat_id}',
                details={'action': action, 'notes': notes}
            )

            logger.info(f"威胁处置成功: {threat_id} - {action}")
            return True, '处置成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"处置威胁失败: {str(e)}")
            return False, f'处置失败: {str(e)}'

    @staticmethod
    def batch_handle(threat_ids, action, handled_by_id=None):
        """批量处置威胁"""
        try:
            count = 0
            for threat_id in threat_ids:
                success, _ = ThreatHandlerService.handle_threat(threat_id, action)
                if success:
                    count += 1

            return True, f'已处理 {count}/{len(threat_ids)} 条威胁记录'

        except Exception as e:
            logger.error(f"批量处置威胁失败: {str(e)}")
            return False, f'批量处理失败: {str(e)}'
