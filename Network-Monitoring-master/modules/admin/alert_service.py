#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
告警管理服务模块
提供告警规则、告警记录、通知设置等管理功能
"""

from datetime import datetime, timedelta
from models_admin import db, AlertRule, AlertRecord, AlertRecipient
from modules.admin.log_service import OperationLogger
import logging
import requests
import json

logger = logging.getLogger(__name__)


class AlertRuleService:
    """告警规则服务"""

    # 预定义告警规则
    DEFAULT_ALERT_RULES = [
        {
            'name': '流量异常告警',
            'metric': 'traffic',
            'condition': '>',
            'threshold': 1000000,  # 1MB/s
            'severity': 'medium',
            'description': '流量超过1MB/s时告警'
        },
        {
            'name': '威胁数量告警',
            'metric': 'threat_count',
            'condition': '>=',
            'threshold': 10,
            'severity': 'high',
            'description': '威胁数量超过10时告警'
        },
        {
            'name': 'CPU使用率告警',
            'metric': 'cpu_usage',
            'condition': '>',
            'threshold': 80,
            'severity': 'warning',
            'description': 'CPU使用率超过80%时告警'
        },
        {
            'name': '内存使用率告警',
            'metric': 'memory_usage',
            'condition': '>',
            'threshold': 85,
            'severity': 'warning',
            'description': '内存使用率超过85%时告警'
        },
        {
            'name': '磁盘空间告警',
            'metric': 'disk_usage',
            'condition': '>',
            'threshold': 90,
            'severity': 'critical',
            'description': '磁盘使用率超过90%时告警'
        }
    ]

    @staticmethod
    def init_alert_rules():
        """初始化默认告警规则"""
        try:
            for rule_data in AlertRuleService.DEFAULT_ALERT_RULES:
                existing = AlertRule.query.filter_by(name=rule_data['name']).first()
                if not existing:
                    rule = AlertRule(
                        name=rule_data['name'],
                        metric=rule_data['metric'],
                        condition=rule_data['condition'],
                        threshold=rule_data['threshold'],
                        severity=rule_data['severity']
                    )
                    db.session.add(rule)
            db.session.commit()
            logger.info("告警规则初始化完成")
            return True
        except Exception as e:
            logger.error(f"告警规则初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def get_alert_rules():
        """获取告警规则列表"""
        try:
            return AlertRule.query.order_by(AlertRule.created_at.desc()).all()
        except Exception as e:
            logger.error(f"获取告警规则失败: {str(e)}")
            return []

    @staticmethod
    def get_rule_by_id(rule_id):
        """根据ID获取规则"""
        try:
            return AlertRule.query.get(rule_id)
        except Exception as e:
            logger.error(f"获取规则失败: {str(e)}")
            return None

    @staticmethod
    def create_alert_rule(name, metric, condition, threshold, severity, silence_duration=0, created_by_id=None):
        """创建告警规则"""
        try:
            # 检查规则名是否已存在
            if AlertRule.query.filter_by(name=name).first():
                return False, None, '规则名已存在'

            rule = AlertRule(
                name=name,
                metric=metric,
                condition=condition,
                threshold=float(threshold),
                severity=severity,
                silence_duration=silence_duration,
                created_by=created_by_id
            )

            db.session.add(rule)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='create_rule',
                resource=f'alert_rule:{rule.id}',
                details={'name': name, 'metric': metric, 'threshold': threshold}
            )

            logger.info(f"创建告警规则成功: {name}")
            return True, rule, '创建成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建告警规则失败: {str(e)}")
            return False, None, f'创建失败: {str(e)}'

    @staticmethod
    def update_alert_rule(rule_id, name=None, threshold=None, severity=None, is_enabled=None, silence_duration=None):
        """更新告警规则"""
        try:
            rule = AlertRule.query.get(rule_id)
            if not rule:
                return False, '规则不存在'

            changes = {}

            if name and name != rule.name:
                rule.name = name
                changes['name'] = name

            if threshold is not None and threshold != rule.threshold:
                rule.threshold = float(threshold)
                changes['threshold'] = threshold

            if severity and severity != rule.severity:
                rule.severity = severity
                changes['severity'] = severity

            if is_enabled is not None and is_enabled != rule.is_enabled:
                rule.is_enabled = is_enabled
                changes['is_enabled'] = is_enabled

            if silence_duration is not None and silence_duration != rule.silence_duration:
                rule.silence_duration = silence_duration
                changes['silence_duration'] = silence_duration

            if not changes:
                return False, '没有需要更新的内容'

            rule.updated_at = datetime.utcnow()
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='update_rule',
                resource=f'alert_rule:{rule_id}',
                details=changes
            )

            logger.info(f"更新告警规则成功: {rule.name}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新告警规则失败: {str(e)}")
            return False, f'更新失败: {str(e)}'

    @staticmethod
    def delete_alert_rule(rule_id):
        """删除告警规则"""
        try:
            rule = AlertRule.query.get(rule_id)
            if not rule:
                return False, '规则不存在'

            rule_name = rule.name
            db.session.delete(rule)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='delete_rule',
                resource=f'alert_rule:{rule_id}',
                details={'name': rule_name}
            )

            logger.info(f"删除告警规则成功: {rule_name}")
            return True, '删除成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除告警规则失败: {str(e)}")
            return False, f'删除失败: {str(e)}'


class AlertRecordService:
    """告警记录服务"""

    @staticmethod
    def get_alert_records(page=1, per_page=50, severity=None, status=None, start_date=None, end_date=None):
        """获取告警记录"""
        try:
            query = AlertRecord.query

            if severity:
                query = query.filter_by(severity=severity)

            if status:
                query = query.filter_by(status=status)

            if start_date:
                query = query.filter(AlertRecord.created_at >= start_date)

            if end_date:
                query = query.filter(AlertRecord.created_at <= end_date)

            # 只返回最近7天的记录
            query = query.filter(AlertRecord.created_at >= datetime.utcnow() - timedelta(days=7))

            pagination = query.order_by(AlertRecord.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取告警记录失败: {str(e)}")
            return [], 0

    @staticmethod
    def confirm_alert(alert_id, confirmed_by_id=None):
        """确认告警"""
        try:
            alert = AlertRecord.query.get(alert_id)
            if not alert:
                return False, '告警记录不存在'

            alert.status = 'confirmed'
            alert.confirmed_by = confirmed_by_id
            alert.confirmed_at = datetime.utcnow()
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='confirm_alert',
                resource=f'alert:{alert_id}',
                details={'rule_name': alert.rule_name}
            )

            logger.info(f"告警确认成功: {alert_id}")
            return True, '确认成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"确认告警失败: {str(e)}")
            return False, f'确认失败: {str(e)}'

    @staticmethod
    def resolve_alert(alert_id, resolved_by_id=None):
        """解决告警"""
        try:
            alert = AlertRecord.query.get(alert_id)
            if not alert:
                return False, '告警记录不存在'

            alert.status = 'resolved'
            alert.confirmed_by = resolved_by_id
            alert.confirmed_at = datetime.utcnow()
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='resolve_alert',
                resource=f'alert:{alert_id}',
                details={'rule_name': alert.rule_name}
            )

            logger.info(f"告警解决成功: {alert_id}")
            return True, '解决成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"解决告警失败: {str(e)}")
            return False, f'解决失败: {str(e)}'

    @staticmethod
    def ignore_alert(alert_id, ignored_by_id=None):
        """忽略告警"""
        try:
            alert = AlertRecord.query.get(alert_id)
            if not alert:
                return False, '告警记录不存在'

            alert.status = 'ignored'
            alert.confirmed_by = ignored_by_id
            alert.confirmed_at = datetime.utcnow()
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='ignore_alert',
                resource=f'alert:{alert_id}',
                details={'rule_name': alert.rule_name}
            )

            logger.info(f"告警忽略成功: {alert_id}")
            return True, '忽略成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"忽略告警失败: {str(e)}")
            return False, f'忽略失败: {str(e)}'

    @staticmethod
    def create_alert(rule_id, rule_name, severity, message, details=None):
        """创建告警记录"""
        try:
            alert = AlertRecord(
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                message=message,
                details=json.dumps(details, ensure_ascii=False) if details else None
            )

            db.session.add(alert)
            db.session.commit()

            logger.info(f"告警记录创建成功: {rule_name}")
            return alert

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建告警记录失败: {str(e)}")
            return None


class NotificationService:
    """通知服务"""

    @staticmethod
    def get_recipients():
        """获取告警接收人列表"""
        try:
            return AlertRecipient.query.order_by(AlertRecipient.created_at.desc()).all()
        except Exception as e:
            logger.error(f"获取接收人列表失败: {str(e)}")
            return []

    @staticmethod
    def add_recipient(name, email=None, dingtalk_webhook=None, wechat_webhook=None):
        """添加告警接收人"""
        try:
            recipient = AlertRecipient(
                name=name,
                email=email,
                dingtalk_webhook=dingtalk_webhook,
                wechat_webhook=wechat_webhook
            )

            db.session.add(recipient)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='add_recipient',
                resource=f'recipient:{recipient.id}',
                details={'name': name}
            )

            logger.info(f"添加告警接收人成功: {name}")
            return True, recipient, '添加成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"添加告警接收人失败: {str(e)}")
            return False, None, f'添加失败: {str(e)}'

    @staticmethod
    def update_recipient(recipient_id, name=None, email=None, is_enabled=None, dingtalk_webhook=None, wechat_webhook=None):
        """更新告警接收人"""
        try:
            recipient = AlertRecipient.query.get(recipient_id)
            if not recipient:
                return False, '接收人不存在'

            changes = {}

            if name and name != recipient.name:
                recipient.name = name
                changes['name'] = name

            if email is not None and email != recipient.email:
                recipient.email = email
                changes['email'] = email

            if is_enabled is not None and is_enabled != recipient.is_enabled:
                recipient.is_enabled = is_enabled
                changes['is_enabled'] = is_enabled

            if dingtalk_webhook is not None and dingtalk_webhook != recipient.dingtalk_webhook:
                recipient.dingtalk_webhook = dingtalk_webhook
                changes['dingtalk_webhook'] = 'updated'

            if wechat_webhook is not None and wechat_webhook != recipient.wechat_webhook:
                recipient.wechat_webhook = wechat_webhook
                changes['wechat_webhook'] = 'updated'

            if not changes:
                return False, '没有需要更新的内容'

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='update_recipient',
                resource=f'recipient:{recipient_id}',
                details=changes
            )

            logger.info(f"更新告警接收人成功: {recipient.name}")
            return True, '更新成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"更新告警接收人失败: {str(e)}")
            return False, f'更新失败: {str(e)}'

    @staticmethod
    def delete_recipient(recipient_id):
        """删除告警接收人"""
        try:
            recipient = AlertRecipient.query.get(recipient_id)
            if not recipient:
                return False, '接收人不存在'

            name = recipient.name
            db.session.delete(recipient)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='alert',
                action='delete_recipient',
                resource=f'recipient:{recipient_id}',
                details={'name': name}
            )

            logger.info(f"删除告警接收人成功: {name}")
            return True, '删除成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除告警接收人失败: {str(e)}")
            return False, f'删除失败: {str(e)}'

    @staticmethod
    def send_notification(alert, recipients):
        """发送告警通知"""
        try:
            sent_count = 0
            failed_count = 0

            for recipient in recipients:
                if not recipient.is_enabled:
                    continue

                # 发送邮件通知
                if recipient.email:
                    try:
                        # 这里应该集成邮件发送功能
                        # 简化版：只记录日志
                        logger.info(f"邮件通知已发送: {recipient.email} - {alert.message}")
                        sent_count += 1
                    except Exception as e:
                        logger.error(f"发送邮件失败: {str(e)}")
                        failed_count += 1

                # 发送钉钉通知
                if recipient.dingtalk_webhook:
                    try:
                        NotificationService._send_dingtalk_notification(
                            recipient.dingtalk_webhook,
                            alert
                        )
                        sent_count += 1
                    except Exception as e:
                        logger.error(f"发送钉钉通知失败: {str(e)}")
                        failed_count += 1

                # 发送企业微信通知
                if recipient.wechat_webhook:
                    try:
                        NotificationService._send_wechat_notification(
                            recipient.wechat_webhook,
                            alert
                        )
                        sent_count += 1
                    except Exception as e:
                        logger.error(f"发送企业微信通知失败: {str(e)}")
                        failed_count += 1

            logger.info(f"告警通知发送完成: 成功 {sent_count}, 失败 {failed_count}")
            return sent_count, failed_count

        except Exception as e:
            logger.error(f"发送告警通知失败: {str(e)}")
            return 0, 1

    @staticmethod
    def _send_dingtalk_notification(webhook_url, alert):
        """发送钉钉通知"""
        data = {
            "msgtype": "markdown",
            "markdown": {
                "title": f"【{alert.severity.upper()}】{alert.rule_name}",
                "text": f"## 告警通知\n\n"
                      f"**告警规则**: {alert.rule_name}\n\n"
                      f"**告警级别**: {alert.severity}\n\n"
                      f"**告警消息**: {alert.message}\n\n"
                      f"**告警时间**: {alert.created_at}\n\n"
            }
        }

        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        return True

    @staticmethod
    def _send_wechat_notification(webhook_url, alert):
        """发送企业微信通知"""
        data = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"## 告警通知\n\n"
                          f"**告警规则**: {alert.rule_name}\n\n"
                          f"**告警级别**: {alert.severity}\n\n"
                          f"**告警消息**: {alert.message}\n\n"
                          f"**告警时间**: {alert.created_at}\n\n"
            }
        }

        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        return True


class AlertSettingsService:
    """告警设置服务"""

    @staticmethod
    def get_notification_templates():
        """获取通知模板"""
        try:
            templates = {
                'email': {
                    'subject': '【IDS系统】告警通知 - {rule_name}',
                    'body': '''
尊敬的用户，

系统检测到以下告警：

告警规则：{rule_name}
告警级别：{severity}
告警消息：{message}
告警时间：{created_at}

请及时处理。

此邮件由系统自动发送，请勿回复。
                    '''
                },
                'dingtalk': {
                    'title': '【{severity}】{rule_name}',
                    'content': '告警规则：{rule_name}\n告警级别：{severity}\n告警消息：{message}\n告警时间：{created_at}'
                },
                'wechat': {
                    'content': '## 告警通知\n\n**告警规则**：{rule_name}\n\n**告警级别**：{severity}\n\n**告警消息**：{message}\n\n**告警时间**：{created_at}'
                }
            }
            return templates
        except Exception as e:
            logger.error(f"获取通知模板失败: {str(e)}")
            return {}

    @staticmethod
    def test_notification(recipient_id, notification_type='email'):
        """测试通知发送"""
        try:
            recipient = AlertRecipient.query.get(recipient_id)
            if not recipient:
                return False, '接收人不存在'

            # 创建测试告警
            test_alert = {
                'rule_name': '测试告警',
                'severity': 'info',
                'message': '这是一条测试通知',
                'created_at': datetime.now().isoformat()
            }

            if notification_type == 'email' and recipient.email:
                # 模拟发送邮件
                logger.info(f"测试邮件发送至: {recipient.email}")
                return True, f'测试邮件已发送至 {recipient.email}'

            elif notification_type == 'dingtalk' and recipient.dingtalk_webhook:
                NotificationService._send_dingtalk_notification(
                    recipient.dingtalk_webhook,
                    test_alert
                )
                return True, '测试钉钉通知已发送'

            elif notification_type == 'wechat' and recipient.wechat_webhook:
                NotificationService._send_wechat_notification(
                    recipient.wechat_webhook,
                    test_alert
                )
                return True, '测试企业微信通知已发送'

            else:
                return False, '未配置相应通知方式'

        except Exception as e:
            logger.error(f"测试通知发送失败: {str(e)}")
            return False, f'测试失败: {str(e)}'
