#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
系统管理服务模块
提供基本设置、邮件配置、数据备份恢复、维护模式等功能
"""

from datetime import datetime
from models_admin import db, SystemConfig, BackupRecord, User
from modules.admin.log_service import OperationLogger
import logging
import json
import os
import shutil
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class SystemConfigService:
    """系统配置服务"""

    # 默认系统配置
    DEFAULT_CONFIGS = {
        'system_name': 'IDS网络防御系统',
        'system_version': '1.0.0',
        'timezone': 'Asia/Shanghai',
        'language': 'zh_CN',
        'session_timeout': 3600,
        'max_login_attempts': 5,
        'login_lockout_duration': 900,
        'log_retention_days': 30,
        'backup_retention_days': 7,
        'enable_monitoring': True,
        'monitoring_interval': 5,
        'auto_cleanup_enabled': True,
        'auto_cleanup_time': '03:00'
    }

    @staticmethod
    def init_configs():
        """初始化默认系统配置"""
        try:
            for key, value in SystemConfigService.DEFAULT_CONFIGS.items():
                existing = SystemConfig.query.filter_by(key=key).first()
                if not existing:
                    config = SystemConfig(
                        key=key,
                        value=json.dumps(value),
                        description=f'{key} 配置项'
                    )
                    db.session.add(config)
            db.session.commit()
            logger.info("系统配置初始化完成")
            return True
        except Exception as e:
            logger.error(f"系统配置初始化失败: {str(e)}")
            db.session.rollback()
            return False

    @staticmethod
    def get_config(key, default=None):
        """获取单个配置"""
        try:
            config = SystemConfig.query.filter_by(key=key).first()
            if config:
                return json.loads(config.value)
            return default
        except Exception as e:
            logger.error(f"获取配置失败: {str(e)}")
            return default

    @staticmethod
    def get_all_configs():
        """获取所有配置"""
        try:
            configs = SystemConfig.query.all()
            result = {}
            for config in configs:
                try:
                    result[config.key] = json.loads(config.value)
                except:
                    result[config.key] = config.value
            return result
        except Exception as e:
            logger.error(f"获取所有配置失败: {str(e)}")
            return {}

    @staticmethod
    def set_config(key, value, description=None):
        """设置配置"""
        try:
            config = SystemConfig.query.filter_by(key=key).first()
            json_value = json.dumps(value, ensure_ascii=False)

            if config:
                old_value = config.value
                config.value = json_value
                if description:
                    config.description = description
                config.updated_at = datetime.utcnow()

                # 记录操作日志
                OperationLogger.log(
                    module='system',
                    action='update_config',
                    resource=f'config:{key}',
                    details={'old': old_value, 'new': json_value}
                )
            else:
                config = SystemConfig(
                    key=key,
                    value=json_value,
                    description=description or f'{key} 配置项'
                )
                db.session.add(config)

                # 记录操作日志
                OperationLogger.log(
                    module='system',
                    action='create_config',
                    resource=f'config:{key}',
                    details={'value': json_value}
                )

            db.session.commit()
            logger.info(f"设置配置成功: {key}")
            return True, '配置已保存'

        except Exception as e:
            db.session.rollback()
            logger.error(f"设置配置失败: {str(e)}")
            return False, f'保存失败: {str(e)}'

    @staticmethod
    def batch_set_configs(configs):
        """批量设置配置"""
        try:
            updated = []
            for key, value in configs.items():
                config = SystemConfig.query.filter_by(key=key).first()
                json_value = json.dumps(value, ensure_ascii=False)

                if config:
                    config.value = json_value
                    config.updated_at = datetime.utcnow()
                else:
                    config = SystemConfig(
                        key=key,
                        value=json_value,
                        description=f'{key} 配置项'
                    )
                    db.session.add(config)

                updated.append(key)

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='system',
                action='batch_update_config',
                resource='config',
                details={'updated': updated}
            )

            logger.info(f"批量更新配置成功: {len(updated)}项")
            return True, f'已更新 {len(updated)} 项配置'

        except Exception as e:
            db.session.rollback()
            logger.error(f"批量设置配置失败: {str(e)}")
            return False, f'批量保存失败: {str(e)}'

    @staticmethod
    def reset_to_default():
        """重置为默认配置"""
        try:
            count = 0
            for key, value in SystemConfigService.DEFAULT_CONFIGS.items():
                config = SystemConfig.query.filter_by(key=key).first()
                if config:
                    config.value = json.dumps(value, ensure_ascii=False)
                    config.updated_at = datetime.utcnow()
                    count += 1

            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='system',
                action='reset_config',
                resource='config',
                details={'reset_count': count}
            )

            logger.info("重置配置成功")
            return True, '已重置为默认配置'

        except Exception as e:
            db.session.rollback()
            logger.error(f"重置配置失败: {str(e)}")
            return False, f'重置失败: {str(e)}'


class MailConfigService:
    """邮件配置服务"""

    @staticmethod
    def get_mail_config():
        """获取邮件配置"""
        try:
            config = {
                'smtp_server': SystemConfigService.get_config('mail_smtp_server', 'smtp.gmail.com'),
                'smtp_port': SystemConfigService.get_config('mail_smtp_port', 587),
                'mail_username': SystemConfigService.get_config('mail_username', ''),
                'mail_from': SystemConfigService.get_config('mail_from', ''),
                'use_tls': SystemConfigService.get_config('mail_use_tls', True),
                'enabled': SystemConfigService.get_config('mail_enabled', False)
            }
            # 不返回密码
            return config
        except Exception as e:
            logger.error(f"获取邮件配置失败: {str(e)}")
            return {}

    @staticmethod
    def set_mail_config(smtp_server, smtp_port, username, password, mail_from, use_tls=True, enabled=False):
        """设置邮件配置"""
        try:
            SystemConfigService.set_config('mail_smtp_server', smtp_server, 'SMTP服务器地址')
            SystemConfigService.set_config('mail_smtp_port', smtp_port, 'SMTP端口')
            SystemConfigService.set_config('mail_username', username, '邮箱用户名')
            SystemConfigService.set_config('mail_password', password, '邮箱密码')
            SystemConfigService.set_config('mail_from', mail_from, '发件人地址')
            SystemConfigService.set_config('mail_use_tls', use_tls, '使用TLS加密')
            SystemConfigService.set_config('mail_enabled', enabled, '启用邮件通知')

            # 记录操作日志（不记录密码）
            OperationLogger.log(
                module='system',
                action='update_mail_config',
                resource='mail_config',
                details={'smtp_server': smtp_server, 'enabled': enabled}
            )

            logger.info("邮件配置已更新")
            return True, '邮件配置已保存'

        except Exception as e:
            logger.error(f"设置邮件配置失败: {str(e)}")
            return False, f'保存失败: {str(e)}'

    @staticmethod
    def send_test_mail(to_email):
        """发送测试邮件"""
        try:
            config = MailConfigService.get_mail_config()
            password = SystemConfigService.get_config('mail_password', '')

            if not config.get('enabled'):
                return False, '邮件服务未启用'

            msg = MIMEMultipart()
            msg['From'] = config['mail_from']
            msg['To'] = to_email
            msg['Subject'] = 'IDS系统测试邮件'

            body = f'''
这是一封来自IDS网络防御系统的测试邮件。

如果您收到此邮件，说明邮件配置正确。

系统时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

此邮件由系统自动发送，请勿回复。
            '''

            msg.attach(MIMEText(body, 'plain', 'utf-8'))

            if config['use_tls']:
                server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
                server.starttls()
            else:
                server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])

            server.login(config['mail_username'], password)
            server.send_message(msg)
            server.quit()

            logger.info(f"测试邮件已发送: {to_email}")
            return True, f'测试邮件已发送至 {to_email}'

        except Exception as e:
            logger.error(f"发送测试邮件失败: {str(e)}")
            return False, f'发送失败: {str(e)}'


class BackupService:
    """数据备份服务"""

    @staticmethod
    def get_backup_records(page=1, per_page=20):
        """获取备份记录"""
        try:
            pagination = BackupRecord.query.order_by(
                BackupRecord.created_at.desc()
            ).paginate(page=page, per_page=per_page, error_out=False)

            return pagination.items, pagination.total

        except Exception as e:
            logger.error(f"获取备份记录失败: {str(e)}")
            return [], 0

    @staticmethod
    def create_backup(description=None, created_by_id=None):
        """创建数据备份"""
        try:
            import sqlite3

            backup_dir = 'backups'
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f'ids_backup_{timestamp}.db'
            backup_path = os.path.join(backup_dir, backup_filename)

            # 获取当前数据库路径
            db_path = db.get_engine(app=None).url.database

            # 复制数据库文件
            shutil.copy2(db_path, backup_path)

            # 获取文件大小
            file_size = os.path.getsize(backup_path)

            # 创建备份记录
            record = BackupRecord(
                filename=backup_filename,
                file_path=backup_path,
                file_size=file_size,
                description=description or '手动备份',
                created_by=created_by_id
            )

            db.session.add(record)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='system',
                action='create_backup',
                resource=f'backup:{record.id}',
                details={'filename': backup_filename, 'size': file_size}
            )

            logger.info(f"数据备份创建成功: {backup_filename}")
            return True, record, '备份创建成功'

        except Exception as e:
            db.session.rollback()
            logger.error(f"创建数据备份失败: {str(e)}")
            return False, None, f'备份失败: {str(e)}'

    @staticmethod
    def restore_backup(backup_id, restored_by_id=None):
        """恢复数据备份"""
        try:
            import sqlite3

            record = BackupRecord.query.get(backup_id)
            if not record:
                return False, '备份记录不存在'

            backup_path = record.file_path
            if not os.path.exists(backup_path):
                return False, '备份文件不存在'

            # 获取当前数据库路径
            db_path = db.get_engine(app=None).url.database

            # 备份当前数据库
            current_backup = f'{db_path}.backup'
            shutil.copy2(db_path, current_backup)

            try:
                # 恢复数据库
                shutil.copy2(backup_path, db_path)

                # 记录操作日志
                OperationLogger.log(
                    module='system',
                    action='restore_backup',
                    resource=f'backup:{backup_id}',
                    details={'filename': record.filename}
                )

                logger.info(f"数据恢复成功: {record.filename}")
                return True, '数据恢复成功，请重启系统以生效'

            except Exception as e:
                # 恢复失败，回滚
                shutil.copy2(current_backup, db_path)
                os.remove(current_backup)
                raise e

        except Exception as e:
            logger.error(f"恢复数据备份失败: {str(e)}")
            return False, f'恢复失败: {str(e)}'

    @staticmethod
    def delete_backup(backup_id):
        """删除备份"""
        try:
            record = BackupRecord.query.get(backup_id)
            if not record:
                return False, '备份记录不存在'

            backup_path = record.file_path
            filename = record.filename

            # 删除文件
            if os.path.exists(backup_path):
                os.remove(backup_path)

            # 删除记录
            db.session.delete(record)
            db.session.commit()

            # 记录操作日志
            OperationLogger.log(
                module='system',
                action='delete_backup',
                resource=f'backup:{backup_id}',
                details={'filename': filename}
            )

            logger.info(f"删除备份成功: {filename}")
            return True, '备份已删除'

        except Exception as e:
            db.session.rollback()
            logger.error(f"删除备份失败: {str(e)}")
            return False, f'删除失败: {str(e)}'

    @staticmethod
    def cleanup_old_backups():
        """清理过期备份"""
        try:
            retention_days = SystemConfigService.get_config('backup_retention_days', 7)
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            old_records = BackupRecord.query.filter(
                BackupRecord.created_at < cutoff_date
            ).all()

            count = 0
            for record in old_records:
                # 删除文件
                if os.path.exists(record.file_path):
                    os.remove(record.file_path)
                # 删除记录
                db.session.delete(record)
                count += 1

            db.session.commit()

            if count > 0:
                logger.info(f"清理过期备份: {count}条")
                # 记录操作日志
                OperationLogger.log(
                    module='system',
                    action='cleanup_backups',
                    resource='backup',
                    details={'count': count}
                )

            return count

        except Exception as e:
            db.session.rollback()
            logger.error(f"清理过期备份失败: {str(e)}")
            return 0


class MaintenanceService:
    """维护模式服务"""

    @staticmethod
    def is_maintenance_mode():
        """检查是否处于维护模式"""
        return SystemConfigService.get_config('maintenance_mode', False)

    @staticmethod
    def set_maintenance_mode(enabled, message=None, set_by_id=None):
        """设置维护模式"""
        try:
            SystemConfigService.set_config('maintenance_mode', enabled, '维护模式开关')
            SystemConfigService.set_config('maintenance_message', message or '系统正在维护中，请稍后再访问', '维护模式提示信息')

            # 记录操作日志
            OperationLogger.log(
                module='system',
                action='set_maintenance',
                resource='maintenance',
                details={'enabled': enabled, 'message': message}
            )

            status = '开启' if enabled else '关闭'
            logger.info(f"维护模式已{status}")
            return True, f'维护模式已{status}'

        except Exception as e:
            logger.error(f"设置维护模式失败: {str(e)}")
            return False, f'设置失败: {str(e)}'

    @staticmethod
    def get_maintenance_status():
        """获取维护模式状态"""
        try:
            return {
                'enabled': SystemConfigService.get_config('maintenance_mode', False),
                'message': SystemConfigService.get_config('maintenance_message', '系统正在维护中，请稍后再访问'),
                'start_time': SystemConfigService.get_config('maintenance_start_time'),
                'end_time': SystemConfigService.get_config('maintenance_end_time')
            }
        except Exception as e:
            logger.error(f"获取维护模式状态失败: {str(e)}")
            return {'enabled': False, 'message': ''}


from datetime import timedelta
