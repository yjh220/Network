#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
后台管理日志服务模块
提供登录日志、操作日志、系统日志的记录功能
"""

from datetime import datetime
from flask import request
from flask_login import current_user
from models_admin import db, LoginLog, OperationLog, SystemLog
import logging
import json
import traceback

logger = logging.getLogger(__name__)


class LoginLogger:
    """登录日志记录器"""

    @staticmethod
    def log_login(username, success=True, failure_reason=None, user_id=None):
        """
        记录登录日志

        Args:
            username: 用户名
            success: 是否成功
            failure_reason: 失败原因
            user_id: 用户ID
        """
        try:
            ip_address = LoginLogger._get_client_ip()
            user_agent = request.headers.get('User-Agent', '')[:500]

            login_log = LoginLog(
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                status='success' if success else 'failed',
                failure_reason=failure_reason
            )

            db.session.add(login_log)
            db.session.commit()

            logger.info(f"登录日志记录: {username} - {ip_address} - {'成功' if success else '失败'}")
        except Exception as e:
            logger.error(f"记录登录日志失败: {str(e)}")
            db.session.rollback()

    @staticmethod
    def _get_client_ip():
        """获取客户端真实IP"""
        if request.headers.getlist("X-Forwarded-For"):
            return request.headers.getlist("X-Forwarded-For")[0]
        return request.remote_addr


class OperationLogger:
    """操作日志记录器"""

    @staticmethod
    def log(module, action, resource=None, details=None, status='success'):
        """
        记录操作日志

        Args:
            module: 操作模块 (user, role, system, etc.)
            action: 操作类型 (create, update, delete, view, etc.)
            resource: 操作资源 (用户ID, 角色名等)
            details: 操作详情 (字典格式)
            status: 操作状态 (success, failed)
        """
        try:
            username = current_user.username if current_user.is_authenticated else 'system'
            user_id = current_user.id if current_user.is_authenticated else None
            ip_address = request.remote_addr if request else None

            operation_log = OperationLog(
                user_id=user_id,
                username=username,
                module=module,
                action=action,
                resource=resource,
                details=json.dumps(details, ensure_ascii=False) if details else None,
                ip_address=ip_address,
                status=status
            )

            db.session.add(operation_log)
            db.session.commit()

            logger.info(f"操作日志记录: {username} - {module}.{action} - {resource or 'N/A'}")
        except Exception as e:
            logger.error(f"记录操作日志失败: {str(e)}")
            db.session.rollback()


class SystemLogger:
    """系统日志记录器"""

    @staticmethod
    def log(level, module, message, details=None, extra_info=None):
        """
        记录系统日志

        Args:
            level: 日志级别 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            module: 所属模块
            message: 日志消息
            details: 详细信息 (字典格式)
            extra_info: 额外信息 (包含file_path, line_number, function)
        """
        try:
            system_log = SystemLog(
                level=level,
                module=module,
                message=message,
                details=json.dumps(details, ensure_ascii=False) if details else None,
                file_path=extra_info.get('file_path') if extra_info else None,
                line_number=extra_info.get('line_number') if extra_info else None,
                function=extra_info.get('function') if extra_info else None
            )

            db.session.add(system_log)
            db.session.commit()

            # 同时写入文件日志
            log_func = getattr(logger, level.lower(), logger.info)
            log_msg = f"[{module}] {message}"
            if details:
                log_msg += f" - {json.dumps(details, ensure_ascii=False)}"
            log_func(log_msg)

        except Exception as e:
            logger.error(f"记录系统日志失败: {str(e)}")
            db.session.rollback()


class DatabaseLogHandler(logging.Handler):
    """
    自定义日志处理器 - 将日志写入数据库
    用法: logger.addHandler(DatabaseLogHandler())
    """

    def emit(self, record):
        """处理日志记录"""
        try:
            # 解析日志级别
            level = record.levelname

            # 解析模块名 (从logger名称获取)
            module = record.name.split('.')[-1] if '.' in record.name else record.name

            # 获取日志消息
            message = self.format(record)

            # 准备详细信息
            details = {
                'thread': record.thread,
                'processName': record.processName,
            }
            if hasattr(record, 'created'):
                details['timestamp'] = record.created

            # 额外信息
            extra_info = {
                'file_path': record.pathname,
                'line_number': record.lineno,
                'function': record.funcName
            }

            # 记录到数据库
            SystemLogger.log(
                level=level,
                module=module,
                message=message,
                details=details,
                extra_info=extra_info
            )

        except Exception:
            # 避免日志记录本身导致问题
            self.handleError(record)


def setup_logging(app):
    """
    配置应用日志系统

    Args:
        app: Flask应用实例
    """
    # 创建日志目录
    import os
    log_dir = os.path.join(app.root_path, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # 配置日志格式
    log_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 文件处理器 - 所有日志
    file_handler = logging.FileHandler(
        os.path.join(log_dir, 'ids_system.log'),
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_format)

    # 文件处理器 - 错误日志
    error_handler = logging.FileHandler(
        os.path.join(log_dir, 'ids_error.log'),
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(log_format)

    # 数据库日志处理器
    db_handler = DatabaseLogHandler()
    db_handler.setLevel(logging.WARNING)

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(log_format)

    # 配置应用日志器
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(error_handler)
    app.logger.addHandler(db_handler)

    # 配置第三方库日志
    for logger_name in ['socketio', 'engineio', 'werkzeug']:
        log = logging.getLogger(logger_name)
        log.setLevel(logging.WARNING)
        log.addHandler(file_handler)

    logger.info("日志系统初始化完成")
