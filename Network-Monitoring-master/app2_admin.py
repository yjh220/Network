#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络入侵检测与防御系统 - 主应用（集成后台管理版本）
基于 app2.py 添加完整的后台管理功能
"""

import os
import time
import threading
import logging
import sys
import random
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# 导入后台管理相关
from models_admin import db, User, Role, Permission, LoginLog, BlockedIP, DefenseRule
from models_monitor import (
    MonitorConfig, IPWhitelist, TrafficStats,
    NetworkInterface, ProtocolConfig, TrafficCleanup
)
from routes_admin import admin_bp
from modules.admin.permissions import PermissionManager
from modules.admin.log_service import LoginLogger, OperationLogger, setup_logging
from modules.admin.admin_service import UserService

# 导入原有模块
from modules.traffic_detection.detector import TrafficDetector
from modules.intrusion_prevention.prevention import IntrusionPrevention
from modules.alert_response.alerter import AlertSystem
from modules.network_monitoring.monitor import NetworkMonitor

# 导入自定义模块 - 新增异常检测模块
from modules.pocket_detection.detector import TrafficDetector as PocketDetector
from modules.threat_find.ThreatFind import ThreatFind

# 导入模拟数据生成器（用于演示）
from mock_traffic_generator import mock_generator

# 导入攻击流量注入器（用于生成攻击流量）
from attack_traffic_injector import attack_injector

# 配置日志
logger = logging.getLogger(__name__)


# 资源路径函数
def resource_path(relative_path):
    """获取 PyInstaller 打包后资源路径"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=1)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)

# 初始化数据库
db.init_app(app)

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'
login_manager.login_message_category = 'warning'


# 确保模板上下文包含 current_user
@app.context_processor
def inject_user():
    """注入 current_user 到所有模板"""
    from flask_login import current_user
    return dict(current_user=current_user)


@login_manager.user_loader
def load_user(user_id):
    """加载用户"""
    try:
        return User.query.get(int(user_id))
    except:
        return None

# 创建数据目录
os.makedirs('data', exist_ok=True)

# 设置日志系统
setup_logging(app)

# 初始化系统模块
traffic_detector = TrafficDetector()
intrusion_prevention = IntrusionPrevention()
alert_system = AlertSystem()
network_monitor = NetworkMonitor(socketio)

# 新增异常检测模块
try:
    model_path = resource_path("model/randomforest_model.pkl")
    pipeline_path = resource_path("model/preprocessing_pipeline.pkl")
    pocket_detector = PocketDetector()
    flow_feature = ThreatFind(None, socketio, model_path, pipeline_path)
    threat_detection_available = True
    logger.info("异常检测模块初始化成功")
except Exception as e:
    logger.error(f"异常检测模块初始化失败: {str(e)}")
    threat_detection_available = False

    class DummyDetector:
        def start_capture(self):
            logger.info("异常检测模块不可用，跳过启动")
        def stop_capture(self):
            logger.info("异常检测模块不可用，跳过停止")
        def get_pcapfiles(self): return []
        def get_traffic_stats(self): return {}
        def get_recent_traffic(self, n): return []
        def analyze_packet(self, data): return {}

    class DummyThreatFind:
        def start_extract(self, files):
            logger.info("异常检测模块不可用，跳过特征提取")
        def getFeatures(self): return []
        def extractFeature(self, file_path):
            logger.info("异常检测模块不可用，跳过特征提取")
        def parse_csv(self, file_path): return []
        def predictThreat(self): return None

    pocket_detector = DummyDetector()
    flow_feature = DummyThreatFind()

# 注册后台管理蓝图
app.register_blueprint(admin_bp)

# 管理系统状态
system_status = {
    'is_running': False,
    'start_time': None,
    'processed_packets': 0,
    'detected_threats': 0,
    'blocked_attacks': 0,
    'threat_detection_available': threat_detection_available
}

# IP阻止管理
blocked_ips = set()


# ==================== 认证路由 ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if current_user.is_authenticated:
        return redirect(url_for('admin.console'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        # 查找用户
        user = User.query.filter_by(username=username).first()

        if not user:
            LoginLogger.log_login(username, success=False, failure_reason='用户不存在')
            flash('用户名或密码错误', 'error')
            return render_template('login.html')

        # 检查账户状态
        if not user.is_active:
            LoginLogger.log_login(username, success=False, failure_reason='账户已被禁用', user_id=user.id)
            flash('账户已被禁用', 'error')
            return render_template('login.html')

        # 检查账户锁定
        if user.is_locked():
            LoginLogger.log_login(username, success=False, failure_reason='账户已被锁定', user_id=user.id)
            flash('账户已被锁定，请稍后再试', 'error')
            return render_template('login.html')

        # 验证密码
        if not user.check_password(password):
            LoginLogger.log_login(username, success=False, failure_reason='密码错误', user_id=user.id)
            user.increment_failed_attempts()
            flash('用户名或密码错误', 'error')
            return render_template('login.html')

        # 登录成功
        login_user(user, remember=remember)
        user.update_last_login(request.remote_addr)
        LoginLogger.log_login(username, success=True, user_id=user.id)

        # 记录操作日志
        OperationLogger.log('auth', 'login', details={'ip': request.remote_addr})

        next_page = request.args.get('next')
        return redirect(next_page or url_for('admin.console'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册（仅开放给第一个用户注册）"""
    # 检查是否已有用户
    if User.query.count() > 0:
        flash('系统已有用户，请联系管理员创建账户', 'warning')
        return redirect(url_for('login'))

    if current_user.is_authenticated:
        return redirect(url_for('admin.console'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return render_template('register.html')

        # 获取admin角色
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            flash('系统初始化错误，请先初始化权限数据', 'error')
            return render_template('register.html')

        success, user, message = UserService.create_user(
            username=username,
            email=email,
            password=password,
            role_id=admin_role.id
        )

        if success:
            login_user(user)
            flash('注册成功！欢迎加入', 'success')
            return redirect(url_for('admin.console'))
        else:
            flash(message, 'error')

    return render_template('register.html')


@app.route('/logout')
def logout():
    """用户登出"""
    from flask import session

    current_username = current_user.username if current_user.is_authenticated else 'None'

    logout_user()
    session.clear()

    response = redirect(url_for('login'))
    response.delete_cookie('remember_token', path='/')
    response.delete_cookie('session', path='/')

    OperationLogger.log('auth', 'logout', details={'username': current_username})
    logger.info(f"用户已退出: {current_username}")
    flash('您已成功退出', 'info')
    return response


@app.route('/')
def index():
    """首页 - 根据登录状态跳转"""
    if current_user.is_authenticated:
        return redirect(url_for('admin.console'))
    return redirect(url_for('login'))


@app.route('/admin')
def admin_redirect():
    """后台管理入口 - 根据登录状态跳转"""
    if current_user.is_authenticated:
        return redirect(url_for('admin.console'))
    return redirect(url_for('login'))


# ==================== 原有功能路由 ====================

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@app.route('/network_monitor')
@login_required
def network_monitor_page():
    return render_template('network_monitor.html')


@app.route('/intrusion_detection')
@login_required
def intrusion_detection_page():
    return render_template('intrusion_detection.html')


# ==================== API路由 - 系统控制 ====================

@app.route('/api/status')
def get_status():
    return jsonify(system_status)


@app.route('/api/start', methods=['POST'])
def start_system():
    if not system_status['is_running']:
        system_status['is_running'] = True
        system_status['start_time'] = time.time()

        try:
            threading.Thread(target=traffic_detector.start_capture, daemon=True).start()
            threading.Thread(target=intrusion_prevention.start_prevention, daemon=True).start()
            threading.Thread(target=alert_system.start_alerting, daemon=True).start()
            threading.Thread(target=network_monitor.start_monitoring, daemon=True).start()

            if threat_detection_available:
                threading.Thread(target=pocket_detector.start_capture, daemon=True).start()
                logger.info("异常检测模块已启动")

            attack_injector.start_injection(interval=8)
            logger.info("攻击流量注入器已启动")
            logger.info("系统已启动")

            # 记录操作日志
            OperationLogger.log('system', 'start', 'system', details={'modules': 'all'})

            return jsonify({
                'success': True,
                'message': '系统已启动',
                'threat_detection_available': threat_detection_available
            })

        except Exception as e:
            system_status['is_running'] = False
            logger.error(f"系统启动失败: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'系统启动失败: {str(e)}'
            })

    return jsonify({'success': False, 'message': '系统已在运行中'})


@app.route('/api/stop', methods=['POST'])
def stop_system():
    if system_status['is_running']:
        system_status['is_running'] = False

        try:
            traffic_detector.stop_capture()
            intrusion_prevention.stop_prevention()
            alert_system.stop_alerting()
            network_monitor.stop_monitoring()

            if threat_detection_available:
                pocket_detector.stop_capture()
                files = pocket_detector.get_pcapfiles()

                if len(files) > 0:
                    threading.Thread(target=flow_feature.start_extract, args=(files,), daemon=True).start()
                    logger.info("开始进行威胁分析")
                    return jsonify({
                        'success': True,
                        'warning': False,
                        'message': '系统已停止，正在进行威胁分析',
                        'files_analyzed': len(files)
                    })
                else:
                    return jsonify({
                        'success': True,
                        'warning': True,
                        'message': '系统已停止，但未捕获到足够的包进行威胁分析'
                    })
            else:
                logger.info("系统已停止（异常检测模块不可用）")
                OperationLogger.log('system', 'stop', 'system')
                return jsonify({
                    'success': True,
                    'message': '系统已停止',
                    'threat_detection_available': False
                })

        except Exception as e:
            logger.error(f"系统停止过程中出错: {str(e)}")
            return jsonify({
                'success': True,
                'warning': True,
                'message': f'系统已停止，但出现错误: {str(e)}'
            })

    return jsonify({'success': False, 'message': '系统未运行'})


# ==================== Socket.IO 事件 ====================

@socketio.on('connect')
def handle_connect():
    logger.info(f"客户端已连接: {request.sid}")
    socketio.emit('system_status', system_status)


@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"客户端已断开连接: {request.sid}")


@socketio.on('request_status')
def handle_status_request():
    socketio.emit('system_status', system_status)


# ==================== 错误处理 ====================

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/admin'):
        # 后台管理404 - 返回JSON或重定向到登录
        if current_user.is_authenticated:
            return jsonify({'error': '页面不存在'}), 404
        else:
            return redirect(url_for('login'))
    # 前台404 - 简单处理
    return jsonify({'error': 'Not Found'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"服务器内部错误: {str(error)}")
    return jsonify({'error': '服务器内部错误'}), 500


# ==================== 初始化命令 ====================

@app.cli.command()
def init_admin():
    """初始化后台管理数据"""
    with app.app_context():
        print("正在初始化权限数据...")
        if PermissionManager.init_permissions():
            print("✓ 权限初始化成功")
        else:
            print("✗ 权限初始化失败")

        print("正在初始化角色数据...")
        if PermissionManager.init_roles():
            print("✓ 角色初始化成功")
        else:
            print("✗ 角色初始化失败")

        print("\n初始化完成！")


@app.cli.command()
def init_monitor():
    """初始化监控数据"""
    with app.app_context():
        from modules.admin.monitor_service import MonitorConfigService, ProtocolConfigService, NetworkInterfaceService

        print("正在初始化监控配置...")
        if MonitorConfigService.init_configs():
            print("✓ 监控配置初始化成功")
        else:
            print("✗ 监控配置初始化失败")

        print("正在初始化协议配置...")
        if ProtocolConfigService.init_protocols():
            print("✓ 协议配置初始化成功")
        else:
            print("✗ 协议配置初始化失败")

        print("正在同步网卡信息...")
        success, message = NetworkInterfaceService.sync_interfaces()
        if success:
            print(f"✓ 网卡同步成功")
        else:
            print(f"✗ 网卡同步失败: {message}")

        print("\n监控数据初始化完成！")


@app.cli.command()
def create_admin():
    """创建管理员账户"""
    with app.app_context():
        username = input("请输入管理员用户名: ")
        email = input("请输入邮箱: ")
        password = input("请输入密码: ")

        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            print("错误: admin角色不存在，请先运行 init-admin")
            return

        success, user, message = UserService.create_user(
            username=username,
            email=email,
            password=password,
            role_id=admin_role.id
        )

        if success:
            print(f"✓ 管理员账户创建成功: {username}")
        else:
            print(f"✗ 创建失败: {message}")


# ==================== 主函数 ====================

if __name__ == '__main__':
    try:
        logger.info("网络入侵检测与防御系统启动中...")
        logger.info(f"异常检测模块状态: {'可用' if threat_detection_available else '不可用'}")

        # 确保数据库表已创建
        with app.app_context():
            db.create_all()
            logger.info("数据库表检查完成")

            # 如果没有任何用户，提示初始化
            if User.query.count() == 0:
                print("\n" + "=" * 50)
                print("检测到系统尚未初始化！")
                print("请执行以下命令初始化系统:")
                print("  flask init-admin      # 初始化权限和角色")
                print("  flask create-admin    # 创建管理员账户")
                print("=" * 50 + "\n")

        # 启动模拟数据生成器
        mock_generator.start_generation(packets_per_second=3)
        logger.info("模拟流量生成器已启动")

        print("=" * 50)
        print("系统已启动！")
        print("访问地址: http://127.0.0.1:8080")
        print("后台管理: http://127.0.0.1:8080/admin")
        print("=" * 50)

        socketio.run(app,
                     host='127.0.0.1',
                     port=8080,
                     debug=True,
                     allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"系统启动失败: {str(e)}")
        print(f"系统启动失败: {str(e)}")
