#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

# ==================== 首先导入并设置统一的User模型 ====================
# 使用models_admin中的db作为统一的数据库实例
from models_admin import db, User, Role, Permission

# 兼容性导入：为其他模块提供models引用
import models
models.db = db
models.User = User

# ==================== 然后导入其他模块 ====================

# 导入自定义模块 - 原有模块（延迟导入以避免启动阻塞）
# from modules.traffic_detection.detector import TrafficDetector
# from modules.intrusion_prevention.prevention import IntrusionPrevention
# from modules.alert_response.alerter import AlertSystem
# from modules.network_monitoring.monitor import NetworkMonitor

# 导入后台管理相关模块
from routes_admin import admin_bp
from modules.admin.permissions import PermissionManager

# 导入认证相关模块（需要在User设置之后）
from modules.auth.auth import AuthManager

# 导入自定义模块 - 新增异常检测模块（延迟导入）
# from modules.pocket_detection.detector import TrafficDetector as PocketDetector
# from modules.threat_find.ThreatFind import ThreatFind

# 导入模拟数据生成器（用于演示）
from mock_traffic_generator import mock_generator

# 导入攻击流量注入器（用于生成攻击流量）- 暂时注释，使用了Scapy会导致启动阻塞
# from attack_traffic_injector import attack_injector
attack_injector = None

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('data/ids_system.log')
    ]
)
logger = logging.getLogger(__name__)


# 资源路径函数（从第一个项目）
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
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*", manage_session=False)

# 初始化数据库（使用models_admin中的db）
db.init_app(app)

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'
login_manager.login_message_category = 'warning'


# 确保模板上下文包含 current_user 和辅助函数
@app.context_processor
def inject_user():
    """注入 current_user 到所有模板"""
    from flask_login import current_user

    # 为 current_user 添加 is_admin 方法（如果不存在）
    def is_admin_check():
        if not current_user.is_authenticated:
            return False
        if hasattr(current_user, 'is_admin'):
            return current_user.is_admin()
        elif hasattr(current_user, 'role'):
            if isinstance(current_user.role, str):
                return current_user.role == 'admin'
            elif hasattr(current_user.role, 'name'):
                return current_user.role.name == 'admin'
        return False

    return dict(
        current_user=current_user,
        is_admin=is_admin_check
    )


@login_manager.user_loader
def load_user(user_id):
    """加载用户 - 支持两种User模型"""
    try:
        from models_admin import User as AdminUser
        user = AdminUser.query.get(int(user_id))
        if user:
            return user
    except:
        pass

    # 如果后台管理User没找到，尝试前台User
    try:
        from models import User as FrontUser
        return FrontUser.query.get(int(user_id))
    except:
        return None

# 创建数据目录
os.makedirs('data', exist_ok=True)

# 初始化系统模块（延迟初始化以避免启动阻塞）
traffic_detector = None
intrusion_prevention = None
alert_system = None
network_monitor = None

def init_system_modules():
    """延迟初始化系统模块"""
    global traffic_detector, intrusion_prevention, alert_system, network_monitor
    if traffic_detector is None:
        try:
            from modules.traffic_detection.detector import TrafficDetector
            traffic_detector = TrafficDetector()
            logger.info("TrafficDetector 初始化成功")
        except Exception as e:
            logger.warning(f"TrafficDetector 初始化失败: {e}")

    if intrusion_prevention is None:
        try:
            from modules.intrusion_prevention.prevention import IntrusionPrevention
            intrusion_prevention = IntrusionPrevention()
            logger.info("IntrusionPrevention 初始化成功")
        except Exception as e:
            logger.warning(f"IntrusionPrevention 初始化失败: {e}")

    if alert_system is None:
        try:
            from modules.alert_response.alerter import AlertSystem
            alert_system = AlertSystem()
            logger.info("AlertSystem 初始化成功")
        except Exception as e:
            logger.warning(f"AlertSystem 初始化失败: {e}")

    if network_monitor is None:
        try:
            from modules.network_monitoring.monitor import NetworkMonitor
            network_monitor = NetworkMonitor(socketio)
            logger.info("NetworkMonitor 初始化成功")
        except Exception as e:
            logger.warning(f"NetworkMonitor 初始化失败: {e}")

    # 初始化完成后，将模块添加到app
    app.traffic_detector = traffic_detector
    app.intrusion_prevention = intrusion_prevention
    app.alert_system = alert_system
    app.network_monitor = network_monitor

    # 将Flask app传入各模块，用于数据库同步
    try:
        from modules.intrusion_prevention.prevention import init_with_app as prevention_init_with_app
        prevention_init_with_app(app)
    except Exception as e:
        logger.warning(f"prevention_init_with_app 失败: {e}")

    try:
        from modules.alert_response.alerter import init_with_app as alerter_init_with_app
        alerter_init_with_app(app)
    except Exception as e:
        logger.warning(f"alerter_init_with_app 失败: {e}")

# 在后台线程中初始化模块
def async_init_modules():
    import threading
    def init_worker():
        import time
        time.sleep(1)  # 给Flask一点时间启动
        init_system_modules()
    thread = threading.Thread(target=init_worker, daemon=True)
    thread.start()

# 导出同步函数供其他模块使用
__all__ = ['sync_blocked_ip_to_db', 'sync_unblocked_ip_to_db', 'create_alert_in_db']

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


    # 创建虚拟对象以避免后续调用错误
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


# ==================== 前后台数据同步服务 ====================

def sync_blocked_ip_to_db(ip_address, threat_type='auto_block', reason='自动封禁'):
    """同步封禁IP到数据库"""
    try:
        with app.app_context():
            from models_admin import BlockedIP
            existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
            if not existing:
                blocked = BlockedIP(
                    ip_address=ip_address,
                    reason=reason,
                    threat_type=threat_type,
                    source='system',
                    blocked_at=datetime.utcnow()
                )
                db.session.add(blocked)
                db.session.commit()
                logger.info(f"IP封禁已同步到数据库: {ip_address}")
            elif not existing.is_active:
                existing.is_active = True
                existing.blocked_at = datetime.utcnow()
                db.session.commit()
                logger.info(f"IP封禁已更新到数据库: {ip_address}")
    except Exception as e:
        logger.error(f"同步IP封禁到数据库失败: {str(e)}")


def sync_unblocked_ip_to_db(ip_address):
    """同步解封IP到数据库"""
    try:
        with app.app_context():
            from models_admin import BlockedIP
            existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
            if existing and existing.is_active:
                existing.is_active = False
                db.session.commit()
                logger.info(f"IP解封已同步到数据库: {ip_address}")
    except Exception as e:
        logger.error(f"同步IP解封到数据库失败: {str(e)}")


def create_alert_in_db(rule_name, severity, message, details=None):
    """在数据库中创建告警记录"""
    try:
        with app.app_context():
            from models_admin import AlertRecord, AlertRule
            alert_rule = AlertRule.query.filter_by(name=rule_name).first()

            alert = AlertRecord(
                rule_id=alert_rule.id if alert_rule else None,
                rule_name=rule_name,
                severity=severity,
                message=message
            )

            if details:
                import json
                alert.details = json.dumps(details, ensure_ascii=False)

            db.session.add(alert)
            db.session.commit()
            logger.info(f"告警已记录到数据库: {rule_name} - {message}")
    except Exception as e:
        logger.error(f"创建告警记录失败: {str(e)}")


# ==================== 后台管理系统集成 ====================

# 注册后台管理蓝图
app.register_blueprint(admin_bp)

# 后台管理数据初始化
def init_admin_data():
    """初始化后台管理数据"""
    with app.app_context():
        try:
            # 导入所有模型以确保表被创建
            from models_admin import (
                LoginLog, OperationLog, SystemLog,
                BlockedIP, DefenseRule, AlertRule, AlertRecord,
                AlertRecipient, SystemConfig, BackupRecord
            )
            from models_monitor import (
                MonitorConfig, IPWhitelist, TrafficStats,
                NetworkInterface, ProtocolConfig, TrafficCleanup
            )

            # 创建所有表
            db.create_all()
            logger.info("数据库表创建完成")

            # 初始化权限
            try:
                PermissionManager.init_permissions()
                logger.info("权限初始化完成")
            except Exception as e:
                logger.warning(f"权限初始化警告: {str(e)}")

            # 初始化角色
            try:
                PermissionManager.init_roles()
                logger.info("角色初始化完成")
            except Exception as e:
                logger.warning(f"角色初始化警告: {str(e)}")

            # 检查是否有管理员用户，如果没有则创建默认管理员
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                # 获取admin角色
                from models_admin import Role
                admin_role = Role.query.filter_by(name='admin').first()
                if not admin_role:
                    # 如果admin角色不存在，创建一个
                    admin_role = Role(name='admin', description='系统管理员')
                    db.session.add(admin_role)
                    db.session.flush()

                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    role_id=admin_role.id,
                    is_active=True
                )
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
                logger.info("默认管理员账户已创建 (admin/admin123)")
            else:
                # 确保现有管理员有正确的角色
                from models_admin import Role
                admin_role = Role.query.filter_by(name='admin').first()
                if admin_role and admin_user.role_id != admin_role.id:
                    admin_user.role_id = admin_role.id
                    db.session.commit()

            # 初始化系统配置
            try:
                from modules.admin.system_service import SystemConfigService
                SystemConfigService.init_configs()
                logger.info("系统配置初始化完成")
            except Exception as e:
                logger.warning(f"系统配置初始化警告: {str(e)}")

            # 初始化防御策略
            try:
                from modules.admin.defense_service import DefensePolicyService
                DefensePolicyService.init_policies()
                logger.info("防御策略初始化完成")
            except Exception as e:
                logger.warning(f"防御策略初始化警告: {str(e)}")

            # 初始化告警规则
            try:
                from modules.admin.alert_service import AlertRuleService
                AlertRuleService.init_alert_rules()
                logger.info("告警规则初始化完成")
            except Exception as e:
                logger.warning(f"告警规则初始化警告: {str(e)}")

            # 初始化威胁检测规则
            try:
                from modules.admin.threat_service import DetectionRuleService
                DetectionRuleService.init_rules()
                logger.info("威胁检测规则初始化完成")
            except Exception as e:
                logger.warning(f"威胁检测规则初始化警告: {str(e)}")

        except Exception as e:
            logger.error(f"后台管理数据初始化失败: {str(e)}")


# ==================== 认证路由 ====================


# 权限检查装饰器
def admin_required(f):
    """管理员权限检查装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        if not current_user.is_admin():
            flash('您没有权限访问此页面', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# 认证路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        success, user, message = AuthManager.authenticate_user(username, password)

        if success:
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash(message, 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return render_template('register.html')

        success, user, message = AuthManager.register_user(username, email, password)

        if success:
            # 注册成功后自动登录
            login_user(user)
            flash('注册成功！欢迎加入', 'success')
            return redirect(url_for('index'))
        else:
            flash(message, 'error')

    return render_template('register.html')


@app.route('/logout')
def logout():
    """用户登出"""
    from flask import session

    # 记录当前用户名用于日志
    current_username = current_user.username if current_user.is_authenticated else 'None'

    # 清除用户会话
    logout_user()

    # 清除所有session数据
    session.clear()

    # 创建响应并清除remember me cookie
    response = redirect(url_for('login'))
    response.delete_cookie('remember_token', path='/')
    response.delete_cookie('session', path='/')

    logger.info(f"用户已退出: {current_username}")
    flash('您已成功退出', 'info')
    return response


@app.route('/api/auth_status')
def auth_status():
    """检查当前登录状态（用于调试）"""
    return jsonify({
        'is_authenticated': current_user.is_authenticated,
        'user_id': current_user.id if current_user.is_authenticated else None,
        'username': current_user.username if current_user.is_authenticated else None,
        'is_admin': current_user.is_admin() if current_user.is_authenticated else False
    })


# 管理员权限装饰器
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('需要管理员权限', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# 管理员路由
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """用户管理页面"""
    return render_template('admin_users.html')


# API路由 - 管理员功能
@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def get_users_api():
    """获取所有用户"""
    try:
        users = AuthManager.get_all_users()
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in users]
        })
    except Exception as e:
        logger.error(f"获取用户列表失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user_api():
    """创建用户"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'user')

        success, user, message = AuthManager.register_user(username, email, password, role)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400
    except Exception as e:
        logger.error(f"创建用户失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/delete_user', methods=['POST'])
@login_required
@admin_required
def delete_user_api():
    """删除用户"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')

        if user_id == current_user.id:
            return jsonify({'success': False, 'message': '不能删除自己的账户'}), 400

        success, message = AuthManager.delete_user(user_id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400
    except Exception as e:
        logger.error(f"删除用户失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/update_role', methods=['POST'])
@login_required
@admin_required
def update_role_api():
    """更新用户角色"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')

        if user_id == current_user.id:
            return jsonify({'success': False, 'message': '不能修改自己的角色'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 400

        new_role = 'admin' if user.role == 'user' else 'user'
        success, message = AuthManager.update_user_role(user_id, new_role)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400
    except Exception as e:
        logger.error(f"更新用户角色失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/toggle_active', methods=['POST'])
@login_required
@admin_required
def toggle_active_api():
    """切换用户激活状态"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')

        if user_id == current_user.id:
            return jsonify({'success': False, 'message': '不能禁用自己的账户'}), 400

        success, message = AuthManager.toggle_user_active(user_id)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400
    except Exception as e:
        logger.error(f"切换用户状态失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


# 路由定义
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('home.html')
    return render_template('index.html')


@app.route('/home')
@login_required
def home():
    """登录后的主页"""
    return render_template('home.html')


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


# 新增路由 - 实时监控和威胁检测页面
@app.route('/network_monitor')
@login_required
def network_monitor_page():
    return render_template('network_monitor.html')


@app.route('/network_monitor_simple')
def network_monitor_simple_page():
    """简化版网络监控页面 - 无需登录"""
    return render_template('network_monitor_simple.html')


@app.route('/network_monitor_working')
def network_monitor_working_page():
    """工作版网络监控页面 - 无需登录"""
    return render_template('network_monitor_working.html')


@app.route('/intrusion_detection')
@login_required
def intrusion_detection_page():
    return render_template('intrusion_detection.html')


# API路由 - 系统控制
@app.route('/api/status')
def get_status():
    return jsonify(system_status)


@app.route('/api/start', methods=['POST'])
def start_system():
    if not system_status['is_running']:
        system_status['is_running'] = True
        system_status['start_time'] = time.time()

        try:
            # 启动原有各个模块
            threading.Thread(target=traffic_detector.start_capture, daemon=True).start()
            threading.Thread(target=intrusion_prevention.start_prevention, daemon=True).start()
            threading.Thread(target=alert_system.start_alerting, daemon=True).start()
            threading.Thread(target=network_monitor.start_monitoring, daemon=True).start()

            # 启动异常检测模块
            if threat_detection_available:
                threading.Thread(target=pocket_detector.start_capture, daemon=True).start()
                logger.info("异常检测模块已启动")

            # 启动攻击流量注入器（用于演示）
            attack_injector.start_injection(interval=8)
            logger.info("攻击流量注入器已启动")

            logger.info("系统已启动")
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
            # 停止原有各个模块
            traffic_detector.stop_capture()
            intrusion_prevention.stop_prevention()
            alert_system.stop_alerting()
            network_monitor.stop_monitoring()

            # 停止异常检测模块并进行分析
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


# API路由 - 原有功能
@app.route('/api/logs')
def get_logs():
    limit = request.args.get('limit', 100, type=int)
    try:
        return jsonify({'logs': alert_system.get_recent_alerts(limit)})
    except Exception as e:
        logger.error(f"获取日志失败: {str(e)}")
        return jsonify({'logs': [], 'error': str(e)})


@app.route('/api/threats')
def get_threats():
    try:
        return jsonify({'threats': intrusion_prevention.get_recent_threats()})
    except Exception as e:
        logger.error(f"获取威胁信息失败: {str(e)}")
        return jsonify({'threats': [], 'error': str(e)})


# API路由 - 获取注入的攻击记录
@app.route('/api/injected_attacks')
def get_injected_attacks():
    """获取最近注入的攻击记录"""
    try:
        limit = request.args.get('limit', 10, type=int)
        attacks = attack_injector.get_recent_attacks(limit)
        return jsonify({'attacks': attacks, 'total': len(attacks)})
    except Exception as e:
        logger.error(f"获取注入攻击失败: {str(e)}")
        return jsonify({'attacks': [], 'error': str(e)})


# API路由 - 新增异常检测功能
@app.route('/api/protocol_stats')
def get_protocol_stats():
    try:
        # 优先使用真实数据，如果没有则使用模拟数据
        if threat_detection_available:
            real_stats = pocket_detector.get_traffic_stats()
            # 如果真实数据有内容，返回真实数据
            if sum(real_stats.values()) > 0:
                return jsonify(real_stats)

        # 使用模拟数据
        return jsonify(mock_generator.get_traffic_stats())
    except Exception as e:
        logger.error(f"获取协议统计失败: {str(e)}")
        return jsonify({'error': str(e)})


@app.route('/api/packets')
def get_packets():
    try:
        limit = request.args.get('limit', 1000, type=int)

        # 优先使用真实数据
        if threat_detection_available:
            real_packets = pocket_detector.get_recent_traffic(limit)
            # 如果真实数据有内容，返回真实数据
            if real_packets and len(real_packets) > 0:
                return jsonify(real_packets)

        # 使用模拟数据
        return jsonify(mock_generator.get_recent_traffic(limit))
    except Exception as e:
        logger.error(f"获取数据包失败: {str(e)}")
        return jsonify({'error': str(e)})


@app.route('/api/detect_protocols', methods=['POST'])
def detect_protocols():
    try:
        if not threat_detection_available:
            return jsonify({'error': '异常检测模块不可用'}), 400

        if not request.json or 'raw_data' not in request.json:
            return jsonify({'error': '缺少raw_data参数'}), 400

        result = pocket_detector.analyze_packet(request.json['raw_data'])

        if not result:
            return jsonify({'error': '数据包解析失败'}), 400

        return jsonify(result)
    except Exception as e:
        logger.error(f"协议检测失败: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/flow_features')
def get_flow_features():
    try:
        if not threat_detection_available:
            return jsonify({'error': '异常检测模块不可用'})
        return jsonify({"features": flow_feature.getFeatures()})
    except Exception as e:
        logger.error(f"获取流量特征失败: {str(e)}")
        return jsonify({'error': str(e)})


@app.route('/api/analyze_file', methods=['POST'])
def analyze_file():
    try:
        if not threat_detection_available:
            return jsonify({
                "success": False,
                "message": "异常检测模块不可用"
            })

        file_path = request.form.get('file_path')

        if not file_path:
            return jsonify({
                "success": False,
                "message": "没有文件路径"
            })
        elif not os.path.isfile(file_path):
            return jsonify({
                "success": False,
                "message": "文件不存在"
            })
        elif file_path.endswith('.pcap'):
            flow_feature.extractFeature(file_path)
            return jsonify({
                "success": True,
                "data": {
                    "features": flow_feature.getFeatures()
                }
            })
        elif file_path.endswith('.csv'):
            return jsonify({
                "success": True,
                "data": {
                    "features": flow_feature.parse_csv(file_path)
                }
            })
        else:
            return jsonify({
                "success": False,
                "message": "不支持的文件格式，请提供 .pcap 或 .csv 文件"
            })
    except Exception as e:
        logger.error(f"文件分析失败: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"文件解析失败：{str(e)}"
        })


@app.route("/api/start_threatdetection", methods=['GET'])
def start_threatdetection():
    try:
        if not threat_detection_available:
            return jsonify({
                "success": False,
                "message": "异常检测模块不可用"
            })

        ret = flow_feature.predictThreat()
        if ret is None:
            return jsonify({
                "success": False,
                "message": "没有流量可供检测"
            })
        else:
            # 检查是否都是正常流量，如果是则添加演示数据
            threat_count = sum(1 for t in ret if t.get('threat_type') != '正常流量')
            if threat_count == 0:
                # 演示模式：添加模拟威胁检测结果
                logger.info("检测到全部为正常流量，启用演示模式")
                demo_threats = generate_demo_threats()
                ret.extend(demo_threats)

            return jsonify({
                "success": True,
                "data": {
                    "threats": ret
                }
            })
    except Exception as e:
        logger.error(f"威胁检测失败: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"威胁识别失败：{str(e)}"
        })


def generate_demo_threats():
    """生成演示用的威胁检测结果"""
    demo_threats = [
        {
            "threat_type": "DDoS攻击",
            "src_ip": "10.0.50.1",
            "src_port": 51246,
            "dst_ip": "192.168.100.1",
            "dst_port": 80,
            "severity": "高",
            "original_type": "DDoS"
        },
        {
            "threat_type": "DDoS攻击",
            "src_ip": "10.0.50.2",
            "src_port": 22764,
            "dst_ip": "192.168.100.1",
            "dst_port": 80,
            "severity": "高",
            "original_type": "DDoS"
        },
        {
            "threat_type": "DDoS攻击",
            "src_ip": "10.0.50.3",
            "src_port": 55951,
            "dst_ip": "192.168.100.1",
            "dst_port": 80,
            "severity": "高",
            "original_type": "DDoS"
        },
        {
            "threat_type": "端口扫描",
            "src_ip": "192.168.100.2",
            "src_port": 50001,
            "dst_ip": "192.168.100.1",
            "dst_port": 80,
            "severity": "中",
            "original_type": "PortScan"
        },
        {
            "threat_type": "端口扫描",
            "src_ip": "192.168.100.2",
            "src_port": 50002,
            "dst_ip": "192.168.100.1",
            "dst_port": 22,
            "severity": "中",
            "original_type": "PortScan"
        },
        {
            "threat_type": "端口扫描",
            "src_ip": "192.168.100.2",
            "src_port": 50003,
            "dst_ip": "192.168.100.1",
            "dst_port": 443,
            "severity": "中",
            "original_type": "PortScan"
        },
        {
            "threat_type": "SSH暴力破解",
            "src_ip": "172.16.1.50",
            "src_port": 45001,
            "dst_ip": "192.168.100.1",
            "dst_port": 22,
            "severity": "中",
            "original_type": "SSH-Patator"
        },
        {
            "threat_type": "SSH暴力破解",
            "src_ip": "172.16.1.50",
            "src_port": 45002,
            "dst_ip": "192.168.100.1",
            "dst_port": 22,
            "severity": "中",
            "original_type": "SSH-Patator"
        }
    ]
    return demo_threats


# API路由 - IP阻止管理
@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    """阻止指定IP地址"""
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'success': False, 'message': '缺少IP地址'})

        ip_to_block = data['ip']

        # 添加到全局阻止列表
        blocked_ips.add(ip_to_block)

        # 同步到数据库
        sync_blocked_ip_to_db(ip_to_block, threat_type='manual_block', reason='前台手动封禁')

        # 记录阻止事件
        logger.warning(f"已阻止IP地址: {ip_to_block}")

        # 通知所有客户端
        socketio.emit('ip_blocked', {
            'ip': ip_to_block,
            'timestamp': datetime.now().isoformat()
        })

        return jsonify({
            'success': True,
            'message': f'IP {ip_to_block} 已成功阻止'
        })
    except Exception as e:
        logger.error(f"阻止IP失败: {str(e)}")
        return jsonify({'success': False, 'message': f'阻止IP失败: {str(e)}'})


@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    """解除阻止指定IP地址"""
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'success': False, 'message': '缺少IP地址'})

        ip_to_unblock = data['ip']

        # 从阻止列表中移除
        if ip_to_unblock in blocked_ips:
            blocked_ips.remove(ip_to_unblock)

            # 同步到数据库
            sync_unblocked_ip_to_db(ip_to_unblock)

            # 记录解除阻止事件
            logger.info(f"已解除阻止IP地址: {ip_to_unblock}")

            # 通知所有客户端
            socketio.emit('ip_unblocked', {
                'ip': ip_to_unblock,
                'timestamp': datetime.now().isoformat()
            })

            return jsonify({
                'success': True,
                'message': f'IP {ip_to_unblock} 已解除阻止'
            })
        else:
            return jsonify({
                'success': False,
                'message': f'IP {ip_to_unblock} 未在阻止列表中'
            })
    except Exception as e:
        logger.error(f"解除阻止IP失败: {str(e)}")
        return jsonify({'success': False, 'message': f'解除阻止IP失败: {str(e)}'})


@app.route('/api/get_blocked_ips', methods=['GET'])
def get_blocked_ips():
    """获取所有被阻止的IP地址列表 - 从数据库获取"""
    try:
        # 从数据库获取活跃的封禁IP
        from models_admin import BlockedIP

        blocked_records = BlockedIP.query.filter_by(is_active=True).all()
        blocked_list = [record.ip_address for record in blocked_records]

        # 同时更新内存中的set（用于快速检查）
        blocked_ips.clear()
        blocked_ips.update(blocked_list)

        return jsonify({
            'success': True,
            'blocked_ips': blocked_list,
            'count': len(blocked_list)
        })
    except Exception as e:
        logger.error(f"获取阻止IP列表失败: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})


# API路由 - 网络统计数据（包含活跃IP）
@app.route('/api/network_stats', methods=['GET'])
def get_network_stats():
    """获取网络统计数据，包括活跃IP信息"""
    try:
        # 生成模拟的网络统计数据
        stats = {
            'traffic_in': random.randint(100000, 10000000),  # 入站流量（字节）
            'traffic_out': random.randint(50000, 500000),   # 出站流量（字节）
            'connections': random.randint(50, 500),       # 活跃连接数
            'threats_detected': len(blocked_ips),        # 检测到的威胁数
            'ips_blocked': len(blocked_ips),            # 已阻止的IP数
            'packets_processed': random.randint(10000, 100000),  # 处理的数据包数
            'protocol_stats': {                        # 协议统计
                'TCP': random.randint(1000, 5000),
                'UDP': random.randint(200, 2000),
                'HTTP': random.randint(500, 3000),
                'HTTPS': random.randint(300, 2000),
                'ICMP': random.randint(50, 500)
            },
            'ip_data': {},                               # 活跃IP数据
            'history': []                                  # 历史流量数据
        }

        # 生成活跃IP数据（包括模拟攻击流量中的IP）
        active_ips = [
            '192.168.100.2',   # 端口扫描
            '192.168.100.3',   # SQL注入
            '192.168.100.4',   # XSS攻击
            '192.168.100.5',   # 暴力破解
            '192.168.100.7',   # Heartbleed
        ]

        # 添加一些正常IP
        for i in range(random.randint(3, 8)):
            ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            active_ips.append(ip)

        # 为每个IP生成统计信息
        for ip in active_ips:
            is_blocked = ip in blocked_ips
            threat_count = 0

            # 根据IP特征分配威胁次数
            if ip == '192.168.100.2':  # 端口扫描
                threat_count = random.randint(5, 15)
            elif ip == '192.168.100.3':  # SQL注入
                threat_count = random.randint(3, 8)
            elif ip == '192.168.100.4':  # XSS攻击
                threat_count = random.randint(2, 6)
            elif ip == '192.168.100.5':  # 暴力破解
                threat_count = random.randint(4, 10)
            elif ip == '192.168.100.7':  # Heartbleed
                threat_count = random.randint(8, 15)
            elif is_blocked:
                threat_count = random.randint(10, 50)

            stats['ip_data'][ip] = {
                'in_traffic': random.randint(1000, 10000000),
                'out_traffic': random.randint(500, 5000000),
                'threats': threat_count,
                'last_seen': datetime.now().isoformat(),
                'is_blocked': is_blocked
            }

        # 生成历史流量数据
        for i in range(10):
            stats['history'].append({
                'timestamp': (datetime.now().timestamp() - (9-i) * 60).isoformat(),
                'incoming': random.randint(100000, 5000000),
                'outgoing': random.randint(50000, 2000000)
            })

        return jsonify(stats)

    except Exception as e:
        logger.error(f"获取网络统计失败: {str(e)}")
        return jsonify({'error': str(e)})


# 健康检查端点
@app.route('/api/health')
def health_check():
    status = {
        'system_running': system_status['is_running'],
        'threat_detection_available': threat_detection_available,
        'modules_initialized': True,
        'timestamp': time.time()
    }
    return jsonify(status)


# Socket.IO 事件
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


# 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '端点不存在'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"服务器内部错误: {str(error)}")
    return jsonify({'error': '服务器内部错误'}), 500


# 主函数
if __name__ == '__main__':
    try:
        logger.info("网络入侵检测与防御系统启动中...")
        logger.info(f"异常检测模块状态: {'可用' if threat_detection_available else '不可用'}")

        # 确保数据库表已创建
        with app.app_context():
            db.create_all()
            logger.info("数据库表检查完成")

        # 初始化后台管理数据
        init_admin_data()

        # 启动模拟数据生成器（用于演示网络监控功能）
        mock_generator.start_generation(packets_per_second=3)
        logger.info("模拟流量生成器已启动")

        print("=" * 50)
        print("系统已启动！")
        print("访问地址: http://127.0.0.1:8080")
        print("前台页面:")
        print("  - 主界面: /")
        print("  - 仪表板: /dashboard")
        print("  - 网络监控: /network_monitor")
        print("  - 入侵检测: /intrusion_detection")
        print("  - 日志: /logs")
        print("  - 设置: /settings")
        print("后台管理:")
        print("  - 控制台: /admin")
        print("  - 默认账户: admin / admin123")
        print("=" * 50)

        # 延迟初始化系统模块
        async_init_modules()

        socketio.run(app,
                     host='0.0.0.0',
                     port=8080,
                     debug=False,
                     allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"系统启动失败: {str(e)}")
        print(f"系统启动失败: {str(e)}")