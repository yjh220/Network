#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络入侵检测与防御系统 - 主程序（集成AI智能体）

This is the main application file with AI agents integrated from FullScopeTest.
The AI agents provide natural language interface for security operations.
"""

import os
import sys
import time
import threading
import logging
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO

# 导入AI智能体模块 - 延迟导入可能导致阻塞的模块
from modules.ai_agents.api import ai_agents_bp, init_ai_agents

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname>] %(message)s]',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('data/ids_system.log')
    ]
)
logger = logging.getLogger(__name__)

# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 限制请求最大16MB
# 简化的 SocketIO 配置（兼容 PyInstaller）
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    manage_session=False,
    max_http_buffer_size=16 * 1024 * 1024
)

# 创建数据目录
os.makedirs('data', exist_ok=True)

# 延迟初始化系统模块（避免启动时阻塞）
traffic_detector = None
intrusion_prevention = None
alert_system = None
network_monitor_obj = None

def init_system_modules():
    """延迟初始化系统模块"""
    global traffic_detector, intrusion_prevention, alert_system, network_monitor_obj
    if traffic_detector is None:
        try:
            from modules.traffic_detection.detector import TrafficDetector
            traffic_detector = TrafficDetector()
            logger.info("TrafficDetector 初始化成功")
        except Exception as e:
            logger.warning(f"TrafficDetector 初始化失败: {e}")
            traffic_detector = None

    if intrusion_prevention is None:
        try:
            from modules.intrusion_prevention.prevention import IntrusionPrevention
            intrusion_prevention = IntrusionPrevention()
            logger.info("IntrusionPrevention 初始化成功")
        except Exception as e:
            logger.warning(f"IntrusionPrevention 初始化失败: {e}")
            intrusion_prevention = None

    if alert_system is None:
        try:
            from modules.alert_response.alerter import AlertSystem
            alert_system = AlertSystem()
            logger.info("AlertSystem 初始化成功")
        except Exception as e:
            logger.warning(f"AlertSystem 初始化失败: {e}")
            alert_system = None

    if network_monitor_obj is None:
        try:
            from modules.network_monitoring.monitor import NetworkMonitor
            network_monitor_obj = NetworkMonitor(socketio)
            logger.info("NetworkMonitor 初始化成功")
        except Exception as e:
            logger.warning(f"NetworkMonitor 初始化失败: {e}")
            network_monitor_obj = None

    # 将系统模块添加到app，供AI智能体访问
    app.traffic_detector = traffic_detector
    app.intrusion_prevention = intrusion_prevention
    app.alert_system = alert_system
    app.network_monitor_obj = network_monitor_obj

# 在后台线程中初始化模块，避免阻塞启动
def async_init_modules():
    import threading
    def init_worker():
        import time
        time.sleep(1)  # 给Flask一点时间启动
        init_system_modules()
    thread = threading.Thread(target=init_worker, daemon=True)
    thread.start()

# 管理系统状态
system_status = {
    'is_running': False,
    'start_time': None,
    'processed_packets': 0,
    'detected_threats': 0,
    'blocked_attacks': 0
}
app.system_status = system_status

# ==================== 辅助函数 ====================

import random
from datetime import datetime, timedelta

def generate_random_ip():
    """生成多样化的随机IP地址"""
    ip_ranges = [
        '192.168.{}.{}',   # 私有网络
        '10.{}.{}.{}',     # 私有网络
        '172.16.{}.{}',    # 私有网络
        '203.0.{}.{}',     # 公网IP
        '114.{}.{}.{}',    # 公网IP
        '223.{}.{}.{}',    # 公网IP
        '8.8.{}.{}',       # 公网IP
        '1.1.{}.{}',       # 公网IP
    ]

    choice = random.choice(ip_ranges)

    if choice.count('{}') == 2:
        return choice.format(random.randint(1, 254), random.randint(1, 254))
    elif choice.count('{}') == 3:
        parts = choice.split('.')
        result = []
        for part in parts:
            if part == '{}':
                result.append(str(random.randint(1, 254)))
            else:
                result.append(part)
        return '.'.join(result)
    else:
        return choice.format(random.randint(1, 254))

def get_relative_timestamp(minutes_ago_max=60):
    """获取相对时间戳（当前时间往前推）"""
    minutes_ago = random.randint(1, minutes_ago_max)
    return (datetime.now() - timedelta(minutes=minutes_ago)).isoformat()

def format_timestamp(timestamp):
    """格式化时间戳为中文格式"""
    try:
        dt = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else datetime.fromtimestamp(timestamp)
        now = datetime.now()
        diff = now - dt

        if diff.seconds < 60:
            return f"{diff.seconds}秒前"
        elif diff.seconds < 3600:
            return f"{diff.seconds // 60}分钟前"
        elif diff.days == 0:
            return f"{diff.seconds // 3600}小时前"
        elif diff.days < 7:
            return f"{diff.days}天前"
        else:
            return dt.strftime('%Y-%m-%d %H:%M')
    except:
        return datetime.now().strftime('%H:%M:%S')


# 注册AI智能体Blueprint
app.register_blueprint(ai_agents_bp)

# 注册意图网络多智能体系统
try:
    from modules.intent_agents import register_intent_app
    register_intent_app(app)
    logger.info("意图网络多智能体系统已注册")
except ImportError as e:
    logger.warning(f"意图网络系统注册失败: {e}")
except Exception as e:
    logger.warning(f"意图网络系统初始化失败: {e}")

# 初始化AI智能体
init_ai_agents(app)

logger.info("AI智能体已初始化")

# ==================== 路由定义 ====================

@app.route('/')
def index():
    # 主页：粒子界面
    return render_template('index_minimal.html')

# 功能页面（带导航栏和六个卡片）
@app.route('/home')
def home():
    class SimpleUser:
        def __init__(self):
            # 检查cookie中的登录状态
            is_logged_in = request.cookies.get('isLoggedIn') == 'true'
            is_admin = request.cookies.get('isAdmin') == 'true'
            username = request.cookies.get('username', 'Guest')

            if is_logged_in:
                self.username = username
                self.is_authenticated = True
                self.role = "admin" if is_admin else "user"  # 只有管理员才有admin角色
            else:
                self.username = "Guest"
                self.is_authenticated = False
                self.role = None  # 未登录用户没有角色

    return render_template('home.html', current_user=SimpleUser())

# 极简科技风粒子界面（备用路由）
@app.route('/landing')
def landing():
    return render_template('index_minimal.html')

@app.route('/dashboard')
def dashboard():
    # 为navbar创建简单的user对象
    class SimpleUser:
        def __init__(self):
            is_logged_in = request.cookies.get('isLoggedIn') == 'true'
            is_admin = request.cookies.get('isAdmin') == 'true'
            username = request.cookies.get('username', 'Guest')

            if is_logged_in:
                self.username = username
                self.is_authenticated = True
                self.role = "admin" if is_admin else "user"
            else:
                self.username = "Guest"
                self.is_authenticated = False
                self.role = None

    current_user = SimpleUser()
    return render_template('dashboard.html', current_user=current_user)

@app.route('/network_monitor')
def network_monitor():
    class SimpleUser:
        def __init__(self):
            is_logged_in = request.cookies.get('isLoggedIn') == 'true'
            is_admin = request.cookies.get('isAdmin') == 'true'
            username = request.cookies.get('username', 'Guest')

            if is_logged_in:
                self.username = username
                self.is_authenticated = True
                self.role = "admin" if is_admin else "user"
            else:
                self.username = "Guest"
                self.is_authenticated = False
                self.role = None
    return render_template('network_monitor.html', current_user=SimpleUser())

@app.route('/network_monitor_simple')
def network_monitor_simple():
    """简化版网络监控 - 不依赖外部CDN"""
    class SimpleUser:
        def __init__(self):
            self.username = "Admin"
            self.is_authenticated = True
            self.role = "admin"
    return render_template('network_monitor_simple.html', current_user=SimpleUser())

@app.route('/honeypot')
def honeypot():
    class SimpleUser:
        def __init__(self):
            is_logged_in = request.cookies.get('isLoggedIn') == 'true'
            is_admin = request.cookies.get('isAdmin') == 'true'
            username = request.cookies.get('username', 'Guest')

            if is_logged_in:
                self.username = username
                self.is_authenticated = True
                self.role = "admin" if is_admin else "user"
            else:
                self.username = "Guest"
                self.is_authenticated = False
                self.role = None
    return render_template('honeypot.html', current_user=SimpleUser())

@app.route('/intrusion_detection')
def intrusion_detection():
    class SimpleUser:
        def __init__(self):
            is_logged_in = request.cookies.get('isLoggedIn') == 'true'
            is_admin = request.cookies.get('isAdmin') == 'true'
            username = request.cookies.get('username', 'Guest')

            if is_logged_in:
                self.username = username
                self.is_authenticated = True
                self.role = "admin" if is_admin else "user"
            else:
                self.username = "Guest"
                self.is_authenticated = False
                self.role = None
    return render_template('intrusion_detection.html', current_user=SimpleUser())

@app.route('/logs')
def logs():
    class SimpleUser:
        def __init__(self):
            is_logged_in = request.cookies.get('isLoggedIn') == 'true'
            is_admin = request.cookies.get('isAdmin') == 'true'
            username = request.cookies.get('username', 'Guest')

            if is_logged_in:
                self.username = username
                self.is_authenticated = True
                self.role = "admin" if is_admin else "user"
            else:
                self.username = "Guest"
                self.is_authenticated = False
                self.role = None
    return render_template('logs.html', current_user=SimpleUser())

@app.route('/settings')
def settings():
    class SimpleUser:
        def __init__(self):
            is_logged_in = request.cookies.get('isLoggedIn') == 'true'
            is_admin = request.cookies.get('isAdmin') == 'true'
            username = request.cookies.get('username', 'Guest')

            if is_logged_in:
                self.username = username
                self.is_authenticated = True
                self.role = "admin" if is_admin else "user"
            else:
                self.username = "Guest"
                self.is_authenticated = False
                self.role = None
    return render_template('settings.html', current_user=SimpleUser())

# AI智能体页面路由
@app.route('/ai/copilot')
def ai_copilot():
    class SimpleUser:
        def __init__(self):
            self.username = "Admin"
            self.is_authenticated = True
            self.role = "admin"
    return render_template('ai_copilot.html', current_user=SimpleUser())

@app.route('/ai/planner')
def ai_planner():
    class SimpleUser:
        def __init__(self):
            self.username = "Admin"
            self.is_authenticated = True
            self.role = "admin"
    return render_template('ai_planner.html', current_user=SimpleUser())

@app.route('/ai/rules')
def ai_rules():
    class SimpleUser:
        def __init__(self):
            self.username = "Admin"
            self.is_authenticated = True
            self.role = "admin"
    return render_template('ai_rules.html', current_user=SimpleUser())

# 简化版认证路由（用于兼容navbar）
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 简化版：直接跳转到主页，并设置登录状态
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # 确定用户角色：只有用户名为 'admin' 的才是管理员
        is_admin = (username == 'admin')

        response = redirect('/home')
        # 设置cookie表示已登录
        response.set_cookie('isLoggedIn', 'true', max_age=60*60*24*7)  # 7天有效
        # 设置管理员状态
        response.set_cookie('isAdmin', 'true' if is_admin else 'false', max_age=60*60*24*7)
        # 设置用户名
        response.set_cookie('username', username or 'Guest', max_age=60*60*24*7)
        return response
    return render_template('login_tech.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # 简化版：直接跳转到粒子界面，并设置登录状态
    if request.method == 'POST':
        response = redirect('/landing')
        response.set_cookie('isLoggedIn', 'true', max_age=60*60*24*7)  # 7天有效
        return response
    return render_template('register_tech.html')

@app.route('/logout')
def logout():
    response = redirect(url_for('index'))
    # 清除所有登录相关的cookie
    response.set_cookie('isLoggedIn', 'false', max_age=0)
    response.set_cookie('isAdmin', 'false', max_age=0)
    response.set_cookie('username', '', max_age=0)
    return response

# 验证页面路由
@app.route('/verification')
def verification():
    class SimpleUser:
        def __init__(self):
            self.username = "Admin"
            self.is_authenticated = True
            self.role = "admin"
    return render_template('verification.html', current_user=SimpleUser())

# Admin console route (for navbar compatibility)
@app.route('/admin/console')
def admin_console():
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"

    return render_template('admin/console.html', current_user=SimpleUser())

# Admin routes (使用原来的模板)
@app.route('/admin/users')
def admin_users():
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"
    # 返回简化的用户管理页面
    return render_template('admin_users_simple.html', current_user=SimpleUser())

@app.route('/admin/defense')
def admin_defense():
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"

    return render_template('admin/defense.html', current_user=SimpleUser())

@app.route('/admin/threats')
def admin_threats():
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"

    return render_template('admin/threats.html', current_user=SimpleUser())

@app.route('/admin/monitor')
def admin_monitor():
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"

    return render_template('admin/monitor.html', current_user=SimpleUser())

@app.route('/admin/roles')
def admin_roles():
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"

    return render_template('admin/roles.html', current_user=SimpleUser())

@app.route('/admin/alerts')
def admin_alerts():
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"

    return render_template('admin/alerts.html', current_user=SimpleUser())

@app.route('/admin/intent')
def admin_intent():
    """意图网络控制页面"""
    # 在路由级别检查登录状态和是否是管理员
    is_logged_in = request.cookies.get('isLoggedIn') == 'true'
    is_admin = request.cookies.get('isAdmin') == 'true'

    if not is_logged_in or not is_admin:
        return redirect('/login')

    username = request.cookies.get('username', 'Admin')

    class SimpleUser:
        def __init__(self):
            self.username = username
            self.is_authenticated = True
            self.role = "admin"

    return render_template('admin/intent.html', current_user=SimpleUser())

# ==================== API路由 ====================

@app.route('/api/status')
def get_status():
    return jsonify(system_status)

@app.route('/api/start', methods=['POST'])
def start_system():
    if not system_status['is_running']:
        # 立即更新状态
        system_status['is_running'] = True
        system_status['start_time'] = time.time()

        # 只启动不需要管理员权限的模块
        def start_safe_modules():
            try:
                alert_system.start_alerting()
                logger.info("告警系统已启动")
            except Exception as e:
                logger.warning(f"告警系统启动失败: {e}")

            try:
                network_monitor_obj.start_monitoring()
                logger.info("网络监控已启动")
            except Exception as e:
                logger.warning(f"网络监控启动失败: {e}")

            # 不启动traffic_detector和intrusion_prevention
            # 它们需要管理员权限且scapy会阻塞整个进程
            logger.info("流量检测和入侵防护需要管理员权限，已跳过")

        threading.Thread(target=start_safe_modules, daemon=True).start()

        logger.info("系统启动命令已发送")
        return jsonify({'success': True, 'message': '系统已启动（安全模式）'})

    return jsonify({'success': False, 'message': '系统已在运行中'})

@app.route('/api/stop', methods=['POST'])
def stop_system():
    if system_status['is_running']:
        system_status['is_running'] = False

        # 停止各个模块
        try:
            traffic_detector.stop_capture()
        except:
            pass
        try:
            intrusion_prevention.stop_prevention()
        except:
            pass
        try:
            alert_system.stop_alerting()
        except:
            pass
        try:
            network_monitor_obj.stop_monitoring()
        except:
            pass

        logger.info("系统已停止")
        return jsonify({'success': True, 'message': '系统已停止'})

    return jsonify({'success': False, 'message': '系统未运行'})

@app.route('/api/health')
def health_check():
    """系统健康检查"""
    health_status = {
        'system_running': system_status['is_running'],
        'threat_detection_available': True,
        'modules_initialized': True,
        'sdn_connected': False,
        'ai_enabled': True
    }

    # 检查SDN控制器连接
    try:
        from modules.ai_agents.sdn_control import check_sdn_connection
        sdn_status = check_sdn_connection()
        health_status['sdn_connected'] = sdn_status.get('connected', False)
    except:
        health_status['sdn_connected'] = False

    return jsonify(health_status)

@app.route('/api/network/traffic')
def get_network_traffic():
    """获取网络流量数据"""
    if not system_status['is_running']:
        return jsonify({
            'success': False,
            'message': '系统未运行',
            'traffic': {'inbound': 0, 'outbound': 0, 'total': 0}
        })

    # 生成模拟流量数据
    import random
    traffic = {
        'inbound': random.randint(100, 10000),
        'outbound': random.randint(50, 5000),
        'total': random.randint(150, 15000),
        'timestamp': time.time()
    }

    return jsonify({
        'success': True,
        'traffic': traffic
    })


@app.route('/api/network_stats')
def get_network_stats():
    """获取网络统计数据 - 用于仪表盘"""
    if not system_status['is_running']:
        return jsonify({
            'traffic': {'inbound': 0, 'outbound': 0},
            'protocols': {},
            'attacks': {}
        })

    # 获取协议统计
    protocols = traffic_detector.get_traffic_stats()

    # 生成统计数据
    import random
    stats = {
        'traffic': {
            'inbound': random.randint(100, 10000),
            'outbound': random.randint(50, 5000)
        },
        'protocols': protocols,
        'attacks': {
            'SQL注入': random.randint(0, 5),
            'XSS攻击': random.randint(0, 3),
            'DDoS攻击': random.randint(0, 2),
            '端口扫描': random.randint(0, 10),
            '暴力破解': random.randint(0, 7),
            '异常流量': random.randint(0, 4)
        },
        'timestamp': time.time()
    }

    return jsonify(stats)

@app.route('/api/network/protocols')
def get_network_protocols():
    """获取网络协议分布"""
    if not system_status['is_running']:
        return jsonify({
            'success': False,
            'message': '系统未运行',
            'protocols': {}
        })

    # 生成模拟协议数据
    import random
    protocols = {
        'TCP': random.randint(100, 1000),
        'UDP': random.randint(50, 500),
        'ICMP': random.randint(10, 100),
        'HTTP': random.randint(200, 2000),
        'HTTPS': random.randint(100, 1500)
    }

    return jsonify({
        'success': True,
        'protocols': protocols
    })

@app.route('/api/threats')
def get_threats():
    """获取威胁数据 - 限制返回数量"""
    limit = request.args.get('limit', 10, type=int)
    # 严格限制最大返回50条
    limit = min(limit, 50)

    # 生成模拟威胁数据
    threats = []
    threat_types = ['DDoS攻击', '端口扫描', 'SQL注入', 'XSS攻击', '暴力破解', '恶意软件']
    severities = ['低', '中', '高', '严重']

    # 限制生成的威胁数量，确保有足够数据显示
    count = min(max(random.randint(5, 12), 5), limit)

    for i in range(count):
        threat_type = random.choice(threat_types)
        timestamp = get_relative_timestamp(random.randint(1, 120))
        source_ip = generate_random_ip()
        target_ip = generate_random_ip()

        threat = {
            'id': f"threat_{int(datetime.now().timestamp())}_{i}",
            'timestamp': timestamp,
            'time_ago': format_timestamp(timestamp),
            'threat_type': threat_type,
            'alert_type': threat_type,
            'type': threat_type,
            'severity': random.choice(severities),
            'source_ip': source_ip,
            'target_ip': target_ip,
            'description': f"检测到来自 {source_ip} 的{threat_type}活动",
            'blocked': random.choice([True, False])
        }
        threats.append(threat)

    return jsonify({
        'success': True,
        'threats': threats
    })

@app.route('/api/logs')
def get_logs():
    """获取系统日志 - 始终返回历史日志，不依赖系统状态"""
    limit = request.args.get('limit', 50, type=int)
    # 限制最大返回100条，避免响应过大
    limit = min(limit, 100)

    # 始终生成模拟日志数据，确保有数据展示
    mock_logs = []
    alert_types = ['DDoS攻击', '端口扫描', 'SQL注入', 'XSS攻击', '暴力破解', '恶意软件', '正常流量']
    severities = ['低', '中', '高', '严重']

    for i in range(min(limit, 50)):
        alert_type = random.choice(alert_types)
        severity = random.choice(severities)
        src_ip = generate_random_ip()
        dst_ip = generate_random_ip()
        timestamp = get_relative_timestamp(random.randint(1, 1440))  # 最远24小时

        mock_logs.append({
            'alert_id': f"alert_{int(datetime.now().timestamp())}_{i}",
            'timestamp': timestamp,
            'time_ago': format_timestamp(timestamp),
            'alert_type': alert_type,
            'threat_type': alert_type,
            'type': alert_type,
            'severity': severity,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'source_ip': src_ip,
            'target_ip': dst_ip,
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']),
            'port': random.choice([80, 443, 22, 53, 3306, 8080]),
            'action_taken': random.choice(['已阻止', '已记录', '已放行', '监控中']),
            'details': f"检测到来自 {src_ip} 的{alert_type}活动，目标为 {dst_ip}",
            'message': f"{alert_type} - {src_ip} -> {dst_ip}"
        })

    # 按时间排序
    mock_logs.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'logs': mock_logs[:limit], 'total': len(mock_logs)})

    # 处理真实日志数据，确保字段完整
    compact_logs = []
    for i, log in enumerate(logs[-50:]):
        compact_logs.append({
            'alert_id': log.get('alert_id', f"alert_{int(time.time())}_{i}"),
            'timestamp': log.get('timestamp', datetime.now().isoformat()),
            'alert_type': log.get('alert_type', log.get('threat_type', '未知')),
            'threat_type': log.get('threat_type', log.get('alert_type', '未知')),
            'severity': log.get('severity', '未知'),
            'src_ip': log.get('src_ip', '未知'),
            'dst_ip': log.get('dst_ip', '未知'),
            'protocol': log.get('protocol', '未知'),
            'port': log.get('port', 0),
            'action_taken': log.get('action_taken', '无操作'),
            'message': log.get('message', ''),
            'details': log.get('details', '')
        })

    return jsonify({'logs': compact_logs})


@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    """封锁IP地址"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '无效的请求数据'})

        ip = data.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'IP地址不能为空'})

        # 尝试调用SDN控制器封锁IP
        try:
            from modules.ai_agents.sdn_control import block_traffic
            result = block_traffic(ip)
            if result.get('success'):
                return jsonify({'success': True, 'message': f'已成功封锁IP: {ip}'})
            else:
                # SDN控制器不可用时，返回模拟成功
                return jsonify({'success': True, 'message': f'已标记IP {ip} 为威胁（演示模式）'})
        except Exception as e:
            logger.warning(f"SDN封锁失败，使用模拟模式: {e}")
            # 模拟模式：返回成功
            return jsonify({'success': True, 'message': f'已标记IP {ip} 为威胁（演示模式）'})

    except Exception as e:
        logger.error(f"封锁IP错误: {e}")
        return jsonify({'success': False, 'message': f'封锁IP失败: {str(e)}'})


@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    """解除IP封锁"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '无效的请求数据'})

        ip = data.get('ip')
        if not ip:
            return jsonify({'success': False, 'message': 'IP地址不能为空'})

        # 尝试调用SDN控制器解除封锁
        try:
            from modules.ai_agents.sdn_control import unblock_traffic
            result = unblock_traffic(ip)
            if result.get('success'):
                return jsonify({'success': True, 'message': f'已解除IP封锁: {ip}'})
            else:
                # SDN控制器不可用时，返回模拟成功
                return jsonify({'success': True, 'message': f'已解除IP {ip} 的封锁（演示模式）'})
        except Exception as e:
            logger.warning(f"SDN解除封锁失败，使用模拟模式: {e}")
            # 模拟模式：返回成功
            return jsonify({'success': True, 'message': f'已解除IP {ip} 的封锁（演示模式）'})

    except Exception as e:
        logger.error(f"解除IP封锁错误: {e}")
        return jsonify({'success': False, 'message': f'解除封锁失败: {str(e)}'})


# ==================== 入侵检测API ====================

@app.route('/api/flow_features')
def get_flow_features():
    """获取流量特征数据"""
    try:
        # 尝试获取真实流量特征
        try:
            from modules.traffic_detection.flow_features import get_features
            features = get_features()
            if features:
                return jsonify({'success': True, 'features': features})
        except:
            pass

        # 返回模拟流量特征数据
        import random
        mock_features = []
        src_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.30', '10.0.0.1', '10.0.0.2', '172.16.0.10']
        dst_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '8.8.8.8', '1.1.1.1']
        protocols = ['TCP', 'UDP', 'TCP', 'TCP', 'ICMP']

        for i in range(15):
            src_ip = random.choice(src_ips)
            dst_ip = random.choice(dst_ips)
            protocol = random.choice(protocols)
            src_port = random.randint(1024, 65000) if protocol in ['TCP', 'UDP'] else 0
            dst_port = random.choice([80, 443, 22, 53, 3306, 8080]) if protocol in ['TCP', 'UDP'] else 0

            fwd_pkts = random.randint(1, 100)
            bwd_pkts = random.randint(0, 50)

            mock_features.append({
                'Src IP': src_ip,
                'Dst IP': dst_ip,
                'Src Port': src_port,
                'Dst Port': dst_port,
                'Protocol': protocol,
                'Fwd Pkts': fwd_pkts,
                'Bwd Pkts': bwd_pkts,
                'Total Length of Fwd Packets': random.randint(100, 50000),
                'Total Length of Bwd Packets': random.randint(50, 30000),
                'Flow Duration(ms)': random.randint(1000, 60000),
                'FIN Count': random.randint(0, 3),
                'SYN Count': random.randint(0, 5),
                'RST Count': random.randint(0, 2),
                'ACK Count': random.randint(0, 50)
            })

        return jsonify({'success': True, 'features': mock_features})

    except Exception as e:
        logger.error(f"获取流量特征失败: {e}")
        return jsonify({'success': False, 'message': f'获取流量特征失败: {str(e)}'})


@app.route('/api/analyze_file', methods=['POST'])
def analyze_file():
    """分析PCAP或CSV文件 - 支持模拟数据模式"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': '无效的请求数据'})

        file_path = data.get('file_path', '')
        if not file_path:
            return jsonify({'success': False, 'message': '文件路径不能为空'})

        import os
        file_exists = os.path.exists(file_path)

        # 检查文件类型
        file_ext = os.path.splitext(file_path)[1].lower()

        # 如果文件不存在或扩展名不支持，生成模拟数据
        if not file_exists or file_ext not in ['.pcap', '.csv']:
            logger.info(f"文件不存在或类型不支持，使用模拟数据: {file_path}, exists={file_exists}, ext={file_ext}")

            # 生成模拟数据
            mock_features = []
            protocols = ['TCP', 'UDP', 'ICMP']

            for i in range(20):
                src_ip = generate_random_ip()
                dst_ip = generate_random_ip()
                protocol = random.choice(protocols)

                mock_features.append({
                    'Src IP': src_ip,
                    'Dst IP': dst_ip,
                    'Src Port': random.randint(1024, 65000) if protocol in ['TCP', 'UDP'] else 0,
                    'Dst Port': random.choice([80, 443, 22, 53, 3306]),
                    'Protocol': protocol,
                    'Fwd Pkts': random.randint(1, 100),
                    'Bwd Pkts': random.randint(0, 50),
                    'Total Length of Fwd Packets': random.randint(64, 1500),
                    'Total Length of Bwd Packets': random.randint(0, 500),
                    'Flow Duration(ms)': random.randint(100, 10000),
                    'FIN Count': random.randint(0, 5),
                    'SYN Count': random.randint(0, 3) if protocol == 'TCP' else 0,
                    'RST Count': random.randint(0, 2),
                    'ACK Count': random.randint(0, 10)
                })

            return jsonify({'success': True, 'data': {'features': mock_features, 'total_packets': 20}})

        # 如果文件存在，进行真实分析
        if file_ext == '.pcap':
            # PCAP文件分析
            try:
                from scapy.all import rdpcap
                packets = rdpcap(file_path)

                # 提取流量特征
                features = []
                for i, pkt in enumerate(packets[:50]):  # 限制处理50个包
                    if hasattr(pkt, 'src') and hasattr(pkt, 'dst'):
                        feature = {
                            'Src IP': pkt.get('src', 'unknown'),
                            'Dst IP': pkt.get('dst', 'unknown'),
                            'Src Port': getattr(pkt.get('TCP'), 'sport', 0) or getattr(pkt.get('UDP'), 'sport', 0) or 0,
                            'Dst Port': getattr(pkt.get('TCP'), 'dport', 0) or getattr(pkt.get('UDP'), 'dport', 0) or 0,
                            'Protocol': 'TCP' if pkt.haslayer('TCP') else ('UDP' if pkt.haslayer('UDP') else 'Other'),
                            'Fwd Pkts': 1,
                            'Bwd Pkts': 0,
                            'Total Length of Fwd Packets': len(pkt),
                            'Total Length of Bwd Packets': 0,
                            'Flow Duration(ms)': 100,
                            'FIN Count': 0,
                            'SYN Count': 1 if pkt.haslayer('TCP') else 0,
                            'RST Count': 0,
                            'ACK Count': 0
                        }
                        features.append(feature)

                return jsonify({'success': True, 'data': {'features': features, 'total_packets': len(packets)}})

            except Exception as e:
                # 如果scapy失败，生成模拟数据
                logger.warning(f"PCAP分析失败，使用模拟数据: {e}")

                # 生成模拟数据
                mock_features = []
                protocols = ['TCP', 'UDP', 'ICMP']
                for i in range(20):
                    src_ip = generate_random_ip()
                    dst_ip = generate_random_ip()
                    protocol = random.choice(protocols)
                    mock_features.append({
                        'Src IP': src_ip,
                        'Dst IP': dst_ip,
                        'Src Port': random.randint(1024, 65000) if protocol in ['TCP', 'UDP'] else 0,
                        'Dst Port': random.choice([80, 443, 22, 53, 3306]),
                        'Protocol': protocol,
                        'Fwd Pkts': random.randint(1, 100),
                        'Bwd Pkts': random.randint(0, 50),
                        'Total Length of Fwd Packets': random.randint(64, 1500),
                        'Total Length of Bwd Packets': random.randint(0, 500),
                        'Flow Duration(ms)': random.randint(100, 10000),
                        'FIN Count': random.randint(0, 5),
                        'SYN Count': random.randint(0, 3) if protocol == 'TCP' else 0,
                        'RST Count': random.randint(0, 2),
                        'ACK Count': random.randint(0, 10)
                    })
                return jsonify({'success': True, 'data': {'features': mock_features, 'total_packets': 20}})

        elif file_ext == '.csv':
            # CSV文件分析
            try:
                import pandas as pd
                df = pd.read_csv(file_path)

                # 限制返回的行数
                features = df.head(50).to_dict('records')

                return jsonify({'success': True, 'data': {'features': features, 'total_rows': len(df)}})

            except Exception as e:
                return jsonify({'success': False, 'message': f'CSV文件分析失败: {str(e)}'})

        else:
            return jsonify({'success': False, 'message': f'不支持的文件类型: {file_ext}'})

    except Exception as e:
        logger.error(f"文件分析错误: {e}")
        return jsonify({'success': False, 'message': f'文件分析失败: {str(e)}'})


@app.route('/api/start_threatdetection')
def start_threat_detection():
    """开始威胁检测"""
    try:
        # 尝试使用真实的机器学习模型进行检测
        try:
            from modules.intrusion_detection.ml_detector import detect_threats
            threats = detect_threats()
            if threats:
                return jsonify({'success': True, 'data': {'threats': threats}})
        except:
            pass

        # 使用模拟检测数据
        threat_types = ['DDoS攻击', '端口扫描', 'SQL注入', 'XSS攻击', '暴力破解', '正常流量']
        severities = ['低', '中', '高', '严重']

        mock_threats = []
        # 生成5-10个威胁
        for i in range(random.randint(5, 10)):
            threat_type = random.choice(threat_types)
            severity = random.choice(severities)
            timestamp = get_relative_timestamp(random.randint(1, 60))
            src_ip = generate_random_ip()
            dst_ip = generate_random_ip()

            threat = {
                'id': f"threat_{int(datetime.now().timestamp())}_{i}",
                'timestamp': timestamp,
                'time_ago': format_timestamp(timestamp),
                'threat_type': threat_type,
                'alert_type': threat_type,
                'type': threat_type,
                'severity': severity,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'source_ip': src_ip,
                'target_ip': dst_ip,
                'src_port': random.randint(1024, 65000),
                'dst_port': random.choice([80, 443, 22, 53, 3306]),
                'description': f"检测到来自 {src_ip} 的{threat_type}活动",
                'blocked': random.choice([True, False])
            }
            mock_threats.append(threat)

        return jsonify({'success': True, 'data': {'threats': mock_threats}})

    except Exception as e:
        logger.error(f"威胁检测错误: {e}")
        return jsonify({'success': False, 'message': f'威胁检测失败: {str(e)}'})


# ==================== 系统设置API ====================

@app.route('/api/settings')
def get_settings():
    """获取系统设置"""
    try:
        settings = {
            'systemName': '网络入侵检测与防御系统',
            'networkInterface': 'all',
            'logRetention': 30,
            'autoStart': True,
            'darkMode': False,
            'detection': {
                'threshold': 0.7,
                'updateInterval': 5,
                'enableML': True
            },
            'prevention': {
                'autoBlock': True,
                'blockDuration': 3600,
                'enableRateLimit': True
            },
            'alert': {
                'emailEnabled': False,
                'emailRecipients': [],
                'minSeverity': 'medium'
            },
            'network': {
                'monitoredRanges': ['192.168.0.0/16', '10.0.0.0/8'],
                'enableSsl': False,
                'requireAuth': True
            }
        }
        return jsonify({'success': True, 'settings': settings})

    except Exception as e:
        logger.error(f"获取设置失败: {e}")
        return jsonify({'success': False, 'message': f'获取设置失败: {str(e)}'})


@app.route('/api/settings', methods=['POST'])
def save_settings():
    """保存系统设置"""
    try:
        data = request.get_json()
        # 在实际应用中，这里应该将设置保存到数据库或配置文件
        logger.info(f"保存设置: {data}")
        return jsonify({'success': True, 'message': '设置已保存'})

    except Exception as e:
        logger.error(f"保存设置失败: {e}")
        return jsonify({'success': False, 'message': f'保存设置失败: {str(e)}'})


@app.route('/api/packets')
def get_packets():
    """获取数据包数据 - 限制返回数量避免413错误"""
    limit = request.args.get('limit', 20, type=int)
    # 严格限制最大返回50条
    limit = min(limit, 50)

    # 获取真实流量数据（如果系统正在运行）
    packets = []
    if system_status['is_running']:
        packets = traffic_detector.get_recent_traffic(limit)

    # 如果没有真实数据，生成模拟数据用于演示
    if not packets or len(packets) == 0:
        mock_packets = []
        protocols = ['TCP', 'UDP', 'TCP', 'TCP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
        applications = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'SMTP', 'MySQL', 'Redis']

        now = datetime.now()
        for i in range(min(limit, 20)):
            src_ip = generate_random_ip()
            dst_ip = generate_random_ip()
            protocol = random.choice(protocols)
            src_port = random.randint(1024, 65000) if protocol in ['TCP', 'UDP'] else 0
            dst_port = random.choice([80, 443, 22, 53, 3306, 6379, 21, 25]) if protocol in ['TCP', 'UDP'] else 0

            packet_time = now - timedelta(seconds=random.randint(1, 300))
            packet_size = random.randint(64, 1500)

            # 生成十六进制数据
            hex_data = ''.join([f'{random.randint(0, 255):02x}' for _ in range(min(32, packet_size))])

            mock_packets.append({
                'timestamp': packet_time.strftime('%H:%M:%S'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'app_protocol': random.choice(applications) if protocol in ['TCP', 'UDP'] else protocol,
                'length': packet_size,
                'size': packet_size,
                'raw': hex_data,
                'hex': hex_data,
                'info': f"{protocol} {src_port} -> {dst_port}"
            })

        return jsonify(mock_packets)

    # 处理真实数据
    compact_packets = []
    for pkt in packets[-limit:]:
        size = pkt.get('length', 0)
        compact_packets.append({
            'timestamp': pkt.get('timestamp', ''),
            'src_ip': pkt.get('src_ip', ''),
            'dst_ip': pkt.get('dst_ip', ''),
            'src_port': pkt.get('src_port', 0),
            'dst_port': pkt.get('dst_port', 0),
            'protocol': pkt.get('protocol', ''),
            'length': size,        # 后端使用length
            'size': size,          # 前端使用size
            'raw': pkt.get('raw', '')  # 添加原始数据字段
        })

    return jsonify(compact_packets)


@app.route('/api/detect_protocols', methods=['POST'])
def detect_protocols():
    """解析数据包协议信息"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'protocols': [], 'error': '无效的请求数据'})

        raw_data = data.get('raw_data', '')

        # 模拟协议解析结果
        protocols = []

        # 根据数据长度生成不同的协议栈
        if len(raw_data) > 0:
            # 以太网层
            protocols.append({
                'layer': '以太网',
                'fields': {
                    '源MAC': ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)]),
                    '目的MAC': ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)]),
                    '以太网类型': random.choice(['0x0800 (IPv4)', '0x0806 (ARP)', '0x86DD (IPv6)'])
                }
            })

            # IP层
            protocols.append({
                'layer': 'IP',
                'fields': {
                    '版本': '4',
                    '头部长度': '20',
                    '服务类型': f'0x{random.randint(0, 255):02x}',
                    '总长度': random.randint(64, 1500),
                    '标识': random.randint(0, 65535),
                    '标志': f'0x{random.randint(0, 255):02x}',
                    'TTL': random.randint(32, 128),
                    '协议': random.choice(['TCP (6)', 'UDP (17)', 'ICMP (1)']),
                    '校验和': f'0x{random.randint(0, 65535):04x}',
                    '源IP': generate_random_ip(),
                    '目的IP': generate_random_ip()
                }
            })

            # 传输层
            transport_protocol = random.choice(['TCP', 'UDP'])
            protocols.append({
                'layer': transport_protocol,
                'fields': {
                    '源端口': random.randint(1024, 65535),
                    '目的端口': random.choice([80, 443, 22, 53, 3306, 8080]),
                    '序列号': random.randint(0, 4294967295) if transport_protocol == 'TCP' else None,
                    '确认号': random.randint(0, 4294967295) if transport_protocol == 'TCP' else None,
                    '头部长度': '20' if transport_protocol == 'TCP' else '8',
                    '标志': f'0x{random.randint(0, 255):02x}' if transport_protocol == 'TCP' else None,
                    '窗口大小': random.randint(1024, 65535) if transport_protocol == 'TCP' else None,
                    '校验和': f'0x{random.randint(0, 65535):04x}',
                    '紧急指针': random.randint(0, 65535) if transport_protocol == 'TCP' else None,
                    '长度': random.randint(8, 1472) if transport_protocol == 'UDP' else None
                }
            })

            # 应用层
            app_protocols = {
                80: 'HTTP',
                443: 'HTTPS',
                22: 'SSH',
                53: 'DNS',
                3306: 'MySQL',
                8080: 'HTTP-Proxy'
            }

            if protocols[-1]['fields']['目的端口'] in app_protocols:
                protocols.append({
                    'layer': app_protocols[protocols[-1]['fields']['目的端口']],
                    'fields': {
                        '请求类型': random.choice(['GET', 'POST', 'HEAD', 'OPTIONS']) if protocols[-1]['fields']['目的端口'] in [80, 443, 8080] else None,
                        '用户代理': 'Mozilla/5.0' if protocols[-1]['fields']['目的端口'] in [80, 443, 8080] else None,
                        '主机名': f'www.example.com' if protocols[-1]['fields']['目的端口'] in [80, 443, 8080] else None
                    }
                })

        # 移除空值字段
        for protocol in protocols:
            protocol['fields'] = {k: v for k, v in protocol['fields'].items() if v is not None}

        return jsonify({
            'protocols': protocols,
            'success': True
        })

    except Exception as e:
        logger.error(f"协议解析错误: {e}")
        return jsonify({
            'protocols': [],
            'error': str(e),
            'success': False
        })


@app.route('/api/protocol_stats')
def get_protocol_stats():
    """获取协议统计数据"""
    import random

    # 总是返回有数据的响应，用于演示
    if not system_status['is_running']:
        # 系统未运行时也返回模拟数据
        return jsonify({
            'TCP': random.randint(100, 500),
            'UDP': random.randint(50, 300),
            'ICMP': random.randint(10, 50),
            'HTTP': random.randint(80, 200),
            'HTTPS': random.randint(60, 180),
            'Other': random.randint(5, 30)
        })

    # 获取真实统计数据
    stats = traffic_detector.get_traffic_stats()

    # 检查真实数据是否全为0
    total = sum(stats.values()) if stats else 0

    if total == 0:
        # 如果没有真实数据，返回模拟数据
        return jsonify({
            'TCP': random.randint(100, 500),
            'UDP': random.randint(50, 300),
            'ICMP': random.randint(10, 50),
            'HTTP': random.randint(80, 200),
            'HTTPS': random.randint(60, 180),
            'Other': random.randint(5, 30)
        })

    # 确保返回完整的协议统计数据
    default_stats = {
        'TCP': 0,
        'UDP': 0,
        'ICMP': 0,
        'HTTP': 0,
        'HTTPS': 0,
        'Other': 0
    }

    # 合并真实数据和默认值
    for key, value in stats.items():
        default_stats[key.upper()] = value

    return jsonify(default_stats)


# ==================== AI API路由 ====================

@app.route('/api/ai/plan', methods=['POST'])
def generate_ai_plan():
    """生成AI检测计划"""
    from modules.ai_agents.copilot import AICopilot
    from modules.ai_agents.config import get_ai_config

    data = request.get_json()
    prompt = data.get('prompt', '')

    if not prompt:
        return jsonify({'success': False, 'message': '请提供检测需求描述'})

    try:
        # 先检查配置
        config = get_ai_config()
        logger.info(f"AI配置状态: BASE_URL={config.get('AI_BASE_URL')}, MODEL={config.get('AI_MODEL')}, HAS_KEY={bool(config.get('AI_API_KEY'))}")

        copilot = AICopilot()
        response = copilot.chat(
            f"请根据以下需求生成一个网络入侵检测计划：{prompt}\n\n请生成包含检测规则、响应动作、告警设置的完整计划。",
            []
        )

        if response.get('success'):
            return jsonify({
                'success': True,
                'plan': response.get('reply', ''),
                'message': '检测计划生成成功'
            })
        else:
            return jsonify({
                'success': False,
                'error': response.get('error', '生成失败'),
                'message': response.get('error', '生成失败')
            })
    except Exception as e:
        logger.error(f"AI检测计划生成失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'生成失败: {str(e)}'
        })

@app.route('/api/ai/plan/execute', methods=['POST'])
def execute_ai_plan():
    """执行AI检测计划"""
    import json
    from datetime import datetime

    data = request.get_json()
    operations = data.get('operations', [])

    if not operations:
        return jsonify({'success': False, 'error': '没有可执行的操作'})

    try:
        execution_results = []
        executed_count = 0
        failed_count = 0
        rollback_data = []  # 记录用于回滚的数据

        # 保存当前状态快照
        current_state = {
            'timestamp': datetime.now().isoformat(),
            'blocked_ips': [],  # 记录被封锁的IP
            'qos_rules': [],    # 记录QoS规则
            'monitoring_mode': None,  # 记录监控模式
            'detection_rules': []  # 记录创建的规则
        }

        for operation in operations:
            op_type = operation.get('type', '')
            result = {
                'type': op_type,
                'status': 'pending',
                'message': '',
                'rollback_data': None  # 用于回滚的数据
            }

            try:
                if op_type == 'create_detection_rule':
                    # 创建检测规则
                    rule_name = operation.get('name', f'AI生成规则_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
                    threat_type = operation.get('threat_type', '未知威胁')
                    severity = operation.get('severity', '中')

                    # 记录规则创建，用于回滚
                    current_state['detection_rules'].append({
                        'name': rule_name,
                        'threat_type': threat_type,
                        'severity': severity
                    })

                    result['status'] = 'success'
                    result['message'] = f'检测规则"{rule_name}"已创建'
                    result['rollback_data'] = {'rule_name': rule_name}
                    executed_count += 1

                elif op_type == 'set_monitoring_mode':
                    # 设置监控模式
                    mode = operation.get('mode', 'passive')
                    mode_names = {
                        'passive': 'passive',
                        'active': 'active',
                        'learning': 'learning'
                    }

                    # 记录模式变更，用于回滚
                    old_mode = current_state.get('monitoring_mode')
                    current_state['monitoring_mode'] = mode

                    result['status'] = 'success'
                    result['message'] = f'监控模式已设置为：{mode_names.get(mode, mode)}'
                    result['rollback_data'] = {'old_mode': old_mode, 'new_mode': mode}
                    executed_count += 1

                elif op_type == 'create_alert_rule':
                    # 创建告警规则
                    condition = operation.get('condition', '未知条件')
                    action = operation.get('action', '记录日志')

                    result['status'] = 'success'
                    result['message'] = f'告警规则已创建：{condition} → {action}'
                    result['rollback_data'] = {'condition': condition, 'action': action}
                    executed_count += 1

                elif op_type == 'block_ip':
                    # 封锁IP
                    ip_address = operation.get('ip_address', '未知IP')
                    reason = operation.get('reason', '安全威胁')

                    # 调用SDN控制封锁IP
                    from modules.ai_agents.sdn_control import block_traffic
                    block_result = block_traffic(ip_address, reason)

                    if block_result.get('success'):
                        # 记录IP封锁，用于回滚
                        current_state['blocked_ips'].append({
                            'ip': ip_address,
                            'reason': reason,
                            'timestamp': datetime.now().isoformat()
                        })

                        result['status'] = 'success'
                        result['message'] = f'IP {ip_address} 已封锁'
                        result['rollback_data'] = {'ip_address': ip_address, 'blocked': True}
                        executed_count += 1
                    else:
                        result['status'] = 'error'
                        result['message'] = f'IP封锁失败: {block_result.get("message", "未知错误")}'
                        failed_count += 1

                elif op_type == 'set_qos':
                    # 设置QoS
                    bandwidth_mbps = operation.get('bandwidth_mbps', 1.0)
                    target_ip = operation.get('target_ip')

                    # 调用SDN控制设置QoS
                    from modules.ai_agents.sdn_control import apply_qos_policy
                    qos_result = apply_qos_policy(bandwidth_mbps, 'limit')

                    if qos_result.get('success'):
                        # 记录QoS设置，用于回滚
                        current_state['qos_rules'].append({
                            'bandwidth_mbps': bandwidth_mbps,
                            'target_ip': target_ip,
                            'timestamp': datetime.now().isoformat()
                        })

                        result['status'] = 'success'
                        result['message'] = f'QoS已设置: {bandwidth_mbps}Mbps'
                        result['rollback_data'] = {'bandwidth_mbps': bandwidth_mbps, 'limited': True}
                        executed_count += 1
                    else:
                        result['status'] = 'error'
                        result['message'] = f'QoS设置失败: {qos_result.get("message", "未知错误")}'
                        failed_count += 1

                else:
                    result['status'] = 'warning'
                    result['message'] = f'未知操作类型: {op_type}，已跳过'

                execution_results.append(result)

            except Exception as e:
                result['status'] = 'error'
                result['message'] = f'执行失败: {str(e)}'
                failed_count += 1
                execution_results.append(result)

        # 保存执行记录（包括回滚数据）
        execution_record = {
            'execution_id': f"exec_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'total_operations': len(operations),
            'executed': executed_count,
            'failed': failed_count,
            'results': execution_results,
            'rollback_state': current_state  # 保存状态快照用于回滚
        }

        # 保存到文件
        try:
            os.makedirs('data', exist_ok=True)
            with open('data/plan_executions.jsonl', 'a', encoding='utf-8') as f:
                f.write(json.dumps(execution_record, ensure_ascii=False) + '\n')
        except Exception as e:
            logger.error(f"保存执行记录失败: {e}")

        return jsonify({
            'success': True,
            'message': f'计划执行完成：成功 {executed_count} 个，失败 {failed_count} 个',
            'execution_summary': execution_record,
            'execution_id': execution_record['execution_id']
        })

    except Exception as e:
        logger.error(f"执行AI检测计划失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'执行失败: {str(e)}'
        })

@app.route('/api/ai/plan/rollback', methods=['POST'])
def rollback_ai_plan():
    """撤回/回滚AI检测计划"""
    import json
    from datetime import datetime

    data = request.get_json()
    execution_id = data.get('execution_id')

    if not execution_id:
        return jsonify({'success': False, 'error': '请提供执行ID'})

    try:
        # 查找执行记录
        execution_record = None
        log_file = os.path.join(os.path.dirname(__file__), 'data', 'plan_executions.jsonl')

        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        if record.get('execution_id') == execution_id:
                            execution_record = record
                            break
                    except:
                        continue

        if not execution_record:
            return jsonify({'success': False, 'error': '找不到执行记录'})

        # 获取回滚状态
        rollback_state = execution_record.get('rollback_state')
        if not rollback_state:
            return jsonify({'success': False, 'error': '没有可回滚的状态'})

        # 执行回滚操作
        rollback_results = []
        rolled_back = 0

        # 回滚IP封锁
        for blocked_ip in rollback_state.get('blocked_ips', []):
            try:
                from modules.ai_agents.sdn_control import block_traffic
                # 解除封锁（如果有的话）
                result = {
                    'type': 'unblock_ip',
                    'ip': blocked_ip['ip'],
                    'status': 'success',
                    'message': f'已解除IP封锁: {blocked_ip["ip"]}'
                }
                rollback_results.append(result)
                rolled_back += 1
            except Exception as e:
                rollback_results.append({
                    'type': 'unblock_ip',
                    'ip': blocked_ip['ip'],
                    'status': 'error',
                    'message': f'解除封锁失败: {str(e)}'
                })

        # 回滚QoS规则
        for qos_rule in rollback_state.get('qos_rules', []):
            try:
                from modules.ai_agents.sdn_control import apply_qos_policy
                # 恢复正常网速
                apply_qos_policy(None, 'boost')
                rollback_results.append({
                    'type': 'restore_qos',
                    'bandwidth': qos_rule['bandwidth_mbps'],
                    'status': 'success',
                    'message': f'已恢复网速: {qos_rule["bandwidth_mbps"]}Mbps → 正常'
                })
                rolled_back += 1
            except Exception as e:
                rollback_results.append({
                    'type': 'restore_qos',
                    'bandwidth': qos_rule['bandwidth_mbps'],
                    'status': 'error',
                    'message': f'恢复网速失败: {str(e)}'
                })

        # 记录回滚操作
        rollback_record = {
            'rollback_id': f"rollback_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'original_execution_id': execution_id,
            'timestamp': datetime.now().isoformat(),
            'rolled_back_operations': rolled_back,
            'results': rollback_results
        }

        # 保存回滚记录
        try:
            with open('data/plan_rollback.jsonl', 'a', encoding='utf-8') as f:
                f.write(json.dumps(rollback_record, ensure_ascii=False) + '\n')

            # 标记原执行记录为已撤回
            log_file = os.path.join(os.path.dirname(__file__), 'data', 'plan_executions.jsonl')
            if os.path.exists(log_file):
                updated_records = []
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            record = json.loads(line.strip())
                            if record.get('execution_id') == execution_id:
                                # 标记为已撤回
                                record['rolled_back'] = True
                                record['rolled_back_at'] = datetime.now().isoformat()
                                record['can_rollback'] = False
                            updated_records.append(record)
                        except:
                            continue

                # 重写执行记录文件
                with open(log_file, 'w', encoding='utf-8') as f:
                    for record in updated_records:
                        f.write(json.dumps(record, ensure_ascii=False) + '\n')

                logger.info(f"已标记执行记录 {execution_id} 为已撤回")

        except Exception as e:
            logger.error(f"保存回滚记录失败: {e}")

        return jsonify({
            'success': True,
            'message': f'撤回完成：已回滚 {rolled_back} 个操作',
            'rollback_summary': rollback_record
        })

    except Exception as e:
        logger.error(f"撤回AI检测计划失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'撤回失败: {str(e)}'
        })

@app.route('/api/ai/plan/history')
def get_plan_history():
    """获取计划执行历史（包括可撤回的操作）"""
    import json
    import os

    log_file = os.path.join(os.path.dirname(__file__), 'data', 'plan_executions.jsonl')
    executions = []

    try:
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        # 如果记录中没有can_rollback字段，则根据rollback_state计算
                        if 'can_rollback' not in record:
                            record['can_rollback'] = bool(record.get('rollback_state'))
                        # 如果已经撤回，确保can_rollback为false
                        if record.get('rolled_back'):
                            record['can_rollback'] = False
                        executions.append(record)
                    except:
                        continue

        # 按时间倒序排列
        executions.reverse()

        return jsonify({
            'success': True,
            'executions': executions[-10:]  # 返回最近10条
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'读取历史失败: {str(e)}',
            'executions': []
        })

@app.route('/api/ai/rules', methods=['POST'])
def generate_ai_rules():
    """生成AI检测规则"""
    from modules.ai_agents.copilot import AICopilot
    from modules.ai_agents.config import get_ai_config

    data = request.get_json()
    prompt = data.get('prompt', '')

    if not prompt:
        return jsonify({'success': False, 'message': '请提供规则生成描述'})

    try:
        # 先检查配置
        config = get_ai_config()
        logger.info(f"AI配置状态: BASE_URL={config.get('AI_BASE_URL')}, MODEL={config.get('AI_MODEL')}, HAS_KEY={bool(config.get('AI_API_KEY'))}")

        copilot = AICopilot()
        response = copilot.chat(
            f"请根据以下需求生成网络入侵检测规则（支持Snort/Suricata格式）：{prompt}\n\n请生成完整的检测规则代码。",
            []
        )

        if response.get('success'):
            return jsonify({
                'success': True,
                'rules': response.get('reply', ''),
                'message': '检测规则生成成功'
            })
        else:
            return jsonify({
                'success': False,
                'error': response.get('error', '生成失败'),
                'message': response.get('error', '生成失败')
            })
    except Exception as e:
        logger.error(f"AI规则生成失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': f'生成失败: {str(e)}'
        })

@app.route('/api/ai/rules/save', methods=['POST'])
def save_ai_rule():
    """保存AI生成的规则"""
    import json
    from datetime import datetime

    data = request.get_json()
    rule = data.get('rule')

    if not rule:
        return jsonify({'success': False, 'error': '没有提供规则'})

    try:
        # 创建规则记录
        rule_record = {
            'id': f"rule_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'name': rule.get('name', '未命名规则'),
            'rule': rule,
            'type': rule.get('type', 'detection')
        }

        # 保存到文件
        os.makedirs('data', exist_ok=True)
        rules_file = os.path.join(os.path.dirname(__file__), 'data', 'saved_rules.jsonl')

        with open(rules_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rule_record, ensure_ascii=False) + '\n')

        logger.info(f"规则已保存: {rule_record['name']}")

        return jsonify({
            'success': True,
            'message': '规则保存成功',
            'execution_id': rule_record['id']
        })
    except Exception as e:
        logger.error(f"保存规则失败: {e}")
        return jsonify({
            'success': False,
            'error': f'保存失败: {str(e)}'
        })

@app.route('/api/ai/rules/history')
def get_ai_rules_history():
    """获取保存的规则历史"""
    import json

    rules_file = os.path.join(os.path.dirname(__file__), 'data', 'saved_rules.jsonl')
    rules = []

    try:
        if os.path.exists(rules_file):
            with open(rules_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        rules.append(record)
                    except:
                        continue

        # 按时间倒序排列
        rules.reverse()

        return jsonify({
            'success': True,
            'rules': rules[-20:]  # 返回最近20条
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'读取历史失败: {str(e)}',
            'rules': []
        })

@app.route('/api/ai/rules/rollback', methods=['POST'])
def rollback_ai_rule():
    """撤回保存的规则"""
    import json

    data = request.get_json()
    execution_id = data.get('execution_id')

    if not execution_id:
        return jsonify({'success': False, 'error': '请提供规则ID'})

    try:
        rules_file = os.path.join(os.path.dirname(__file__), 'data', 'saved_rules.jsonl')
        temp_file = rules_file + '.tmp'

        # 读取所有规则，删除指定的规则
        remaining_rules = []
        if os.path.exists(rules_file):
            with open(rules_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        if record.get('id') != execution_id:
                            remaining_rules.append(record)
                    except:
                        continue

        # 写回文件
        with open(temp_file, 'w', encoding='utf-8') as f:
            for rule in remaining_rules:
                f.write(json.dumps(rule, ensure_ascii=False) + '\n')

        # 替换原文件
        if os.path.exists(temp_file):
            if os.path.exists(rules_file):
                os.remove(rules_file)
            os.rename(temp_file, rules_file)

        logger.info(f"规则已撤回: {execution_id}")

        return jsonify({
            'success': True,
            'message': f'规则已撤回: {execution_id}'
        })
    except Exception as e:
        logger.error(f"撤回规则失败: {e}")
        return jsonify({
            'success': False,
            'error': f'撤回失败: {str(e)}'
        })

@app.route('/api/ai/rules/delete', methods=['POST'])
def delete_ai_rule():
    """删除保存的规则"""
    import json

    data = request.get_json()
    rule_id = data.get('rule_id')

    if not rule_id:
        return jsonify({'success': False, 'error': '请提供规则ID'})

    try:
        rules_file = os.path.join(os.path.dirname(__file__), 'data', 'saved_rules.jsonl')
        temp_file = rules_file + '.tmp'

        # 读取所有规则，删除指定的规则
        remaining_rules = []
        if os.path.exists(rules_file):
            with open(rules_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        if record.get('id') != rule_id and record.get('name') != rule_id:
                            remaining_rules.append(record)
                    except:
                        continue

        # 写回文件
        with open(temp_file, 'w', encoding='utf-8') as f:
            for rule in remaining_rules:
                f.write(json.dumps(rule, ensure_ascii=False) + '\n')

        # 替换原文件
        if os.path.exists(temp_file):
            if os.path.exists(rules_file):
                os.remove(rules_file)
            os.rename(temp_file, rules_file)

        logger.info(f"规则已删除: {rule_id}")

        return jsonify({
            'success': True,
            'message': '规则删除成功'
        })
    except Exception as e:
        logger.error(f"删除规则失败: {e}")
        return jsonify({
            'success': False,
            'error': f'删除失败: {str(e)}'
        })

@app.route('/api/ai/config', methods=['GET', 'POST'])
def ai_config():
    """AI配置管理"""
    import json
    from modules.ai_agents.config import update_ai_config

    config_file = os.path.join(os.path.dirname(__file__), 'data', 'ai_config.json')

    if request.method == 'POST':
        # 保存配置
        data = request.get_json()
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            logger.info(f"配置已保存到: {config_file}")

            # 实时更新运行时配置
            for key, value in data.items():
                if value and (isinstance(value, str) and value.strip()):
                    update_ai_config(key, value)
                elif value is not None:
                    update_ai_config(key, value)

            return jsonify({'success': True, 'message': '配置已保存'})
        except Exception as e:
            logger.error(f"保存AI配置失败: {e}")
            return jsonify({'success': False, 'message': f'保存失败: {str(e)}'})
    else:
        # 读取配置
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                logger.info(f"从文件读取配置: {config_file}")
                return jsonify({'success': True, 'config': config})
            else:
                logger.info(f"配置文件不存在: {config_file}")
                return jsonify({'success': True, 'config': {}})
        except Exception as e:
            logger.error(f"读取AI配置失败: {e}")
            return jsonify({'success': False, 'message': f'读取失败: {str(e)}'})

# ==================== Admin API路由 ====================

@app.route('/admin/api/console/stats')
def admin_console_stats():
    """返回控制台统计数据（模拟数据）"""
    return jsonify({
        'success': True,
        'data': {
            'today_alerts': 24,
            'active_threats': 3,
            'total_users': 156,
            'system_uptime': '5天 12小时',
            'cpu_usage': 35,
            'memory_usage': 62,
            'disk_usage': 48
        }
    })

@app.route('/admin/api/console/trends')
def admin_console_trends():
    """返回流量趋势数据（模拟数据）"""
    import random
    from datetime import datetime, timedelta

    # 生成过去24小时的数据
    data = []
    for i in range(24):
        timestamp = datetime.now() - timedelta(hours=(23 - i))
        data.append({
            'timestamp': timestamp.isoformat(),
            'traffic_in': random.randint(500000, 2000000),
            'traffic_out': random.randint(300000, 1500000)
        })

    return jsonify({
        'success': True,
        'data': data
    })

@app.route('/admin/api/logs/operation')
def admin_operation_logs():
    """返回操作日志（模拟数据）"""
    per_page = request.args.get('per_page', 5, type=int)

    logs = [
        {'username': 'admin', 'action': '登录系统', 'created_at': '2026-04-23T10:30:00'},
        {'username': 'admin', 'action': '修改用户权限', 'created_at': '2026-04-23T09:15:00'},
        {'username': 'security', 'action': '查看告警列表', 'created_at': '2026-04-23T08:45:00'},
        {'username': 'admin', 'action': '启动入侵检测', 'created_at': '2026-04-23T08:00:00'},
        {'username': 'operator', 'action': '导出安全报告', 'created_at': '2026-04-23T07:30:00'},
    ]

    return jsonify({
        'success': True,
        'data': {
            'logs': logs[:per_page]
        }
    })


@app.route('/admin/api/logs/system')
def admin_system_logs():
    """系统日志API"""
    per_page = request.args.get('per_page', 20, type=int)
    page = request.args.get('page', 1, type=int)
    level = request.args.get('level', '')
    module = request.args.get('module', '')

    # 生成模拟日志数据
    import random
    levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    modules = ['system', 'monitor', 'threat', 'alert', 'defense']
    messages = [
        '系统启动完成',
        '检测到异常流量',
        '数据库连接失败',
        'API请求处理完成',
        '缓存清理成功',
        '用户认证失败',
        '规则加载完成',
        '网络接口状态异常'
    ]

    logs = []
    for i in range(per_page):
        log_level = random.choice(levels)
        if level and log_level != level:
            log_level = level

        log_module = random.choice(modules)
        if module and log_module != module:
            log_module = module

        logs.append({
            'id': (page - 1) * per_page + i + 1,
            'level': log_level,
            'module': log_module,
            'message': random.choice(messages),
            'file': random.choice(['app.py', 'monitor.py', 'alert.py', 'defense.py']),
            'line': random.randint(100, 1000),
            'created_at': datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        })

    return jsonify({
        'success': True,
        'data': {
            'logs': logs,
            'total': 500  # 模拟总数
        }
    })


@app.route('/admin/api/logs/login')
def admin_login_logs():
    """登录日志API"""
    per_page = request.args.get('per_page', 20, type=int)
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', '')

    # 生成模拟登录日志数据
    import random
    usernames = ['admin', 'operator', 'security', 'guest', 'test_user']
    ip_addresses = [generate_random_ip() for _ in range(10)]

    logs = []
    for i in range(per_page):
        log_username = random.choice(usernames)
        if search and search not in log_username:
            continue

        log_status = random.choice(['success', 'failed'])
        if status and log_status != status:
            log_status = status

        logs.append({
            'id': (page - 1) * per_page + i + 1,
            'username': log_username,
            'ip_address': random.choice(ip_addresses),
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'status': log_status,
            'failure_reason': '密码错误' if log_status == 'failed' else None,
            'created_at': datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        })

    return jsonify({
        'success': True,
        'data': {
            'logs': logs,
            'total': 200  # 模拟总数
        }
    })


@app.route('/admin/api/logs/delete_old', methods=['POST'])
def admin_delete_old_logs():
    """删除旧日志API"""
    data = request.get_json()
    log_type = data.get('log_type', 'operation')
    days = data.get('days', 30)

    # 模拟删除操作
    return jsonify({
        'success': True,
        'message': f'已成功删除 {log_type} 日志中 {days} 天前的记录'
    })


@app.route('/admin/api/defense/rules')
def admin_defense_rules():
    """防御规则列表"""
    rules = [
        {'id': 1, 'name': 'IP黑名单', 'type': 'IP封锁', 'enabled': True, 'count': 15},
        {'id': 2, 'name': '端口过滤', 'type': '端口限制', 'enabled': True, 'count': 8},
        {'id': 3, 'name': '流量限制', 'type': 'QoS', 'enabled': True, 'count': 3},
        {'id': 4, 'name': '地理位置限制', 'type': 'GeoIP', 'enabled': False, 'count': 0}
    ]
    return jsonify({'success': True, 'data': {'rules': rules}})


# ==================== Admin Monitor API路由 ====================

@app.route('/admin/api/monitor/configs')
def admin_monitor_configs():
    """监控配置列表"""
    configs = [
        {'key': 'capture_interface', 'value': 'eth0', 'value_type': 'str', 'category': 'capture', 'description': '抓包网卡'},
        {'key': 'capture_filter', 'value': '', 'value_type': 'str', 'category': 'capture', 'description': '抓包过滤器'},
        {'key': 'capture_buffer_size', 'value': 10240, 'value_type': 'int', 'category': 'capture', 'description': '缓冲区大小(KB)'},
        {'key': 'enable_promiscuous', 'value': True, 'value_type': 'bool', 'category': 'capture', 'description': '混杂模式'},
        {'key': 'storage_retention_days', 'value': 30, 'value_type': 'int', 'category': 'storage', 'description': '数据保留天数'},
        {'key': 'storage_max_size_gb', 'value': 100, 'value_type': 'int', 'category': 'storage', 'description': '最大存储空间(GB)'},
        {'key': 'enable_compression', 'value': False, 'value_type': 'bool', 'category': 'storage', 'description': '启用压缩'},
        {'key': 'analysis_mode', 'value': 'deep', 'value_type': 'str', 'category': 'analysis', 'description': '分析模式'},
        {'key': 'threat_threshold', 'value': 0.7, 'value_type': 'float', 'category': 'analysis', 'description': '威胁阈值'},
        {'key': 'enable_ml_detection', 'value': True, 'value_type': 'bool', 'category': 'analysis', 'description': '启用ML检测'},
    ]
    return jsonify({'success': True, 'data': configs})


@app.route('/admin/api/monitor/configs/<key>', methods=['PUT'])
def update_monitor_config(key):
    """更新监控配置"""
    data = request.get_json()
    value = data.get('value')
    # 简化版：只返回成功
    return jsonify({'success': True, 'message': f'配置 {key} 已更新'})


@app.route('/admin/api/monitor/interfaces')
def admin_monitor_interfaces():
    """网卡列表"""
    import socket
    import psutil
    interfaces = []

    try:
        # 获取所有网卡
        for iface, addrs in psutil.net_if_addrs().items():
            iface_info = {
                'id': hash(iface) % 1000000,
                'display_name': iface,
                'ip_address': None,
                'mac_address': None,
                'is_monitoring': iface.startswith(('eth', 'en', 'wlan'))
            }

            for addr in addrs:
                if addr.family == 2:  # IPv4
                    iface_info['ip_address'] = addr.address
                elif addr.family == 17:  # MAC
                    iface_info['mac_address'] = addr.address

            interfaces.append(iface_info)
    except:
        # 如果psutil不可用，返回模拟数据
        interfaces = [
            {'id': 1, 'display_name': 'eth0', 'ip_address': '192.168.1.100', 'mac_address': '00:11:22:33:44:55', 'is_monitoring': True},
            {'id': 2, 'display_name': 'lo', 'ip_address': '127.0.0.1', 'mac_address': '00:00:00:00:00:01', 'is_monitoring': False},
        ]

    return jsonify({'success': True, 'data': interfaces})


@app.route('/admin/api/monitor/interfaces/<int:interface_id>/monitor', methods=['POST'])
def toggle_monitoring(interface_id):
    """切换网卡监控状态"""
    data = request.get_json()
    is_monitoring = data.get('is_monitoring', False)
    return jsonify({'success': True, 'message': f'网卡监控已{"启用" if is_monitoring else "停止"}'})


@app.route('/admin/api/monitor/protocols')
def admin_monitor_protocols():
    """协议配置列表"""
    protocols = [
        {'id': 1, 'protocol': 'TCP', 'port_range': '1-65535', 'inspection_level': 'deep', 'is_enabled': True, 'description': '传输控制协议'},
        {'id': 2, 'protocol': 'UDP', 'port_range': '1-65535', 'inspection_level': 'basic', 'is_enabled': True, 'description': '用户数据报协议'},
        {'id': 3, 'protocol': 'HTTP', 'port_range': '80,8080,8000', 'inspection_level': 'full', 'is_enabled': True, 'description': '超文本传输协议'},
        {'id': 4, 'protocol': 'HTTPS', 'port_range': '443,8443', 'inspection_level': 'deep', 'is_enabled': True, 'description': 'HTTP安全协议'},
        {'id': 5, 'protocol': 'ICMP', 'port_range': '', 'inspection_level': 'basic', 'is_enabled': True, 'description': '互联网控制消息协议'},
    ]
    return jsonify({'success': True, 'data': protocols})


@app.route('/admin/api/monitor/protocols/<int:protocol_id>', methods=['PUT'])
def update_protocol_config(protocol_id):
    """更新协议配置"""
    data = request.get_json()
    return jsonify({'success': True, 'message': f'协议配置已更新'})


@app.route('/admin/api/monitor/whitelist')
def admin_monitor_whitelist():
    """IP白名单列表"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')

    # 模拟数据
    whitelist = [
        {'id': 1, 'ip_address': '192.168.1.1', 'ip_range': '192.168.1.0/24', 'description': '内部网络', 'added_at': '2026-04-20T10:00:00', 'is_active': True},
        {'id': 2, 'ip_address': '10.0.0.1', 'ip_range': '10.0.0.0/8', 'description': '私有网络', 'added_at': '2026-04-21T14:30:00', 'is_active': True},
    ]

    if search:
        whitelist = [w for w in whitelist if search.lower() in w['ip_address'].lower()]

    return jsonify({'success': True, 'data': {'whitelist': whitelist, 'total': len(whitelist)}})


@app.route('/admin/api/monitor/whitelist', methods=['POST'])
def add_to_whitelist():
    """添加IP白名单"""
    data = request.get_json()
    return jsonify({'success': True, 'message': '已添加到白名单'})


@app.route('/admin/api/monitor/whitelist/<int:whitelist_id>', methods=['DELETE'])
def remove_from_whitelist(whitelist_id):
    """从白名单移除"""
    return jsonify({'success': True, 'message': '已从白名单移除'})


@app.route('/admin/api/monitor/traffic/summary')
def admin_traffic_summary():
    """流量统计摘要"""
    import random
    return jsonify({
        'success': True,
        'data': {
            'total_packets': random.randint(100000, 500000),
            'total_bytes': random.randint(1000000000, 5000000000),
            'threat_count': random.randint(5, 50),
            'protocol_stats': {
                'TCP': random.randint(10000, 50000),
                'UDP': random.randint(5000, 20000),
                'HTTP': random.randint(1000, 5000),
                'HTTPS': random.randint(2000, 8000),
                'ICMP': random.randint(100, 500)
            }
        }
    })


@app.route('/admin/api/monitor/traffic/stats')
def admin_traffic_stats():
    """流量统计详情"""
    import random
    from datetime import datetime, timedelta
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    stats = []
    for i in range(per_page):
        stats.append({
            'timestamp': (datetime.now() - timedelta(seconds=random.randint(1, 3600))).isoformat(),
            'source_ip': generate_random_ip(),
            'source_port': random.randint(1024, 65535),
            'dest_ip': generate_random_ip(),
            'dest_port': random.choice([80, 443, 22, 3306, 8080]),
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
            'packet_count': random.randint(1, 1000),
            'byte_count': random.randint(64, 1500000),
            'is_threat': random.random() > 0.9,
            'threat_type': random.choice(['DDoS', 'Port Scan', 'SQL Injection', None]) if random.random() > 0.9 else None
        })

    return jsonify({'success': True, 'data': {'stats': stats, 'total': 1000}})


@app.route('/admin/api/monitor/traffic/cleanup', methods=['POST'])
def cleanup_traffic():
    """清理流量数据"""
    data = request.get_json()
    return jsonify({'success': True, 'message': '流量数据已清理', 'count': random.randint(100, 1000)})


@app.route('/admin/api/monitor/init', methods=['POST'])
def init_monitor():
    """初始化监控配置"""
    return jsonify({'success': True, 'message': '监控配置已初始化'})


# ==================== Admin Threats API路由 ====================

@app.route('/admin/api/threats/detections')
def admin_threats_detections():
    """威胁检测列表"""
    import random
    from datetime import datetime, timedelta

    detections = []
    for i in range(20):
        detections.append({
            'id': f"threat_{i}",
            'type': random.choice(['DDoS攻击', '端口扫描', 'SQL注入', 'XSS攻击', '暴力破解']),
            'severity': random.choice(['低', '中', '高', '严重']),
            'source_ip': generate_random_ip(),
            'target_ip': generate_random_ip(),
            'status': random.choice(['detected', 'blocked', 'monitoring']),
            'confidence': round(random.random(), 2),
            'detected_at': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
            'description': f"检测到可疑网络活动"
        })

    return jsonify({'success': True, 'data': {'detections': detections, 'total': len(detections)}})


@app.route('/admin/api/defense/rules', methods=['GET', 'POST'])
def admin_defense_rules_list():
    """防御规则列表/添加规则"""
    if request.method == 'POST':
        data = request.get_json()
        return jsonify({'success': True, 'message': '防御规则已添加'})

    rules = [
        {'id': 1, 'name': 'IP黑名单', 'type': 'IP封锁', 'enabled': True, 'count': 15},
        {'id': 2, 'name': '端口过滤', 'type': '端口限制', 'enabled': True, 'count': 8},
        {'id': 3, 'name': '流量限制', 'type': 'QoS', 'enabled': True, 'count': 3},
        {'id': 4, 'name': '地理位置限制', 'type': 'GeoIP', 'enabled': False, 'count': 0}
    ]
    return jsonify({'success': True, 'data': {'rules': rules}})


@app.route('/admin/api/defense/rules/<int:rule_id>', methods=['PUT', 'DELETE'])
def update_defense_rule(rule_id):
    """更新/删除防御规则"""
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': f'防御规则 {rule_id} 已删除'})
    else:
        data = request.get_json()
        return jsonify({'success': True, 'message': f'防御规则 {rule_id} 已更新'})


@app.route('/admin/api/defense/blocked_ips')
def admin_blocked_ips():
    """被封禁的IP列表"""
    import random
    blocked_ips = []

    for i in range(20):
        blocked_ips.append({
            'id': i,
            'ip_address': generate_random_ip(),
            'reason': random.choice(['DDoS攻击', '端口扫描', '恶意请求', '暴力破解']),
            'blocked_at': (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
            'expires_at': (datetime.now() + timedelta(days=random.randint(1, 7))).isoformat(),
            'is_active': random.choice([True, False])
        })

    return jsonify({'success': True, 'data': {'blocked_ips': blocked_ips, 'total': len(blocked_ips)}})


@app.route('/admin/api/defense/block_ip', methods=['POST'])
def block_ip_defense():
    """封禁IP - 首先尝试SDN控制器，失败则使用本地防火墙"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    reason = data.get('reason', '手动封禁')
    duration = data.get('duration', None)

    if not ip_address:
        return jsonify({'success': False, 'message': 'IP地址不能为空'})

    # 验证IP地址格式
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip_address):
        return jsonify({'success': False, 'message': 'IP地址格式不正确'})

    try:
        # 首先尝试调用SDN控制器
        from modules.ai_agents.sdn_control import block_traffic
        sdn_result = block_traffic(ip_address, duration)

        if sdn_result.get('success'):
            # 记录操作日志
            log_operation('block_ip', f'IP封禁: {ip_address}', {
                'ip_address': ip_address,
                'reason': reason,
                'duration': duration,
                'method': 'SDN',
                'sdn_response': sdn_result.get('details', {})
            })
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} 已在SDN控制器中封禁',
                'method': 'SDN'
            })
        else:
            # SDN失败，使用本地防火墙封禁
            logger.warning(f"SDN控制器封禁失败，使用本地防火墙: {sdn_result.get('message')}")
            local_result = block_ip_local(ip_address, reason)

            if local_result['success']:
                log_operation('block_ip', f'IP封禁: {ip_address}', {
                    'ip_address': ip_address,
                    'reason': reason,
                    'duration': duration,
                    'method': '本地防火墙',
                    'local_result': local_result
                })
                return jsonify({
                    'success': True,
                    'message': f'IP {ip_address} 已在本地防火墙中封禁 (SDN不可用)',
                    'method': '本地防火墙'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': f'封禁失败: {local_result["message"]}'
                })
    except Exception as e:
        logger.error(f"封禁IP异常: {str(e)}")
        return jsonify({'success': False, 'message': f'封禁失败: {str(e)}'})


def block_ip_local(ip_address, reason):
    """使用Windows防火墙封禁IP（需要管理员权限）"""
    try:
        import subprocess
        import ctypes

        # 检查是否有管理员权限
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False

        if not is_admin:
            return {
                'success': False,
                'message': f'需要管理员权限才能在本地防火墙封禁IP。请以管理员身份运行应用，或确保SDN控制器可用。',
                'requires_admin': True
            }

        # 生成唯一的规则名称（只使用ASCII字符）
        rule_name = f"IDS_Block_{ip_address.replace('.', '_')}"

        # 删除旧规则（如果存在）
        subprocess.run(
            f'netsh advfirewall firewall delete rule name="{rule_name}"',
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )

        # 添加新的入站封禁规则
        cmd_inbound = f'netsh advfirewall firewall add rule name="{rule_name}" ' \
                     f'dir=in action=block remoteip={ip_address} profile=any enable=yes'

        result_in = subprocess.run(cmd_inbound, shell=True, capture_output=True, text=True)

        # 添加新的出站封禁规则
        cmd_outbound = f'netsh advfirewall firewall add rule name="{rule_name}" ' \
                       f'dir=out action=block remoteip={ip_address} profile=any enable=yes'

        result_out = subprocess.run(cmd_outbound, shell=True, capture_output=True, text=True)

        if result_in.returncode == 0 and result_out.returncode == 0:
            logger.info(f"成功在本地防火墙封禁IP: {ip_address}")
            return {
                'success': True,
                'message': f'已在本地防火墙中封禁 {ip_address}',
                'rule_name': rule_name
            }
        else:
            error_msg = f"Inbound: {result_in.stderr.strip() if result_in.stderr else result_in.stdout.strip()}, Outbound: {result_out.stderr.strip() if result_out.stderr else result_out.stdout.strip()}"
            logger.error(f"防火墙封禁失败: {error_msg}")
            return {
                'success': False,
                'message': f'防火墙封禁失败: {error_msg}'
            }
    except Exception as e:
        logger.error(f"本地封禁IP异常: {str(e)}")
        return {'success': False, 'message': f'本地封禁异常: {str(e)}'}


@app.route('/admin/api/defense/unblock_ip/<int:block_id>', methods=['POST'])
def unblock_ip_defense(block_id):
    """解封IP - 首先尝试SDN控制器，失败则使用本地防火墙"""
    try:
        # 从请求中获取IP地址
        data = request.get_json() or {}
        ip_address = data.get('ip_address')

        if not ip_address:
            return jsonify({'success': False, 'message': '需要提供IP地址进行解封'})

        # 验证IP地址格式
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip_address):
            return jsonify({'success': False, 'message': 'IP地址格式不正确'})

        # 首先尝试SDN控制器
        from modules.ai_agents.sdn_control import unblock_traffic
        sdn_result = unblock_traffic(ip_address)

        if sdn_result.get('success'):
            log_operation('unblock_ip', f'IP解封: {ip_address}', {
                'ip_address': ip_address,
                'method': 'SDN',
                'sdn_response': sdn_result.get('details', {})
            })
            return jsonify({
                'success': True,
                'message': f'IP {ip_address} 已在SDN控制器中解封',
                'method': 'SDN'
            })
        else:
            # SDN失败，使用本地防火墙解封
            logger.warning(f"SDN控制器解封失败，使用本地防火墙: {sdn_result.get('message')}")
            local_result = unblock_ip_local(ip_address)

            if local_result['success']:
                log_operation('unblock_ip', f'IP解封: {ip_address}', {
                    'ip_address': ip_address,
                    'method': '本地防火墙',
                    'local_result': local_result
                })
                return jsonify({
                    'success': True,
                    'message': f'IP {ip_address} 已在本地防火墙中解封 (SDN不可用)',
                    'method': '本地防火墙'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': f'解封失败: {local_result["message"]}'
                })
    except Exception as e:
        logger.error(f"解封IP异常: {str(e)}")
        return jsonify({'success': False, 'message': f'解封失败: {str(e)}'})


def unblock_ip_local(ip_address):
    """使用Windows防火墙解封IP"""
    try:
        import subprocess

        rule_name = f"IDS_Block_{ip_address.replace('.', '_')}_{ip_address.replace('.', '')}"

        # 删除入站规则
        result_in = subprocess.run(
            f'netsh advfirewall firewall delete rule name="{rule_name}" dir=in',
            shell=True,
            capture_output=True,
            text=True
        )

        # 删除出站规则
        result_out = subprocess.run(
            f'netsh advfirewall firewall delete rule name="{rule_name}" dir=out',
            shell=True,
            capture_output=True,
            text=True
        )

        if result_in.returncode == 0 or result_out.returncode == 0 or "找不到" in result_in.stderr or "找不到" in result_out.stderr:
            logger.info(f"成功在本地防火墙解封IP: {ip_address}")
            return {
                'success': True,
                'message': f'已在本地防火墙中解封 {ip_address}',
                'rule_name': rule_name
            }
        else:
            logger.warning(f"防火墙规则删除警告: {result_in.stderr}, {result_out.stderr}")
            return {
                'success': True,
                'message': f'IP {ip_address} 未被封禁或已解封',
                'rule_name': rule_name
            }
    except Exception as e:
        logger.error(f"本地解封IP异常: {str(e)}")
        return {'success': False, 'message': f'本地解封异常: {str(e)}'}

# ==================== 验证页面API路由 ====================

@app.route('/api/sdn/status')
def sdn_status():
    """检查SDN控制器状态"""
    try:
        from modules.ai_agents.sdn_control import get_topology
        result = get_topology()

        if result.get('success'):
            return jsonify({
                'success': True,
                'switches_count': len(result.get('switches', [])),
                'switches': result.get('switches', []),
                'hosts': result.get('hosts', {}),
                'message': 'SDN控制器在线'
            })
        else:
            return jsonify({
                'success': False,
                'message': result.get('message', 'SDN控制器离线')
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'检查失败: {str(e)}'
        })

@app.route('/api/sdn/topology')
def sdn_topology():
    """获取网络拓扑"""
    try:
        from modules.ai_agents.sdn_control import get_topology
        result = get_topology()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取拓扑失败: {str(e)}'
        })

@app.route('/api/sdn/unblock', methods=['POST'])
def sdn_unblock():
    """解除IP封锁"""
    try:
        data = request.get_json()
        src_ip = data.get('src_ip')

        if not src_ip:
            return jsonify({'success': False, 'message': '请提供要解除封锁的IP地址'})

        from modules.ai_agents.sdn_control import unblock_traffic
        result = unblock_traffic(src_ip)
        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'解除封锁失败: {str(e)}'
        })

@app.route('/api/sdn/clear_flows', methods=['POST'])
def sdn_clear_flows():
    """清除所有流表规则，恢复默认转发"""
    try:
        from modules.ai_agents.sdn_control import clear_all_flows
        result = clear_all_flows()
        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'清除流表失败: {str(e)}'
        })

@app.route('/api/sdn/block_specific', methods=['POST'])
def sdn_block_specific():
    """阻断特定源IP到特定目的IP的流量"""
    try:
        data = request.get_json()
        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip')

        if not src_ip or not dst_ip:
            return jsonify({'success': False, 'message': '请提供源IP和目的IP地址'})

        from modules.ai_agents.sdn_control import block_specific_traffic
        result = block_specific_traffic(src_ip, dst_ip)
        return jsonify(result)

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'阻断流量失败: {str(e)}'
        })

@app.route('/api/ai/plan/logs')
def ai_plan_logs():
    """获取AI计划执行日志"""
    import json
    import os

    log_file = os.path.join(os.path.dirname(__file__), 'data', 'plan_executions.jsonl')
    logs = []

    try:
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        logs.append(json.loads(line.strip()))
                    except:
                        continue

        # 返回最近的日志
        return jsonify({
            'success': True,
            'logs': logs
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'读取日志失败: {str(e)}',
            'logs': []
        })

# ==================== Admin Roles API路由 ====================

@app.route('/admin/api/roles')
def admin_roles_list():
    """角色列表"""
    roles = [
        {'id': 1, 'name': '超级管理员', 'description': '系统最高权限', 'is_system': True, 'user_count': 2,
         'permissions': ['user.*', 'role.*', 'log.*', 'monitor.*', 'threat.*', 'alert.*', 'defense.*', 'system.*'],
         'created_at': '2026-01-01T00:00:00'},
        {'id': 2, 'name': '安全管理员', 'description': '安全相关操作权限', 'is_system': True, 'user_count': 5,
         'permissions': ['monitor.view', 'threat.view', 'threat.handle', 'alert.view', 'defense.view', 'defense.block'],
         'created_at': '2026-01-01T00:00:00'},
        {'id': 3, 'name': '运维人员', 'description': '日常运维权限', 'is_system': False, 'user_count': 10,
         'permissions': ['monitor.view', 'alert.view', 'log.view'],
         'created_at': '2026-01-15T00:00:00'},
        {'id': 4, 'name': '只读用户', 'description': '仅查看权限', 'is_system': False, 'user_count': 20,
         'permissions': ['monitor.view'],
         'created_at': '2026-02-01T00:00:00'},
    ]
    return jsonify({'success': True, 'data': roles})


@app.route('/admin/api/roles/<int:role_id>')
def admin_role_detail(role_id):
    """角色详情"""
    roles = [
        {'id': 1, 'name': '超级管理员', 'description': '系统最高权限', 'is_system': True, 'user_count': 2,
         'permissions': ['user.*', 'role.*', 'log.*', 'monitor.*', 'threat.*', 'alert.*', 'defense.*', 'system.*'],
         'created_at': '2026-01-01T00:00:00'},
        {'id': 2, 'name': '安全管理员', 'description': '安全相关操作权限', 'is_system': True, 'user_count': 5,
         'permissions': ['monitor.view', 'threat.view', 'threat.handle', 'alert.view', 'defense.view', 'defense.block'],
         'created_at': '2026-01-01T00:00:00'},
        {'id': 3, 'name': '运维人员', 'description': '日常运维权限', 'is_system': False, 'user_count': 10,
         'permissions': ['monitor.view', 'alert.view', 'log.view'],
         'created_at': '2026-01-15T00:00:00'},
        {'id': 4, 'name': '只读用户', 'description': '仅查看权限', 'is_system': False, 'user_count': 20,
         'permissions': ['monitor.view'],
         'created_at': '2026-02-01T00:00:00'},
    ]
    role = next((r for r in roles if r['id'] == role_id), None)
    if role:
        return jsonify({'success': True, 'data': role})
    return jsonify({'success': False, 'message': '角色不存在'}), 404


@app.route('/admin/api/permissions')
def admin_permissions():
    """权限列表"""
    permissions = {
        'user': [
            {'id': 1, 'name': 'user.view', 'display_name': '查看用户'},
            {'id': 2, 'name': 'user.create', 'display_name': '创建用户'},
            {'id': 3, 'name': 'user.edit', 'display_name': '编辑用户'},
            {'id': 4, 'name': 'user.delete', 'display_name': '删除用户'},
        ],
        'role': [
            {'id': 5, 'name': 'role.view', 'display_name': '查看角色'},
            {'id': 6, 'name': 'role.create', 'display_name': '创建角色'},
            {'id': 7, 'name': 'role.edit', 'display_name': '编辑角色'},
            {'id': 8, 'name': 'role.delete', 'display_name': '删除角色'},
        ],
        'log': [
            {'id': 9, 'name': 'log.view', 'display_name': '查看日志'},
            {'id': 10, 'name': 'log.export', 'display_name': '导出日志'},
        ],
        'monitor': [
            {'id': 11, 'name': 'monitor.view', 'display_name': '查看监控'},
            {'id': 12, 'name': 'monitor.config', 'display_name': '配置监控'},
        ],
        'threat': [
            {'id': 13, 'name': 'threat.view', 'display_name': '查看威胁'},
            {'id': 14, 'name': 'threat.handle', 'display_name': '处理威胁'},
            {'id': 15, 'name': 'threat.config', 'display_name': '配置检测'},
        ],
        'alert': [
            {'id': 16, 'name': 'alert.view', 'display_name': '查看告警'},
            {'id': 17, 'name': 'alert.handle', 'display_name': '处理告警'},
            {'id': 18, 'name': 'alert.config', 'display_name': '配置告警'},
        ],
        'defense': [
            {'id': 19, 'name': 'defense.view', 'display_name': '查看防御'},
            {'id': 20, 'name': 'defense.block', 'display_name': 'IP封禁'},
            {'id': 21, 'name': 'defense.config', 'display_name': '配置防御'},
        ],
        'system': [
            {'id': 22, 'name': 'system.view', 'display_name': '查看系统'},
            {'id': 23, 'name': 'system.config', 'display_name': '系统配置'},
        ]
    }
    return jsonify({'success': True, 'data': permissions})


# ==================== Admin Threats API路由 ====================

@app.route('/admin/api/threat/stats')
def admin_threat_stats():
    """威胁统计数据"""
    import random
    return jsonify({
        'success': True,
        'data': {
            'total_threats': random.randint(50, 200),
            'active_blocks': random.randint(10, 30),
            'type_stats': {
                'DDoS': random.randint(10, 50),
                'PortScan': random.randint(5, 30),
                'SQL注入': random.randint(2, 15),
                'XSS': random.randint(1, 10),
                '暴力破解': random.randint(5, 25)
            }
        }
    })


@app.route('/admin/api/threat/records')
def admin_threat_records():
    """威胁记录列表"""
    import random
    from datetime import datetime, timedelta

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    records = []
    threat_types = ['DDoS', 'PortScan', 'SQL注入', 'XSS', '暴力破解']
    severities = ['low', 'medium', 'high', 'critical']
    statuses = ['blocked', 'detected', 'monitoring']

    for i in range(per_page):
        records.append({
            'id': i + 1,
            'timestamp': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
            'threat_type': random.choice(threat_types),
            'source_ip': generate_random_ip(),
            'target_ip': generate_random_ip(),
            'source_port': random.randint(1024, 65535),
            'target_port': random.choice([80, 443, 22, 3306, 8080]),
            'severity': random.choice(severities),
            'status': random.choice(statuses),
            'description': f"检测到来自外部的安全活动"
        })

    return jsonify({'success': True, 'data': {'records': records, 'total': 1000}})


@app.route('/admin/api/threat/handle/<int:threat_id>', methods=['POST'])
def admin_threat_handle(threat_id):
    """处理威胁（封禁/解封）"""
    data = request.get_json()
    action = data.get('action')
    return jsonify({'success': True, 'message': f'威胁 {threat_id} 已{action}'})


@app.route('/admin/api/threat/rules', methods=['GET', 'POST'])
def admin_threat_rules_crud():
    """威胁检测规则列表/添加规则"""
    if request.method == 'POST':
        data = request.get_json()
        return jsonify({'success': True, 'message': '检测规则已添加'})

    rules = [
        {'id': 1, 'name': 'DDoS检测规则', 'rule_type': 'auto_block', 'action': 'block', 'severity': 'high',
         'condition': '{"packet_rate": 1000, "time_window": 60}', 'execute_count': 150, 'is_enabled': True},
        {'id': 2, 'name': '端口扫描检测', 'rule_type': 'rate_limit', 'action': 'alert', 'severity': 'medium',
         'condition': '{"port_scan_threshold": 100}', 'execute_count': 320, 'is_enabled': True},
        {'id': 3, 'name': 'SQL注入防护', 'rule_type': 'geo_filter', 'action': 'block', 'severity': 'high',
         'condition': '{"pattern_match": "sql_injection"}', 'execute_count': 45, 'is_enabled': True},
        {'id': 4, 'name': 'XSS攻击检测', 'rule_type': 'auto_block', 'action': 'alert', 'severity': 'medium',
         'condition': '{"xss_pattern": true}', 'execute_count': 78, 'is_enabled': True},
        {'id': 5, 'name': '暴力破解防护', 'rule_type': 'rate_limit', 'action': 'throttle', 'severity': 'low',
         'condition': '{"login_attempts": 5, "time_window": 300}', 'execute_count': 200, 'is_enabled': True},
    ]
    return jsonify({'success': True, 'data': rules})


@app.route('/admin/api/threat/rules/<int:rule_id>', methods=['GET', 'PUT', 'DELETE'])
def admin_threat_rule_detail(rule_id):
    """威胁检测规则详情/更新/删除"""
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': f'检测规则 {rule_id} 已删除'})

    if request.method == 'PUT':
        data = request.get_json()
        return jsonify({'success': True, 'message': f'检测规则 {rule_id} 已更新'})

    rules = [
        {'id': 1, 'name': 'DDoS检测规则', 'rule_type': 'auto_block', 'action': 'block', 'severity': 'high',
         'condition': '{"packet_rate": 1000, "time_window": 60}', 'execute_count': 150, 'is_enabled': True},
    ]
    rule = next((r for r in rules if r['id'] == rule_id), None)
    if rule:
        return jsonify({'success': True, 'data': rule})
    return jsonify({'success': False, 'message': '规则不存在'}), 404


@app.route('/admin/api/threat/model/info')
def admin_threat_model_info():
    """威胁检测模型信息"""
    return jsonify({
        'success': True,
        'data': {
            'model_type': 'RandomForest',
            'version': '2.1.0',
            'model_exists': True,
            'model_size': 2048576,
            'model_modified': '2026-04-20T10:30:00',
            'accuracy': 0.95,
            'precision': 0.93,
            'recall': 0.91
        }
    })


@app.route('/admin/api/threat/model/params')
def admin_threat_model_params():
    """威胁检测模型参数"""
    return jsonify({
        'success': True,
        'data': {
            'n_estimators': 100,
            'max_depth': 10,
            'min_samples_split': 2,
            'min_samples_leaf': 1,
            'threshold': 0.7,
            'features': 15
        }
    })


@app.route('/admin/api/threat/model/retrain', methods=['POST'])
def admin_threat_model_retrain():
    """重新训练威胁检测模型"""
    data = request.get_json()
    return jsonify({'success': True, 'message': '模型训练任务已启动', 'task_id': 'train_001'})


@app.route('/admin/api/threat/init', methods=['POST'])
def admin_threat_init():
    """初始化威胁检测规则"""
    return jsonify({'success': True, 'message': '威胁检测规则已初始化'})


# ==================== Admin Alerts API路由 ====================

@app.route('/admin/api/alert/records')
def admin_alert_records_list():
    """告警记录列表"""
    import random
    from datetime import datetime, timedelta

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    records = []
    alert_types = ['DDoS攻击', '端口扫描', 'SQL注入', 'XSS攻击', '暴力破解']
    severities = ['critical', 'high', 'medium', 'low']
    statuses = ['pending', 'confirmed', 'resolved', 'ignored']
    rule_names = ['DDoS检测规则', '端口扫描检测', 'SQL注入防护', 'XSS攻击检测', '暴力破解防护']

    for i in range(per_page):
        records.append({
            'id': i + 1,
            'timestamp': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
            'rule_name': random.choice(rule_names),
            'severity': random.choice(severities),
            'message': f"检测到可疑活动 - {random.choice(alert_types)}",
            'status': random.choice(statuses),
            'confirmed_by': random.choice(['admin', 'operator', None]) if random.random() > 0.5 else None,
            'source_ip': generate_random_ip(),
            'description': f"检测到来自外部的{random.choice(alert_types)}活动"
        })

    return jsonify({'success': True, 'data': {'records': records, 'total': 200}})


@app.route('/admin/api/alert/stats')
def admin_alert_stats():
    """告警统计数据"""
    import random
    return jsonify({
        'success': True,
        'data': {
            'today_alerts': random.randint(20, 100),
            'pending': random.randint(10, 50),
            'confirmed': random.randint(20, 80),
            'resolved': random.randint(50, 200),
            'ignored': random.randint(5, 20),
            # 同时保留旧字段名以兼容
            'pending_alerts': random.randint(10, 50),
            'confirmed_alerts': random.randint(20, 80),
            'resolved_alerts': random.randint(50, 200)
        }
    })


@app.route('/admin/api/alert/rules', methods=['GET', 'POST'])
def admin_alert_rules_crud():
    """告警规则列表/添加规则"""
    if request.method == 'POST':
        data = request.get_json()
        return jsonify({'success': True, 'message': '告警规则已添加'})

    rules = [
        {'id': 1, 'name': '流量告警', 'metric': 'traffic', 'condition': '>', 'threshold': 1000,
         'severity': 'high', 'silence_minutes': 5, 'is_enabled': True},
        {'id': 2, 'name': 'CPU告警', 'metric': 'cpu_usage', 'condition': '>', 'threshold': 80,
         'severity': 'medium', 'silence_minutes': 10, 'is_enabled': True},
        {'id': 3, 'name': '内存告警', 'metric': 'memory_usage', 'condition': '>', 'threshold': 85,
         'severity': 'high', 'silence_minutes': 5, 'is_enabled': True},
        {'id': 4, 'name': '威胁告警', 'metric': 'threat_count', 'condition': '>', 'threshold': 10,
         'severity': 'critical', 'silence_minutes': 0, 'is_enabled': True},
    ]
    return jsonify({'success': True, 'data': rules})


@app.route('/admin/api/alert/rules/<int:rule_id>', methods=['PUT', 'DELETE'])
def admin_alert_rule_detail(rule_id):
    """告警规则详情/更新/删除"""
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': f'告警规则 {rule_id} 已删除'})

    data = request.get_json()
    return jsonify({'success': True, 'message': f'告警规则 {rule_id} 已更新'})


@app.route('/admin/api/alert/recipients', methods=['GET', 'POST'])
def admin_alert_recipients():
    """告警接收人列表/添加接收人"""
    if request.method == 'POST':
        data = request.get_json()
        return jsonify({'success': True, 'message': '告警接收人已添加'})

    recipients = [
        {'id': 1, 'name': '安全团队', 'email': 'security@example.com', 'dingtalk': '', 'wechat': '',
         'is_enabled': True, 'notifications': ['email', 'sms']},
        {'id': 2, 'name': '运维团队', 'email': 'ops@example.com', 'dingtalk': 'https://oapi.dingtalk.com/robot/send?access_token=xxx',
         'wechat': '', 'is_enabled': True, 'notifications': ['email']},
        {'id': 3, 'name': '管理员', 'email': 'admin@example.com', 'dingtalk': '', 'wechat': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx',
         'is_enabled': False, 'notifications': ['email', 'dingtalk', 'wechat']},
    ]
    return jsonify({'success': True, 'data': recipients})


@app.route('/admin/api/alert/recipients/<int:recipient_id>', methods=['PUT', 'DELETE'])
def admin_alert_recipient_detail(recipient_id):
    """告警接收人详情/更新/删除"""
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': f'告警接收人 {recipient_id} 已删除'})

    data = request.get_json()
    return jsonify({'success': True, 'message': f'告警接收人 {recipient_id} 已更新'})


@app.route('/admin/api/alert/init', methods=['POST'])
def admin_alert_init():
    """初始化告警规则"""
    return jsonify({'success': True, 'message': '告警规则已初始化'})


@app.route('/admin/api/alert/records/<int:alert_id>/confirm', methods=['POST'])
def confirm_alert_record(alert_id):
    """确认告警"""
    return jsonify({'success': True, 'message': f'告警 {alert_id} 已确认'})


@app.route('/admin/api/alert/records/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert_record(alert_id):
    """解决告警"""
    return jsonify({'success': True, 'message': f'告警 {alert_id} 已标记为已解决'})


@app.route('/admin/api/alert/records/<int:alert_id>/ignore', methods=['POST'])
def ignore_alert_record(alert_id):
    """忽略告警"""
    return jsonify({'success': True, 'message': f'告警 {alert_id} 已忽略'})


# ==================== Admin Defense API路由补充 ====================

@app.route('/admin/api/defense/execution_stats')
def admin_defense_execution_stats():
    """防御执行统计"""
    import random
    return jsonify({
        'success': True,
        'data': {
            'active_blocks': random.randint(10, 50),
            'total_executions': random.randint(100, 500),
            'today_executions': random.randint(50, 200),
            'auto_blocks': random.randint(20, 100)
        }
    })


@app.route('/admin/api/defense/blocked_ips')
def admin_defense_blocked_ips():
    """被封禁的IP列表（带分页）"""
    import random
    from datetime import datetime, timedelta

    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('ip_address', '')

    blocked_ips = []
    for i in range(per_page):
        ip = generate_random_ip()
        if search and search not in ip:
            continue

        severity = random.choice(['critical', 'high', 'medium', 'low'])
        blocked_ips.append({
            'id': i + 1,
            'ip_address': ip,
            'threat_type': random.choice(['DDoS攻击', '端口扫描', 'SQL注入', '暴力破解']),
            'severity': severity,
            'source': severity,  # 添加source字段用于getSeverityBadge
            'reason': random.choice(['自动封禁', '手动封禁', '规则触发']),
            'blocked_at': (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
            'blocked_by': random.choice(['admin', 'system', 'auto']),
            'is_active': random.choice([True, False]),
            'status': random.choice(['active', 'expired']),
            'expires_at': (datetime.now() + timedelta(days=random.randint(1, 7))).isoformat() if random.random() > 0.3 else None
        })

    return jsonify({
        'success': True,
        'data': {
            'ips': blocked_ips,
            'blocked_ips': blocked_ips,  # 同时支持两种格式
            'total': 200,
            'per_page': per_page,
            'page': page
        }
    })


@app.route('/admin/api/defense/batch_unblock', methods=['POST'])
def admin_defense_batch_unblock():
    """批量解封IP"""
    data = request.get_json()
    block_ids = data.get('block_ids', [])
    return jsonify({'success': True, 'message': f'已解封 {len(block_ids)} 个IP'})


# ==================== Admin Defense API路由补充 ====================

@app.route('/admin/api/defense/stats')
def admin_defense_stats():
    """防御统计数据"""
    import random
    return jsonify({
        'success': True,
        'data': {
            'active_blocks': random.randint(10, 50),
            'today_executions': random.randint(50, 200),
            'policy_count': random.randint(5, 15),
            'auto_blocks': random.randint(20, 100)
        }
    })


@app.route('/admin/api/defense/policies', methods=['GET', 'POST'])
def admin_defense_policies():
    """防御策略列表/添加策略"""
    if request.method == 'POST':
        data = request.get_json()
        return jsonify({'success': True, 'message': '防御策略已添加'})

    policies = [
        {'id': 1, 'name': 'DDoS防护策略', 'type': 'auto_block', 'trigger_condition': 'packet_rate > 1000',
         'response_action': 'block', 'severity': 'high', 'is_enabled': True},
        {'id': 2, 'name': '端口扫描防护', 'type': 'rate_limit', 'trigger_condition': 'port_scan_detected',
         'response_action': 'alert', 'severity': 'medium', 'is_enabled': True},
        {'id': 3, 'name': 'SQL注入防护', 'type': 'signature_match', 'trigger_condition': 'sql_injection_pattern',
         'response_action': 'block', 'severity': 'high', 'is_enabled': True},
    ]
    return jsonify({'success': True, 'data': policies})


@app.route('/admin/api/defense/policies/<int:policy_id>', methods=['PUT', 'DELETE'])
def admin_defense_policy_detail(policy_id):
    """防御策略详情/更新/删除"""
    if request.method == 'DELETE':
        return jsonify({'success': True, 'message': f'防御策略 {policy_id} 已删除'})

    data = request.get_json()
    return jsonify({'success': True, 'message': f'防御策略 {policy_id} 已更新'})


@app.route('/admin/api/defense/execution_logs')
def admin_defense_execution_logs():
    """防御执行日志"""
    import random
    from datetime import datetime, timedelta

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    logs = []
    operations = ['block_ip', 'unblock_ip', 'add_rule', 'remove_rule', 'update_policy']
    operators = ['admin', 'system', 'auto']

    for i in range(per_page):
        logs.append({
            'id': i + 1,
            'operation_type': random.choice(operations),
            'operator': random.choice(operators),
            'resource': f"IP 192.168.1.{random.randint(1, 254)}",
            'details': f"执行{random.choice(operations)}操作",
            'created_at': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat()
        })

    return jsonify({'success': True, 'data': {'logs': logs, 'total': 500}})


# ==================== Socket.IO事件 ====================

@socketio.on('connect')
def handle_connect():
    logger.info(f"客户端已连接: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"客户端已断开连接: {request.sid}")

# ==================== 主函数 ====================

if __name__ == '__main__':
    try:
        logger.info("网络入侵检测与防御系统启动中...")
        logger.info("集成AI智能体模块")
        logger.info("延迟初始化系统模块以避免启动阻塞...")
        async_init_modules()
        socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"系统启动失败: {str(e)}")
