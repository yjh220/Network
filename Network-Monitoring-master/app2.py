#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import threading
import logging
import sys
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

# 导入自定义模块 - 原有模块
from modules.traffic_detection.detector import TrafficDetector
from modules.intrusion_prevention.prevention import IntrusionPrevention
from modules.alert_response.alerter import AlertSystem
from modules.network_monitoring.monitor import NetworkMonitor

# 导入自定义模块 - 新增异常检测模块
from modules.pocket_detection.detector import TrafficDetector as PocketDetector
from modules.threat_find.ThreatFind import ThreatFind

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
socketio = SocketIO(app, cors_allowed_origins="*")

# 创建数据目录
os.makedirs('data', exist_ok=True)

# 初始化系统模块
# 原有模块
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


# 路由定义
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/logs')
def logs():
    return render_template('logs.html')


@app.route('/settings')
def settings():
    return render_template('settings.html')


# 新增路由 - 实时监控和威胁检测页面
@app.route('/network_monitor')
def network_monitor_page():
    return render_template('network_monitor.html')


@app.route('/intrusion_detection')
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


# API路由 - 新增异常检测功能
@app.route('/api/protocol_stats')
def get_protocol_stats():
    try:
        if not threat_detection_available:
            return jsonify({'error': '异常检测模块不可用'})
        return jsonify(pocket_detector.get_traffic_stats())
    except Exception as e:
        logger.error(f"获取协议统计失败: {str(e)}")
        return jsonify({'error': str(e)})


@app.route('/api/packets')
def get_packets():
    try:
        if not threat_detection_available:
            return jsonify({'error': '异常检测模块不可用'})
        limit = request.args.get('limit', 1000, type=int)
        return jsonify(pocket_detector.get_recent_traffic(limit))
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

        print("=" * 50)
        print("系统已启动！")
        print("访问地址: http://127.0.0.1:8080")
        print("可用页面:")
        print("  - 主界面: /")
        print("  - 仪表板: /dashboard")
        print("  - 网络监控: /network_monitor")
        print("  - 入侵检测: /intrusion_detection")
        print("  - 日志: /logs")
        print("  - 设置: /settings")
        print("=" * 50)

        socketio.run(app,
                     host='127.0.0.1',
                     port=8080,
                     debug=True,
                     allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"系统启动失败: {str(e)}")
        print(f"系统启动失败: {str(e)}")