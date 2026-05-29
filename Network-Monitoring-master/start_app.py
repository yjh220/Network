#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速启动脚本 - 网络入侵检测系统
"""
print("正在启动网络入侵检测与防御系统...")

import os
import sys
import time

# 确保在正确的目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

try:
    from app_ai_integrated import app, socketio, logger
    logger.info("系统启动成功！")
    print("=" * 60)
    print("🌐 网络入侵检测与防御系统")
    print("=" * 60)
    print(f"✅ 主页面: http://localhost:8080")
    print(f"✅ 仪表盘: http://localhost:8080/home")
    print(f"✅ SDN控制台: http://localhost:8080/admin/intent")
    print(f"✅ 入侵检测: http://localhost:8080/intrusion_detection")
    print(f"✅ 蜜罐系统: http://localhost:8080/honeypot")
    print("=" * 60)
    print("系统正在运行，按 Ctrl+C 停止...")
    print()

    socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)

except KeyboardInterrupt:
    print("\n系统已停止")
except Exception as e:
    print(f"启动失败: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
