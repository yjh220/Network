"""
一键打包脚本 - 将Flask应用打包成Windows可执行文件
使用方法: python build_exe.py
"""

import os
import sys
import shutil
from PyInstaller.__main__ import run

# 项目配置
APP_NAME = "网络入侵检测与防御系统"
MAIN_SCRIPT = "app_ai_integrated.py"  # AI智能体集成版本
VERSION = "1.0.0"

# PyInstaller配置参数
PYINSTALLER_OPTS = [
    MAIN_SCRIPT,
    '--name=%s' % 'NetworkMonitor',  # 可执行文件名
    '--onefile',                      # 打包成单个EXE
    '--console',                     # 显示控制台（便于调试）
    '--icon=NONE',                    # 图标文件（如无则省略）
    '--add-data=templates;templates', # 添加模板文件夹
    '--add-data=static;static',       # 添加静态资源文件夹
    '--add-data=model;model',         # 添加模型文件夹
    '--hidden-import=flask_socketio',
    '--hidden-import=socketio',
    '--hidden-import=eventlet',
    '--hidden-import=eventlet.wsgi',
    '--hidden-import=eventlet.greenlet',
    '--hidden-import=scapy.all',
    '--clean',                        # 清理临时文件
    '--noconfirm',                    # 不询问确认
]

def check_environment():
    """检查运行环境"""
    print("=" * 60)
    print("检查打包环境...")
    print("=" * 60)

    # 检查Python版本
    if sys.version_info < (3, 7):
        print("❌ 错误：需要Python 3.7或更高版本")
        return False
    print(f"✅ Python版本: {sys.version}")

    # 检查PyInstaller
    try:
        import PyInstaller
        print(f"✅ PyInstaller已安装: {PyInstaller.__version__}")
    except ImportError:
        print("⚠️  PyInstaller未安装，正在安装...")
        os.system("pip install pyinstaller")
        print("✅ PyInstaller安装完成")

    # 检查项目文件
    required_files = [
        MAIN_SCRIPT,
        'requirements.txt',
        'templates',
        'static',
        'modules'
    ]

    for file in required_files:
        if not os.path.exists(file):
            print(f"❌ 错误：缺少必要文件/目录 {file}")
            return False
    print(f"✅ 项目文件检查通过")

    return True

def build_exe():
    """执行打包"""
    print("\n" + "=" * 60)
    print("开始打包应用...")
    print("=" * 60)

    try:
        run(PYINSTALLER_OPTS)
        print("\n✅ 打包成功！")
        return True
    except Exception as e:
        print(f"\n❌ 打包失败：{str(e)}")
        return False

def create_release_package():
    """创建发布包"""
    print("\n" + "=" * 60)
    print("创建发布包...")
    print("=" * 60)

    release_dir = "Release"
    dist_dir = "dist"

    if not os.path.exists(dist_dir):
        print(f"❌ 错误：找不到 {dist_dir} 目录")
        return False

    # 创建发布目录
    if os.path.exists(release_dir):
        shutil.rmtree(release_dir)
    os.makedirs(release_dir)

    # 复制可执行文件
    exe_name = "NetworkMonitor.exe"
    src_exe = os.path.join(dist_dir, exe_name)
    if os.path.exists(src_exe):
        shutil.copy(src_exe, release_dir)
        print(f"✅ 复制 {exe_name}")
    else:
        print(f"⚠️  警告：找不到 {exe_name}")

    # 复制必要文件
    files_to_copy = [
        ('项目说明文档.md', '项目说明文档.md'),
        ('系统运行教程.md', '系统运行教程.md'),
        ('requirements.txt', 'requirements.txt'),
        ('使用说明.txt', '使用说明.txt'),
    ]

    for src, dst in files_to_copy:
        if os.path.exists(src):
            shutil.copy(src, os.path.join(release_dir, dst))
            print(f"✅ 复制 {dst}")
        else:
            print(f"⚠️  警告：找不到 {src}")

    # 复制model目录（如果单独打包没包含）
    if os.path.exists('model'):
        shutil.copytree('model', os.path.join(release_dir, 'model'), dirs_exist_ok=True)
        print(f"✅ 复制 model/")

    # 创建启动脚本
    start_bat = """@echo off
chcp 65001 >nul
title 网络入侵检测与防御系统
echo ========================================
echo   网络入侵检测与防御系统 v1.0
echo ========================================
echo.
echo 正在启动系统...
echo.

NetworkMonitor.exe

pause
"""
    with open(os.path.join(release_dir, '启动系统.bat'), 'w', encoding='utf-8') as f:
        f.write(start_bat)
    print("✅ 创建 启动系统.bat")

    print(f"\n✅ 发布包创建完成！")
    print(f"📁 发布目录: {os.path.abspath(release_dir)}")
    return True

def create_readme():
    """创建使用说明文件"""
    content = """===============================================
  网络入侵检测与防御系统 - 快速使用说明
===============================================

一、首次运行
1. 双击 "启动系统.bat" 启动系统
2. 等待控制台显示 "系统已启动！"
3. 打开浏览器访问: http://127.0.0.1:8080
4. 使用默认账户登录:
   - 用户名: admin
   - 密码: admin123

二、主要功能
- 态势仪表板: 实时网络安全态势
- 网络监控: 数据包捕获与分析
- 入侵检测: AI驱动的威胁识别
- 日志管理: 系统日志与告警记录
- 后台管理: 用户与策略管理

三、停止系统
1. 在命令行窗口按 Ctrl+C
2. 等待系统停止
3. 关闭窗口

四、常见问题
- 如果端口被占用，请关闭占用8080端口的程序
- Windows用户需要安装WinPcap或Npcap
- 详细问题请查看《系统运行教程.md》

五、技术支持
- 项目名称: 网络入侵检测与防御系统
- 版本: v1.0.0
- 开发语言: Python
"""

    with open('使用说明.txt', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ 创建 使用说明.txt")

def main():
    """主函数"""
    print("\n" + "=" * 60)
    print(f"  {APP_NAME} - 打包工具")
    print(f"  版本: {VERSION}")
    print("=" * 60)

    # 检查环境
    if not check_environment():
        input("\n按回车键退出...")
        return

    # 创建使用说明
    create_readme()

    # 执行打包
    if build_exe():
        # 创建发布包
        create_release_package()

        print("\n" + "=" * 60)
        print("🎉 打包完成！")
        print("=" * 60)
        print("\n📦 发布内容:")
        print(f"  - 可执行文件: Release/NetworkMonitor.exe")
        print(f"  - 启动脚本: Release/启动系统.bat")
        print(f"  - 说明文档: Release/*.md")
        print("\n💡 提示:")
        print(f"  1. 将 Release/ 文件夹压缩成ZIP即可提交")
        print(f"  2. 解压后双击 '启动系统.bat' 即可运行")
        print(f"  3. 无需安装Python环境")
    else:
        print("\n❌ 打包失败，请检查错误信息")

    input("\n按回车键退出...")

if __name__ == '__main__':
    main()
