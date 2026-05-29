@echo off
chcp 65001 >nul
cls
echo ====================================
echo  网络入侵检测与防御系统
echo  版本: AI集成版
echo ====================================
echo.
echo [√] 所有依赖已安装完成
echo.
echo 即将启动服务...
echo 服务地址: http://127.0.0.1:8080
echo.
echo 按 Ctrl+C 停止服务器
echo ====================================
echo.

python app_ai_integrated.py

pause
