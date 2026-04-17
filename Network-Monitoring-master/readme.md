## 📋 项目简介
这是一个基于 Flask 的 Web 应用系统，集成了网络入侵检测与防御功能。系统能够实时监控网络流量，检测异常行为，并通过机器学习模型识别潜在威胁。

## 🏗️ 项目结构

```
app/
├── app.py                      # 主程序入口
├── app2.py                     # 增强版主程序（集成异常检测）
├── data/                       # 数据存储目录
│   ├── alerts/                 # 告警数据
│   ├── flow_features/          # 流量特征数据
│   ├── monitoring/             # 监控数据
│   ├── pcap/                   # PCAP包文件
│   ├── threats/                # 威胁数据
│   └── traffic/                # 流量数据
├── model/                      # 机器学习模型
│   └── train/                  # 训练相关文件
│       ├── preprocessing_pipeline.pkl    # 预处理流水线
│       └── randomforest_model.pkl        # 随机森林模型
├── modules/                    # 核心功能模块
│   ├── alert_response/         # 告警响应模块
│   │   └── alerter.py         # 告警系统
│   ├── intrusion_prevention/   # 入侵防御模块
│   │   └── prevention.py      # 防御系统
│   ├── network_monitoring/     # 网络监控模块
│   │   └── monitor.py         # 监控系统
│   ├── pocket_detection/       # 异常检测模块
│   │   └── detector.py        # 数据包检测
│   ├── threat_find/           # 威胁发现模块
│   │   └── ThreatFind.py      # 威胁识别
│   └── traffic_detection/      # 流量检测模块
│       ├── __init__.py
│       └── detector.py        # 流量检测器
├── static/                     # 静态资源
│   ├── css/                    # 样式文件
│   └── js/                     # JavaScript文件
├── templates/                   # HTML模板
│   ├── dashboard.html          # 仪表盘页面
│   ├── index.html              # 主页
│   ├── intrusion_detection.html # 入侵检测页面
│   ├── logs.html               # 日志页面
│   ├── network_monitor.html    # 网络监控页面
│   └── settings.html           # 设置页面
├── main.py                      # 模型训练脚本
└── mergeData.py                 # 数据合并脚本
```

## ✨ 功能特点

### 🔍 网络监控
- 实时捕获网络数据包
- 协议统计分析（TCP/UDP/ICMP/HTTP等）
- 数据包详情解析（类似Wireshark的协议分层）
- 流量可视化图表

### 🎯 入侵检测
- 基于机器学习的威胁识别（随机森林模型）
- 支持PCAP文件分析
- 实时流量特征提取
- 多类型威胁检测（DDoS、端口扫描、暴力破解等）

### 🛡️ 防御机制
- 自动/手动IP阻止
- 威胁等级评估
- 攻击类型统计
- 防御规则可配置

### ⚠️ 告警系统
- Web界面实时通知
- 告警分级（高/中/低）
- 告警历史查询
- 支持邮件通知（可配置）

## 🚀 快速开始

### 环境要求
- Python 3.7+
- Flask
- 其他依赖见 `requirements.txt`

### 安装步骤
1. **克隆项目**
   ```bash
   git clone [你的仓库地址]
   cd [项目目录]
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **启动系统**
   ```bash
   # 基础版本
   python app.py
   
   # 增强版本（包含异常检测）
   python app2.py
   ```

4. **访问系统**
   打开浏览器访问 `http://127.0.0.1:8080`

## 📖 使用指南

### 主页功能
- 查看系统运行状态
- 启动/停止系统
- 快速访问各功能模块
- 健康状态检查

### 仪表盘
- 实时流量监控
- 协议分布统计
- 威胁检测统计
- 活跃IP列表

### 网络监控
- 实时数据包捕获
- 协议分析视图
- 十六进制数据查看
- 数据包筛选

### 入侵检测
- PCAP文件上传分析
- CSV特征文件分析
- 流量特征展示
- 威胁识别结果

### 日志与设置
- 查看系统日志
- 配置检测参数
- 设置防御规则
- 告警配置

## 🤖 机器学习模型

系统使用随机森林分类器进行威胁检测：

### 模型特征
- 数据包统计特征
- 流量时序特征
- 协议相关特征
- 连接状态特征

### 支持的威胁类型
| 威胁类型 | 严重等级 | 说明 |
|---------|---------|------|
| DDoS攻击 | 高 | 分布式拒绝服务 |
| 端口扫描 | 中 | 探测开放端口 |
| SQL注入 | 高 | 数据库攻击 |
| XSS攻击 | 中 | 跨站脚本攻击 |
| 暴力破解 | 中 | FTP/SSH暴力破解 |
| 僵尸网络 | 高 | Bot网络活动 |
| Heartbleed | 高 | OpenSSL漏洞利用 |

## ⚙️ 配置文件说明

### 系统配置 (`settings.html`)
- **网络接口**：选择监控的网卡
- **检测模式**：被动/主动/学习
- **防御模式**：监控/自动/严格
- **告警设置**：邮件通知、告警级别

### 模型训练 (`main.py`)
- 数据预处理流水线
- PCA降维
- SMOTE过采样
- 网格搜索参数优化

## 📊 数据存储

系统自动在 `data/` 目录下生成以下数据：
- `alerts/` - 告警记录
- `flow_features/` - 流量特征
- `monitoring/` - 监控数据
- `pcap/` - 原始数据包
- `threats/` - 威胁记录
- `traffic/` - 流量统计

## 🔧 常见问题

### Q: 系统无法启动？
A: 检查端口8080是否被占用，或修改 `app.py` 中的端口号。

### Q: 异常检测模块不可用？
A: 确保 `model/train/` 目录下有训练好的模型文件（.pkl）。

### Q: 如何添加新的检测规则？
A: 在 `modules/threat_find/ThreatFind.py` 中扩展威胁映射表。

## 📝 待办事项

- [ ] 添加更多机器学习模型支持
- [ ] 实现实时告警推送
- [ ] 优化数据包处理性能
- [ ] 添加用户认证系统
- [ ] 支持分布式部署