# AI智能体集成指南

## 概述

本指南说明如何将从FullScopeTest项目借鉴的AI智能体集成到Network-Monitoring网络监控系统中。

## 集成内容

### 从FullScopeTest借鉴的AI组件

| FullScopeTest组件 | Network-Monitoring集成 | 功能说明 |
|---|---|---|
| AI Copilot | AI Security Copilot | 自然语言对话界面，用户可以用日常语言操作安全系统 |
| AI Planner | AI Detection Planner | 自然语言转检测计划，自动生成威胁检测方案 |
| AI Script Generator | AI Rule Generator | 自然语言生成检测规则 |
| AI Script Healer | AI Rule Healer | 自动分析和修复检测规则错误 |
| AI Data Synthesizer | AI Threat Synthesizer | 生成测试威胁场景 |

## 目录结构

```
Network-Monitoring-master/
├── modules/
│   └── ai_agents/          # AI智能体模块（新增）
│       ├── __init__.py     # 模块初始化
│       ├── config.py       # AI配置
│       ├── copilot.py      # AI对话助手
│       ├── planner.py      # AI检测计划
│       ├── rule_generator.py  # AI规则生成
│       ├── rule_healer.py  # AI规则修复
│       ├── threat_synthesizer.py  # AI威胁场景生成
│       └── api.py          # Flask API接口
├── templates/
│   ├── ai_copilot.html    # AI对话界面（新增）
│   ├── ai_planner.html    # AI计划界面（新增）
│   └── ai_rules.html      # AI规则界面（新增）
├── app_ai_integrated.py   # 集成AI的主程序（新增）
└── app.py                 # 原主程序（保留）
```

## 配置说明

### 环境变量配置

在启动应用前，设置以下环境变量：

```bash
# AI配置（可选，也可通过Web界面配置）
export AI_BASE_URL="https://api.deepseek.com/v1"
export AI_MODEL="deepseek-chat"
export AI_API_KEY="sk-your-api-key"
export AI_ENABLED="true"
```

### 配置文件

AI配置也可以通过Web界面动态配置：
- 访问 `/ai/copilot` 页面
- 在右侧配置面板中输入API信息
- 点击"保存配置"

## 使用指南

### 1. AI安全助手 (Copilot)

访问 `/ai/copilot` 页面，使用自然语言与系统交互：

**示例对话：**
```
用户: 帮我查看最近的威胁
AI: [调用get_recent_threats工具] 最近检测到3个威胁...

用户: 封锁IP 192.168.1.100
AI: [调用block_ip_address工具] 已成功封锁IP 192.168.1.100

用户: 生成今日安全报告
AI: [调用generate_detection_report工具] 正在生成今日安全报告...
```

### 2. AI检测计划 (Planner)

访问 `/ai/planner` 页面，生成检测计划：

**输入示例：**
```
创建一个检测计划来监控端口扫描攻击。
当检测到同一IP在一分钟内访问超过20个端口时，
发送高危告警并自动封锁该IP地址。
```

**输出：**
```json
{
  "summary": "生成端口扫描检测计划，包含检测规则、告警规则和响应动作",
  "operations": [
    {
      "type": "create_detection_rule",
      "name": "端口扫描检测",
      "threat_type": "端口扫描",
      "severity": "中",
      "conditions": {
        "port_threshold": 20,
        "time_window": 60
      }
    },
    {
      "type": "create_alert_rule",
      "name": "端口扫描告警",
      "severity": "高",
      "notification_method": "web"
    },
    {
      "type": "configure_response_action",
      "action": "block_ip",
      "duration": 3600
    }
  ]
}
```

### 3. AI规则生成 (Rule Generator)

访问 `/ai/rules` 页面，生成检测规则：

**生成检测规则：**
```
输入: 检测SSH暴力破解攻击，同一IP在一分钟内连接尝试超过10次
输出: 完整的检测规则JSON配置
```

**修复规则错误：**
```
输入:
  规则: {"threshold": "invalid"}
  错误: "threshold must be a number"

输出:
  诊断: "threshold字段类型错误"
  修复后: {"threshold": 10}
  说明: "将字符串'invalid'改为数字10"
```

## API接口

### 对话接口
```http
POST /api/ai/chat
Content-Type: application/json

{
  "message": "用户消息",
  "history": [...]
}
```

### 计划生成接口
```http
POST /api/ai/plan
Content-Type: application/json

{
  "prompt": "生成检测计划描述",
  "context": {...}
}
```

### 规则生成接口
```http
POST /api/ai/rules/generate
Content-Type: application/json

{
  "prompt": "规则描述",
  "rule_type": "detection|prevention|alert"
}
```

### 规则修复接口
```http
POST /api/ai/rules/fix
Content-Type: application/json

{
  "rule": {...},
  "error": "错误信息"
}
```

## 启动方式

### 使用集成AI的版本
```bash
cd Network-Monitoring-master
python app_ai_integrated.py
```

### 使用原版本（不含AI）
```bash
cd Network-Monitoring-master
python app.py
```

## 功能对比

| 功能 | 原系统 | 集成AI后 |
|---|---|---|
| 网络监控 | ✅ | ✅ |
| 威胁检测 | ✅ | ✅ |
| 规则配置 | 手动编写 | AI生成 |
| 告警响应 | 固定规则 | 自然语言控制 |
| 系统操作 | 点击菜单 | 对话交互 |
| 规则修复 | 手动调试 | AI自动修复 |

## 技术架构

### AI组件通信流程

```
用户输入 → AI Copilot → LLM API → Function Calling → 系统工具执行 → 返回结果
```

### Function Calling工具列表

| 工具名 | 功能 | 对应系统模块 |
|---|---|---|
| block_ip_address | 封锁IP | IntrusionPrevention |
| unblock_ip_address | 解封IP | IntrusionPrevention |
| get_network_stats | 获取统计 | NetworkMonitor |
| get_recent_threats | 获取威胁 | AlertSystem |
| analyze_pcap_file | 分析文件 | ThreatFind |
| get_alerts | 获取告警 | AlertSystem |
| set_monitoring_mode | 设置模式 | SystemConfig |
| get_system_status | 系统状态 | SystemStatus |
| generate_detection_report | 生成报告 | ReportGenerator |

## 扩展开发

### 添加新的AI工具

1. 在 `config.py` 中定义工具描述
2. 在 `copilot.py` 中注册工具处理器
3. 在 `api.py` 中连接实际系统函数

示例：
```python
# 1. 定义工具
{
    "type": "function",
    "function": {
        "name": "custom_tool",
        "description": "工具描述",
        "parameters": {...}
    }
}

# 2. 注册处理器
copilot.register_tool_handler('custom_tool', my_custom_function)

# 3. 实现函数
def my_custom_function(param1, param2):
    # 实现逻辑
    return {"status": "success", "result": ...}
```

## 常见问题

### Q: AI功能未启用？
A: 检查环境变量 `AI_ENABLED=true` 和 `AI_API_KEY` 配置。

### Q: LLM请求超时？
A: 检查网络连接，或增加 `AI_TIMEOUT` 配置值。

### Q: 工具调用失败？
A: 查看后端日志，确认系统模块已正确初始化。

## 致谢

本AI智能体模块借鉴自 [FullScopeTest](https://github.com/huangxuan) 项目，感谢原作者的开源贡献。

---

**版本:** 1.0.0
**更新日期:** 2025年
**集成项目:** Network-Monitoring + FullScopeTest AI Framework
