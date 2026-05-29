#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI Copilot - Network Security Assistant

Natural language interface for network security operations using Function Calling.
Users can interact with the system using plain language commands.

Example interactions:
- "帮我查看最近的威胁"
- "封锁IP 192.168.1.100"
- "生成今日的安全报告"
- "查看系统状态"
"""

import json
import logging
import requests
from typing import Dict, Any, List, Callable, Optional

from .config import get_ai_config, get_ai_tools

logger = logging.getLogger(__name__)


class AICopilot:
    """
    AI Copilot for network security monitoring.

    Provides natural language interface to the Network-Monitoring system
    using LLM function calling capabilities.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI Copilot.

        Args:
            config: Optional AI configuration (uses default if not provided)
        """
        self.config = config or get_ai_config()
        self.tools = get_ai_tools()
        self.tool_handlers: Dict[str, Callable] = {}

        # Register default tool handlers
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default tool handlers (can be overridden)."""
        from . import sdn_control

        self.tool_handlers = {
            # SDN控制工具
            'boost_network_speed': self._default_boost_speed,
            'limit_network_speed': self._default_limit_speed,
            'get_network_topology': self._default_get_topology,

            # 安全工具
            'block_ip_address': self._default_block_ip,
            'unblock_ip_address': self._default_unblock_ip,
            'get_network_stats': self._default_get_stats,
            'get_recent_threats': self._default_get_threats,
            'analyze_pcap_file': self._default_analyze_pcap,
            'get_alerts': self._default_get_alerts,
            'set_monitoring_mode': self._default_set_mode,
            'get_system_status': self._default_get_status,
            'generate_detection_report': self._default_generate_report,
        }

    def register_tool_handler(self, tool_name: str, handler: Callable):
        """
        Register a custom tool handler.

        Args:
            tool_name: Name of the tool
            handler: Function to handle the tool call
        """
        self.tool_handlers[tool_name] = handler
        logger.info(f"Registered handler for tool: {tool_name}")

    def chat(
        self,
        message: str,
        conversation_history: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Process a natural language message.

        Args:
            message: User's message
            conversation_history: Optional conversation history

        Returns:
            Response with AI reply and any tool calls performed
        """
        # 重新读取最新配置
        from .config import get_ai_config
        current_config = get_ai_config()

        if not current_config.get('AI_ENABLED', True):
            return {
                'success': False,
                'error': 'AI功能未启用',
                'reply': 'AI功能未启用，请检查配置。'
            }

        # 模拟模式 - 用于测试界面
        if current_config.get('AI_MOCK_MODE', False):
            return self._mock_response(message)

        api_key = current_config.get('AI_API_KEY', '').strip()
        if not api_key:
            return {
                'success': False,
                'error': 'AI_API_KEY未配置',
                'reply': '请先配置AI API密钥。在右侧配置面板输入你的DeepSeek API密钥（格式：sk-xxxxx）'
            }

        try:
            return self._process_with_llm(message, conversation_history or [], current_config)
        except Exception as e:
            logger.error(f"AI Copilot error: {e}")
            return {
                'success': False,
                'error': str(e),
                'reply': f'处理请求时出错: {str(e)}'
            }

    def _process_with_llm(
        self,
        message: str,
        history: List[Dict[str, str]],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process message using LLM with function calling.

        Args:
            message: User message
            history: Conversation history
            config: AI configuration

        Returns:
            AI response
        """
        base_url = config.get('AI_BASE_URL', '').rstrip('/')
        model = config.get('AI_MODEL', 'gpt-4o-mini')
        api_key = config.get('AI_API_KEY', '').strip()
        timeout = config.get('AI_TIMEOUT', 30)

        endpoint = f"{base_url}/chat/completions"

        # System prompt for network security assistant
        system_message = {
            "role": "system",
            "content": (
                "你是一个网络安全监控系统的AI助手，帮助用户管理网络安全威胁。"
                "你可以帮助用户：\n"
                "- 查看网络统计信息和威胁数据\n"
                "- 封锁或解封IP地址\n"
                "- 分析PCAP文件\n"
                "- 生成安全报告\n"
                "- 设置监控模式\n"
                "请使用中文回复。如果用户的请求可以通过调用工具来完成，请使用相应的工具。"
            )
        }

        # Build messages
        messages = [system_message]
        messages.extend(history)
        messages.append({"role": "user", "content": message})

        payload = {
            "model": model,
            "temperature": 0.3,
            "messages": messages,
            "tools": self.tools,
            "tool_choice": "auto"
        }

        # Make request
        resp = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=timeout
        )

        if resp.status_code >= 400:
            raise RuntimeError(f"LLM请求失败: HTTP {resp.status_code} {resp.text}")

        data = resp.json()
        response_message = data["choices"][0]["message"]

        # Check if LLM wants to call tools
        if response_message.get("tool_calls"):
            messages.append(response_message)

            # Execute all tool calls
            tool_results = []
            for tool_call in response_message["tool_calls"]:
                result = self._execute_tool_call(tool_call)
                tool_results.append(result)

                # Add tool result to messages
                messages.append({
                    "tool_call_id": tool_call["id"],
                    "role": "tool",
                    "name": tool_call["function"]["name"],
                    "content": json.dumps(result, ensure_ascii=False),
                })

            # Second request to get final response
            second_payload = {
                "model": model,
                "messages": messages,
            }

            second_resp = requests.post(
                endpoint,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json=second_payload,
                timeout=timeout
            )

            if second_resp.status_code >= 400:
                raise RuntimeError(f"LLM第二次请求失败: {second_resp.text}")

            final_message = second_resp.json()["choices"][0]["message"]

            return {
                'success': True,
                'reply': final_message.get("content", ""),
                'tool_calls': tool_results
            }

        # Direct response without tool calls
        return {
            'success': True,
            'reply': response_message.get("content", ""),
            'tool_calls': []
        }

    def _execute_tool_call(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool call from the LLM.

        Args:
            tool_call: Tool call from LLM response

        Returns:
            Tool execution result
        """
        function_name = tool_call.get("function", {}).get("name")
        try:
            arguments = json.loads(
                tool_call.get("function", {}).get("arguments", "{}")
            )
        except json.JSONDecodeError:
            arguments = {}

        logger.info(f"执行工具: {function_name} 参数: {arguments}")

        handler = self.tool_handlers.get(function_name)
        if handler:
            try:
                return handler(**arguments)
            except Exception as e:
                logger.error(f"工具执行错误 {function_name}: {e}")
                return {
                    "status": "error",
                    "message": f"执行工具时出错: {str(e)}"
                }

        return {
            "status": "error",
            "message": f"未知工具: {function_name}"
        }

    # Default tool handlers (can be overridden by the main application)

    def _default_block_ip(self, ip_address: str, reason: str = "") -> Dict[str, Any]:
        """Default handler for blocking IP (override in actual app)."""
        return {
            "status": "success",
            "message": f"已封锁IP地址: {ip_address}。原因: {reason}",
            "ip_address": ip_address
        }

    def _default_unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Default handler for unblocking IP (override in actual app)."""
        return {
            "status": "success",
            "message": f"已解封IP地址: {ip_address}",
            "ip_address": ip_address
        }

    def _default_get_stats(self, timeframe: str = "hour") -> Dict[str, Any]:
        """Default handler for getting stats (override in actual app)."""
        return {
            "status": "success",
            "message": f"获取网络统计信息 ({timeframe})",
            "timeframe": timeframe
        }

    def _default_get_threats(
        self,
        limit: int = 10,
        severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """Default handler for getting threats (override in actual app)."""
        return {
            "status": "success",
            "message": f"获取最近 {limit} 条威胁记录",
            "threats": []
        }

    def _default_analyze_pcap(self, filename: str) -> Dict[str, Any]:
        """Default handler for analyzing PCAP (override in actual app)."""
        return {
            "status": "success",
            "message": f"分析PCAP文件: {filename}",
            "filename": filename
        }

    def _default_get_alerts(
        self,
        limit: int = 20,
        severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """Default handler for getting alerts (override in actual app)."""
        return {
            "status": "success",
            "message": f"获取最近 {limit} 条告警",
            "alerts": []
        }

    def _default_set_mode(self, mode: str) -> Dict[str, Any]:
        """Default handler for setting mode (override in actual app)."""
        mode_names = {
            "passive": "被动监控",
            "active": "主动防御",
            "learning": "学习模式"
        }
        return {
            "status": "success",
            "message": f"监控模式已设置为: {mode_names.get(mode, mode)}",
            "mode": mode
        }

    def _default_get_status(self) -> Dict[str, Any]:
        """Default handler for getting status (override in actual app)."""
        return {
            "status": "success",
            "message": "系统运行正常",
            "system_status": {
                "is_running": True,
                "processed_packets": 0,
                "detected_threats": 0,
                "blocked_attacks": 0
            }
        }

    def _default_generate_report(self, timeframe: str = "day") -> Dict[str, Any]:
        """Default handler for generating report (override in actual app)."""
        return {
            "status": "success",
            "message": f"生成 {timeframe} 安全报告",
            "timeframe": timeframe
        }

    # ============ SDN控制工具处理函数 ============

    def _default_boost_speed(self, target: str = "all") -> Dict[str, Any]:
        """提高网速"""
        from . import sdn_control

        result = sdn_control.apply_qos_policy(bandwidth_mbps=None, action="boost")

        if result.get("success"):
            return {
                "status": "success",
                "message": f"已提高网速，网络性能已优化",
                "target": target,
                "details": result.get("details", {})
            }
        else:
            return {
                "status": "error",
                "message": result.get("message", "提速失败")
            }

    def _default_limit_speed(self, bandwidth_mbps: float = 0.5, target_ip: str = None) -> Dict[str, Any]:
        """限制网速"""
        from . import sdn_control

        result = sdn_control.apply_qos_policy(
            bandwidth_mbps=bandwidth_mbps,
            action="limit"
        )

        if result.get("success"):
            return {
                "status": "success",
                "message": f"已限制网速为 {bandwidth_mbps} Mbps",
                "target_ip": target_ip,
                "details": result.get("details", {})
            }
        else:
            return {
                "status": "error",
                "message": result.get("message", "限速失败")
            }

    def _default_get_topology(self) -> Dict[str, Any]:
        """获取网络拓扑"""
        from . import sdn_control

        result = sdn_control.get_topology()

        if result.get("success"):
            switches = result.get("switches", [])
            hosts = result.get("hosts", {})
            return {
                "status": "success",
                "message": f"网络拓扑: {len(switches)} 台交换机, {len(hosts)} 台主机",
                "switches": switches,
                "hosts": list(hosts.keys()) if hosts else []
            }
        else:
            return {
                "status": "error",
                "message": result.get("message", "获取拓扑失败")
            }

    def _mock_response(self, message: str) -> Dict[str, Any]:
        """Generate mock response for testing without API key."""
        msg_lower = message.lower()

        # 模拟工具调用
        tool_calls = []

        # SDN控制相关
        if '快' in msg_lower or '速度' in msg_lower or '提速' in msg_lower:
            tool_calls.append({
                "status": "success",
                "message": "已提高网速",
                "action": "boost_speed"
            })
            reply = "已提高网络速度！网速已优化到最佳状态。\n\n注意：这是模拟操作，需要连接SDN控制器才能实际控制网络。"

        elif '慢' in msg_lower or '限制' in msg_lower or '限速' in msg_lower:
            tool_calls.append({
                "status": "success",
                "message": "已限制网速",
                "action": "limit_speed",
                "bandwidth_mbps": 0.5
            })
            reply = "已限制网络速度为 0.5 Mbps，用于QoS控制。\n\n注意：这是模拟操作，需要连接SDN控制器才能实际控制网络。"

        elif '拓扑' in msg_lower or 'topology' in msg_lower:
            tool_calls.append({
                "status": "success",
                "message": "获取网络拓扑",
                "switches": 3,
                "hosts": 4
            })
            reply = "网络拓扑信息：\n- 交换机数量: 3台\n- 主机数量: 4台\n\n注意：这是模拟数据。"

        # 威胁检测相关
        elif '威胁' in msg_lower or 'threat' in msg_lower:
            tool_calls.append({
                "status": "success",
                "message": "获取最近威胁（模拟数据）",
                "threats": [
                    {"type": "端口扫描", "severity": "中", "src_ip": "192.168.1.100"},
                    {"type": "DDoS攻击", "severity": "高", "src_ip": "192.168.1.200"}
                ]
            })
            reply = "已获取最近的威胁信息。检测到2个威胁：\n1. 端口扫描攻击（中危）来自 192.168.1.100\n2. DDoS攻击（高危）来自 192.168.1.200\n\n注意：这是模拟数据。"

        elif '统计' in msg_lower or 'stats' in msg_lower:
            tool_calls.append({
                "status": "success",
                "message": "网络统计（模拟数据）",
                "traffic_in": "1.2 GB",
                "traffic_out": "0.8 GB",
                "connections": 45
            })
            reply = "当前网络统计：\n- 入站流量: 1.2 GB\n- 出站流量: 0.8 GB\n- 活跃连接: 45\n\n注意：这是模拟数据。"

        elif '报告' in msg_lower or 'report' in msg_lower:
            tool_calls.append({
                "status": "success",
                "message": "生成安全报告",
                "report_url": "/api/reports/daily"
            })
            reply = "已生成今日安全报告。报告包含：\n- 威胁检测统计\n- 网络流量分析\n- 系统健康状态\n\n注意：这是模拟数据。"

        elif '状态' in msg_lower or 'status' in msg_lower:
            tool_calls.append({
                "status": "success",
                "message": "系统状态",
                "is_running": True,
                "processed_packets": 15234,
                "detected_threats": 8
            })
            reply = "系统状态：\n- 运行状态: 正常运行\n- 已处理数据包: 15,234\n- 检测到威胁: 8个\n\n注意：这是模拟数据。"

        elif '封锁' in msg_lower or 'block' in msg_lower:
            # 提取IP地址
            import re
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            ip = ip_match.group(1) if ip_match else "192.168.1.100"
            tool_calls.append({
                "status": "success",
                "message": f"已封锁IP地址: {ip}",
                "ip_address": ip
            })
            reply = f"已成功封锁IP地址: {ip}\n\n注意：这是模拟操作。"

        else:
            reply = """我可以帮助你：

**网络控制：**
- 提高网速 / 提速 / 加速
- 限制网速 / 限速 / 降低网速
- 查看网络拓扑
- 查看网络统计

**安全防护：**
- 封锁IP地址
- 查看威胁信息
- 生成安全报告
- 查看系统状态

请尝试说："让网速快一点" 或 "限制网速到0.5Mbps"

注意：当前为模拟模式，实际控制需要连接SDN控制器。"""

        return {
            'success': True,
            'reply': reply,
            'tool_calls': tool_calls,
            'mock_mode': True
        }


# Test the copilot
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Example usage
    copilot = AICopilot()

    # Test conversation
    response = copilot.chat("帮我查看最近的威胁")
    print(f"AI回复: {response.get('reply')}")

    if response.get('tool_calls'):
        print(f"执行的工具调用: {response['tool_calls']}")
