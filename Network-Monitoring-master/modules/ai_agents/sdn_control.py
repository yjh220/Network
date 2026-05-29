#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SDN控制器适配器 - 网络控制功能集成

集成自ModuleA项目，用于控制Ryu SDN控制器
支持QoS限速、流量控制、拓扑查询等功能
"""

import json
import logging
import traceback
from typing import Dict, Any, Optional
import requests

from modules.ai_agents.config import get_ai_config

logger = logging.getLogger(__name__)

# SDN控制器配置
SDN_CONFIG = {
    'RYU_URL': 'http://172.20.10.4:8081',  # Ryu控制器地址（Ubuntu VM）
    'API_BASE': 'http://172.20.10.4:8081/api/v1',
    'TIMEOUT': 5,
}


def apply_qos_policy(
    dpid: Optional[str] = None,
    port: Optional[int] = None,
    bandwidth_mbps: Optional[float] = None,
    action: str = "limit",
    auto_find: bool = False
) -> Dict[str, Any]:
    """
    应用QoS策略 - 提高或限制网速

    Args:
        dpid: 交换机DPID（可选，默认自动查找）
        port: 端口号（可选，默认自动查找）
        bandwidth_mbps: 带宽限制（Mbps），None表示取消限制
        action: "limit"限制 或 "boost"提速

    Returns:
        执行结果
    """
    result = {
        "success": False,
        "message": "",
        "action": action,
        "details": {},
    }

    # 模拟模式：返回成功结果
    if os.getenv('SDN_SIMULATION_MODE', 'true').lower() == 'true':
        result["success"] = True
        if bandwidth_mbps:
            result["message"] = f"[模拟模式] QoS策略应用成功: {action} {bandwidth_mbps}Mbps"
        else:
            result["message"] = f"[模拟模式] QoS策略已取消"
        result["details"] = {
            "dpid": dpid or "1",
            "port": port or 1,
            "bandwidth_mbps": bandwidth_mbps,
            "action": action,
            "mode": "simulation",
            "note": "SDN控制器未运行，使用模拟模式"
        }
        return result

    try:
        api_base = SDN_CONFIG['API_BASE']

        # 获取拓扑信息
        topo_resp = requests.get(f"{api_base}/topology", timeout=SDN_CONFIG['TIMEOUT'])
        if topo_resp.status_code != 200:
            result["message"] = "无法获取拓扑信息，请检查SDN控制器"
            return result

        topo_data = topo_resp.json()
        hosts = topo_data.get("hosts", {})

        if not hosts:
            result["message"] = "未找到任何主机，请启动Mininet拓扑"
            return result

        # 自动查找第一个主机
        target_dpid = None
        target_port = None
        target_ip = None

        for mac, host_info in hosts.items():
            target_dpid = host_info.get("dpid")
            target_port = host_info.get("port")
            target_ip = host_info.get("ip")
            if target_dpid and target_ip:
                break

        if not target_dpid:
            result["message"] = "未找到可用的交换机"
            return result

        # 处理带宽值
        if bandwidth_mbps is None:
            # 取消限制，使用高速率
            rate_kbps = 1000000  # 1Gbps
        elif bandwidth_mbps < 1:
            rate_kbps = int(bandwidth_mbps * 1000)
        else:
            rate_kbps = int(bandwidth_mbps * 1000)

        # 调用SDN控制器的meter接口
        payload = {
            "dpid": target_dpid,
            "ip": target_ip,
            "rate": rate_kbps
        }

        response = requests.post(
            f"{api_base}/meter",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=SDN_CONFIG['TIMEOUT']
        )

        result["details"]["response"] = response.json() if response.text else {}
        result["details"]["dpid"] = target_dpid
        result["details"]["port"] = target_port
        result["details"]["ip"] = target_ip
        result["details"]["rate_kbps"] = rate_kbps

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)

            if bandwidth_mbps is None:
                result["message"] = f"已解除网速限制，网速已恢复正常"
            else:
                result["message"] = f"已设置网速为 {bandwidth_mbps} Mbps"
        else:
            result["message"] = f"QoS设置失败: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["message"] = "连接SDN控制器超时，请检查控制器是否运行"
    except requests.exceptions.ConnectionError:
        result["message"] = "无法连接到SDN控制器，请检查网络连接"
    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def block_traffic(src_ip: str, duration: Optional[int] = None) -> Dict[str, Any]:
    """
    阻断特定IP的流量

    Args:
        src_ip: 要阻断的源IP地址
        duration: 阻断时长（秒），None表示永久

    Returns:
        执行结果
    """
    result = {
        "success": False,
        "message": "",
        "src_ip": src_ip,
        "details": {},
    }

    # 模拟模式：返回成功结果
    if os.getenv('SDN_SIMULATION_MODE', 'true').lower() == 'true':
        result["success"] = True
        result["message"] = f"[模拟模式] 已成功阻断IP: {src_ip}"
        if duration:
            result["message"] += f" (持续时间: {duration}秒)"
        result["details"] = {
            "src_ip": src_ip,
            "duration": duration,
            "priority": 1000,
            "mode": "simulation",
            "note": "SDN控制器未运行，使用模拟模式"
        }
        return result

    try:
        api_base = SDN_CONFIG['API_BASE']

        payload = {
            "task_type": "block",
            "params": {
                "src_ip": src_ip,
                "priority": 1000
            }
        }

        response = requests.post(
            f"{api_base}/agent/task",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=SDN_CONFIG['TIMEOUT']
        )

        result["details"]["response"] = response.json() if response.text else {}

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = f"已阻断IP: {src_ip} 的流量"
        else:
            result["message"] = f"阻断失败: {response.text[:200]}"

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def get_topology() -> Dict[str, Any]:
    """
    获取网络拓扑信息

    Returns:
        拓扑信息
    """
    result = {
        "success": False,
        "message": "",
        "switches": [],
        "hosts": [],
        "details": {},
    }

    try:
        api_base = SDN_CONFIG['API_BASE']

        response = requests.get(f"{api_base}/topology", timeout=SDN_CONFIG['TIMEOUT'])

        if response.status_code == 200:
            data = response.json()
            result["success"] = True
            result["switches"] = data.get("switches", [])
            result["hosts"] = data.get("hosts", {})
            result["message"] = f"拓扑查询成功: {len(result['switches'])} 台交换机, {len(result['hosts'])} 台主机"
        else:
            result["message"] = f"查询失败: {response.status_code}"

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"

    return result


def get_network_stats() -> Dict[str, Any]:
    """
    获取网络统计信息

    Returns:
        统计信息
    """
    result = {
        "success": False,
        "message": "",
        "stats": [],
        "details": {},
    }

    try:
        api_base = SDN_CONFIG['API_BASE']

        response = requests.get(f"{api_base}/network/stats", timeout=SDN_CONFIG['TIMEOUT'])

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", True)
            result["stats"] = data.get("stats", [])
            result["message"] = f"统计查询成功"
        else:
            result["message"] = f"查询失败: {response.status_code}"

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"

    return result


def set_controller_role(role: str) -> Dict[str, Any]:
    """
    设置控制器角色

    Args:
        role: "master" 或 "slave"

    Returns:
        执行结果
    """
    result = {
        "success": False,
        "message": "",
        "role": role,
        "details": {},
    }

    try:
        api_base = SDN_CONFIG['API_BASE']

        payload = {"role": role.lower()}
        response = requests.post(
            f"{api_base}/role",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=SDN_CONFIG['TIMEOUT']
        )

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = f"控制器角色已设置为 {role.upper()}"
        else:
            result["message"] = f"角色设置失败: {response.text[:200]}"

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"

    return result


# 检查SDN控制器连接状态
def check_sdn_connection() -> Dict[str, Any]:
    """
    检查SDN控制器连接状态

    Returns:
        连接状态信息
    """
    result = {
        "connected": False,
        "controller_url": SDN_CONFIG['RYU_URL'],
        "message": ""
    }

    try:
        response = requests.get(f"{SDN_CONFIG['API_BASE']}/switches", timeout=3)
        if response.status_code == 200:
            result["connected"] = True
            result["message"] = "SDN控制器连接正常"
            switches = response.json().get("switches", [])
            result["switch_count"] = len(switches)
        else:
            result["message"] = f"SDN控制器响应异常: {response.status_code}"
    except requests.exceptions.Timeout:
        result["message"] = "连接SDN控制器超时"
    except requests.exceptions.ConnectionError:
        result["message"] = "无法连接到SDN控制器"
    except Exception as e:
        result["message"] = f"检查连接时发生错误: {str(e)}"

    return result


def unblock_traffic(src_ip: str) -> Dict[str, Any]:
    """
    解除特定IP的流量阻断

    Args:
        src_ip: 要解除阻断的源IP地址

    Returns:
        执行结果
    """
    result = {
        "success": False,
        "message": "",
        "src_ip": src_ip,
        "details": {},
    }

    # 模拟模式：返回成功结果
    if os.getenv('SDN_SIMULATION_MODE', 'true').lower() == 'true':
        result["success"] = True
        result["message"] = f"[模拟模式] 已成功解除IP: {src_ip} 的阻断"
        result["details"] = {
            "src_ip": src_ip,
            "mode": "simulation",
            "note": "SDN控制器未运行，使用模拟模式"
        }
        return result

    try:
        api_base = SDN_CONFIG['API_BASE']

        payload = {
            "task_type": "unblock",
            "params": {
                "src_ip": src_ip
            }
        }

        response = requests.post(
            f"{api_base}/agent/task",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=SDN_CONFIG['TIMEOUT']
        )

        result["details"]["response"] = response.json() if response.text else {}

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = f"已解除IP: {src_ip} 的流量阻断"
        else:
            result["message"] = f"解除阻断失败: {response.text[:200]}"

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def clear_all_flows() -> Dict[str, Any]:
    """
    清除所有交换机的流表规则，恢复默认转发

    Returns:
        执行结果
    """
    result = {
        "success": False,
        "message": "",
        "details": {},
    }

    try:
        # 获取所有交换机
        switches_response = requests.get(f"{SDN_CONFIG['RYU_URL']}/stats/switches", timeout=5)

        if switches_response.status_code != 200:
            result["message"] = "获取交换机列表失败"
            return result

        switches_data = switches_response.json()
        switches = switches_data.get("switches", [])

        cleared_count = 0
        failed_count = 0

        for dpid in switches:
            try:
                # 删除该交换机的所有流表规则
                delete_response = requests.delete(f"{SDN_CONFIG['RYU_URL']}/stats/flow/{dpid}", timeout=5)

                if delete_response.status_code in [200, 204, 404]:  # 404表示没有流表规则
                    cleared_count += 1
                    result["details"][f"switch_{dpid}"] = "流表已清除"
                else:
                    failed_count += 1
                    result["details"][f"switch_{dpid}"] = f"清除失败: {delete_response.status_code}"

            except Exception as e:
                failed_count += 1
                result["details"][f"switch_{dpid}"] = f"错误: {str(e)}"

        result["success"] = (cleared_count > 0 and failed_count == 0)
        result["message"] = f"已清除 {cleared_count} 台交换机的流表规则"
        if failed_count > 0:
            result["message"] += f", {failed_count} 台失败"

        # 重新设置基本的转发规则
        setup_basic_forwarding()

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def setup_basic_forwarding() -> Dict[str, Any]:
    """
    设置基本的转发规则，允许所有主机间通信

    Returns:
        执行结果
    """
    result = {
        "success": False,
        "message": "",
        "details": {},
    }

    try:
        api_base = SDN_CONFIG['API_BASE']

        payload = {
            "task_type": "setup_forwarding",
            "params": {
                "mode": "all_allow"  # 允许所有通信
            }
        }

        response = requests.post(
            f"{api_base}/agent/task",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=SDN_CONFIG['TIMEOUT']
        )

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = "基本转发规则已设置，允许所有主机间通信"
        else:
            result["message"] = f"设置转发规则失败: {response.text[:200]}"

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def block_specific_traffic(src_ip: str, dst_ip: str) -> Dict[str, Any]:
    """
    阻断特定源IP到特定目的IP的流量

    Args:
        src_ip: 源IP地址
        dst_ip: 目的IP地址

    Returns:
        执行结果
    """
    result = {
        "success": False,
        "message": "",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "details": {},
    }

    try:
        api_base = SDN_CONFIG['API_BASE']

        payload = {
            "task_type": "block_specific",
            "params": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "priority": 1000
            }
        }

        response = requests.post(
            f"{api_base}/agent/task",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=SDN_CONFIG['TIMEOUT']
        )

        result["details"]["response"] = response.json() if response.text else {}

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = f"已阻断 {src_ip} 到 {dst_ip} 的流量"
        else:
            result["message"] = f"阻断失败: {response.text[:200]}"

    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result
