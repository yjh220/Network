"""
SDN控制器适配器 - 适配自定义Ryu控制器

将ModuleA的SDN工具调用适配到自定义Ryu控制器的API
自定义控制器API端点：
- /api/v1/switches - 交换机列表
- /api/v1/topology - 拓扑信息
- /api/v1/meter - QoS限速
- /api/v1/agent/task - 通用任务接口
- /api/v1/honeypot/redirect - 蜜罐引流
- /api/v1/network/stats - 网络统计
"""

import json
import traceback
import os
from typing import Dict, Any, Optional, List
import requests


# 自定义控制器API基础路径（从环境变量或使用默认值）
RYU_HOST = os.getenv('RYU_HOST', '172.20.10.4')
RYU_PORT = os.getenv('RYU_PORT', '8081')
CUSTOM_API_URL = f"http://{RYU_HOST}:{RYU_PORT}"
API_BASE = f"{CUSTOM_API_URL}/api/v1"

# 启用模拟模式（当真实SDN控制器不可用时）
# 已禁用模拟模式，连接到真实虚拟机控制器
SIMULATION_MODE = os.getenv('SDN_SIMULATION_MODE', 'false').lower() == 'true'


def apply_qos_policy(
    dpid: str,
    port: int,
    bandwidth_mbps: int,
    meter_id: Optional[int] = None,
    priority: int = 100,
    output_port: Optional[int] = None,
    auto_find: bool = False,
) -> Dict[str, Any]:
    """
    在指定交换机端口上应用QoS限速策略

    适配到自定义控制器的 /api/v1/meter 接口

    Args:
        dpid: 交换机DPID（整数或十六进制字符串，可为None自动查找）
        port: 端口号（可为None自动查找）
        bandwidth_mbps: 带宽限制（Mbps）
        meter_id: Meter表ID（可选）
        priority: 流表优先级
        output_port: 输出端口

    Returns:
        执行结果字典
    """
    result = {
        "success": False,
        "message": "",
        "dpid": dpid,
        "port": port,
        "bandwidth_mbps": bandwidth_mbps,
        "details": {},
    }

    # 模拟模式：返回成功结果
    if SIMULATION_MODE:
        result["success"] = True
        result["message"] = f"[模拟模式] QoS限速成功: {bandwidth_mbps}Mbps"
        result["dpid"] = dpid or "1"
        result["port"] = port or 1
        result["details"] = {
            "mode": "simulation",
            "meter_id": meter_id or 1,
            "rate_kbps": bandwidth_mbps * 1000,
            "burst_size": bandwidth_mbps * 100,
            "note": "SDN控制器未运行，使用模拟模式"
        }
        return result

    try:
        # 先获取拓扑信息，用于查找IP位置
        topo_resp = requests.get(f"{API_BASE}/topology", timeout=5)
        if topo_resp.status_code != 200:
            result["message"] = f"无法获取拓扑信息: {topo_resp.status_code}"
            return result

        topo_data = topo_resp.json()
        hosts = topo_data.get("hosts", {})

        # 处理带宽单位转换（处理小于1Mbps的情况）
        # 200Kbps = 0.2Mbps，直接使用Kbps
        if bandwidth_mbps < 1:
            rate_kbps = int(bandwidth_mbps * 1000)
        else:
            rate_kbps = bandwidth_mbps * 1000

        # 如果没有指定dpid，从拓扑中查找任意主机对应的交换机
        target_dpid_int = None
        target_port = None
        target_ip = None

        if dpid is None or port is None:
            # 从拓扑中找第一个可用的主机
            for mac, host_info in hosts.items():
                target_dpid_int = host_info.get("dpid")
                target_port = host_info.get("port")
                target_ip = host_info.get("ip")
                if target_dpid_int and target_ip:
                    break
        else:
            # 使用指定的dpid
            if isinstance(dpid, str):
                target_dpid_int = int(dpid.replace('0x', '').replace('0X', ''), 16)
            else:
                target_dpid_int = int(dpid)
            target_port = port

            # 查找对应的主机IP
            for mac, host_info in hosts.items():
                if host_info.get("dpid") == target_dpid_int and host_info.get("port") == target_port:
                    target_ip = host_info.get("ip")
                    break

        if not target_dpid_int:
            result["message"] = "未找到可用的交换机，请确认网络拓扑已初始化"
            return result

        if not target_ip:
            result["message"] = f"未找到连接到交换机{target_dpid_int}的主机"
            return result

        # 调用自定义控制器的meter接口
        payload = {
            "dpid": target_dpid_int,
            "ip": target_ip,
            "rate": rate_kbps
        }

        response = requests.post(
            f"{API_BASE}/meter",
            json=payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            timeout=5
        )

        result["details"]["response"] = response.json() if response.text else {}
        result["details"]["dpid_used"] = target_dpid_int
        result["details"]["ip_used"] = target_ip
        result["details"]["rate_kbps"] = rate_kbps

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = data.get("message", "QoS限速已设置")
            result["dpid"] = target_dpid_int
            result["port"] = target_port
            result["meter_id"] = data.get("details", {}).get("meter_id")
        else:
            result["message"] = f"QoS限速设置失败: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["message"] = f"连接控制器超时: {API_BASE}"
    except requests.exceptions.ConnectionError:
        result["message"] = f"无法连接到控制器: {API_BASE}"
    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def apply_security_block(
    src_ip: str,
    dpid: Optional[str] = None,
    priority: int = 1000,
    duration: Optional[int] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
) -> Dict[str, Any]:
    """
    在网络中下发安全阻断规则

    适配到自定义控制器的 /api/v1/agent/task 接口

    Args:
        src_ip: 需要阻断的源IP地址
        dpid: 目标交换机DPID（可选）
        priority: 流表优先级
        duration: 规则持续时间（秒）
        dst_ip: 目标IP（可选）
        dst_port: 目标端口（可选）
        protocol: 协议类型（可选）

    Returns:
        执行结果字典
    """
    result = {
        "success": False,
        "message": "",
        "blocked_src_ip": src_ip,
        "dpid": dpid,
        "priority": priority,
        "flow_ids": [],
        "affected_switches": 0,
        "details": {},
    }

    try:
        # 调用自定义控制器的agent/task接口
        payload = {
            "task_type": "block",
            "params": {
                "src_ip": src_ip,
                "priority": priority
            }
        }

        response = requests.post(
            f"{API_BASE}/agent/task",
            json=payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            timeout=5
        )

        result["details"]["response"] = response.json() if response.text else {}

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = data.get("message", "阻断规则已下发")
            result["affected_switches"] = data.get("affected_switches", 1)
            result["flow_ids"] = [f"block_{src_ip}"]
        else:
            result["message"] = f"阻断规则下发失败: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["message"] = f"连接控制器超时: {API_BASE}"
    except requests.exceptions.ConnectionError:
        result["message"] = f"无法连接到控制器: {API_BASE}"
    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def redirect_to_honeypot(
    attacker_ip: str,
    dpid: Optional[str] = None,
    honeypot_port: int = 3,
) -> Dict[str, Any]:
    """
    将攻击者流量重定向到蜜罐

    使用自定义控制器的 /api/v1/honeypot/redirect 接口

    Args:
        attacker_ip: 攻击者IP地址
        dpid: 交换机DPID（可选，默认为1）
        honeypot_port: 蜜罐端口

    Returns:
        执行结果字典
    """
    result = {
        "success": False,
        "message": "",
        "attacker_ip": attacker_ip,
        "honeypot_port": honeypot_port,
        "details": {},
    }

    try:
        # 确定目标交换机
        target_dpid = 1  # 默认使用交换机1
        if dpid:
            if isinstance(dpid, str):
                target_dpid = int(dpid.replace('0x', '').replace('0X', ''), 16)
            else:
                target_dpid = int(dpid)

        # 调用蜜罐重定向接口
        payload = {
            "dpid": target_dpid,
            "attacker_ip": attacker_ip,
            "honeypot_port": honeypot_port
        }

        response = requests.post(
            f"{API_BASE}/honeypot/redirect",
            json=payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            timeout=5
        )

        result["details"]["response"] = response.json() if response.text else {}

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = data.get("message", "流量已重定向到蜜罐")
            result["details"].update(data.get("details", {}))
        else:
            result["message"] = f"蜜罐重定向失败: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["message"] = f"连接控制器超时: {API_BASE}"
    except requests.exceptions.ConnectionError:
        result["message"] = f"无法连接到控制器: {API_BASE}"
    except Exception as e:
        result["message"] = f"发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def query_switches() -> Dict[str, Any]:
    """
    查询网络中所有交换机的列表

    适配到 /api/v1/switches 接口

    Returns:
        包含查询结果的字典
    """
    result = {
        "success": False,
        "message": "",
        "switches": [],
        "dpid_list": [],
        "count": 0,
        "details": {},
    }

    try:
        response = requests.get(f"{API_BASE}/switches", timeout=5)

        if response.status_code == 200:
            data = response.json()

            switches = []
            dpid_list = []

            for dpid in data.get("switches", []):
                if isinstance(dpid, int):
                    formatted_dpid = f"{dpid:016x}"
                else:
                    formatted_dpid = str(dpid)

                switches.append({"dpid": formatted_dpid, "dpid_int": dpid if isinstance(dpid, int) else int(dpid, 16)})
                dpid_list.append(formatted_dpid)

            result["success"] = True
            result["switches"] = switches
            result["dpid_list"] = dpid_list
            result["count"] = len(switches)
            result["message"] = f"查询成功，发现 {len(switches)} 台交换机"
        else:
            result["message"] = f"查询失败，状态码: {response.status_code}"

    except Exception as e:
        result["message"] = f"查询交换机时发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def query_topology() -> Dict[str, Any]:
    """
    查询网络拓扑信息（包括主机）

    使用 /api/v1/topology 接口

    Returns:
        包含拓扑信息的字典
    """
    result = {
        "success": False,
        "message": "",
        "switches": [],
        "hosts": {},
        "details": {},
    }

    try:
        response = requests.get(f"{API_BASE}/topology", timeout=5)

        if response.status_code == 200:
            data = response.json()
            result["success"] = True
            result["switches"] = data.get("switches", [])
            result["hosts"] = data.get("hosts", {})
            result["message"] = (
                f"拓扑查询成功: {data.get('switches_count', 0)} 台交换机, "
                f"{len(data.get('hosts', {}))} 台主机"
            )
        else:
            result["message"] = f"查询失败，状态码: {response.status_code}"

    except Exception as e:
        result["message"] = f"查询拓扑时发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def query_network_stats() -> Dict[str, Any]:
    """
    查询网络统计信息

    使用 /api/v1/network/stats 接口

    Returns:
        包含统计信息的字典
    """
    result = {
        "success": False,
        "message": "",
        "stats": [],
        "details": {},
    }

    try:
        response = requests.get(f"{API_BASE}/network/stats", timeout=5)

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", True)
            result["stats"] = data.get("stats", [])
            result["message"] = f"网络统计查询成功，{data.get('count', 0)} 个端口有数据"
        else:
            result["message"] = f"查询失败，状态码: {response.status_code}"

    except Exception as e:
        result["message"] = f"查询统计时发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def set_controller_role(role: str) -> Dict[str, Any]:
    """
    设置控制器角色（MASTER/SLAVE）

    使用 /api/v1/role 接口

    Args:
        role: "master" 或 "slave"

    Returns:
        执行结果字典
    """
    result = {
        "success": False,
        "message": "",
        "role": role,
        "details": {},
    }

    try:
        payload = {"role": role.lower()}
        response = requests.post(
            f"{API_BASE}/role",
            json=payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            result["success"] = data.get("success", False)
            result["message"] = data.get("message", f"角色切换为{role.upper()}")
        else:
            result["message"] = f"角色切换失败: {response.text[:200]}"

    except Exception as e:
        result["message"] = f"切换角色时发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def query_flow_tables(dpid: str) -> Dict[str, Any]:
    """
    查询指定交换机的流表信息

    由于自定义控制器没有流表查询API，返回基础信息

    Args:
        dpid: 交换机DPID

    Returns:
        包含流表信息的字典
    """
    result = {
        "success": False,
        "message": "",
        "dpid": dpid,
        "flows": [],
        "flow_count": 0,
        "details": {},
    }

    try:
        # 格式化DPID
        if isinstance(dpid, int):
            formatted_dpid = f"{dpid:016x}"
        else:
            formatted_dpid = dpid

        # 自定义控制器不支持直接流表查询，返回基础信息
        result["success"] = True
        result["flows"] = []
        result["flow_count"] = 0
        result["message"] = f"交换机 {formatted_dpid} 流表查询（自定义控制器暂不支持详细流表查询）"

    except Exception as e:
        result["message"] = f"查询流表时发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


def query_port_stats(dpid: str, port: Optional[int] = None) -> Dict[str, Any]:
    """
    查询交换机端口统计信息

    使用 /api/v1/network/stats 接口获取统计数据

    Args:
        dpid: 交换机DPID
        port: 端口号（可选）

    Returns:
        包含端口统计的字典
    """
    result = {
        "success": False,
        "message": "",
        "dpid": dpid,
        "ports": [],
        "details": {},
    }

    try:
        # 获取网络统计
        response = requests.get(f"{API_BASE}/network/stats", timeout=5)

        if response.status_code == 200:
            data = response.json()
            all_stats = data.get("stats", [])

            # 格式化DPID用于比较
            if isinstance(dpid, int):
                dpid_int = dpid
            else:
                dpid_int = int(dpid.replace('0x', '').replace('0X', ''), 16)

            # 过滤出目标交换机的端口
            target_ports = []
            for stat in all_stats:
                if stat.get("dpid") == dpid_int:
                    if port is None or stat.get("port") == port:
                        target_ports.append(stat)

            result["success"] = True
            result["ports"] = target_ports

            if port:
                if target_ports:
                    p = target_ports[0]
                    result["message"] = (
                        f"交换机 {dpid} 端口 {port}: "
                        f"速率 {p.get('kbps', 0)} Kbps"
                    )
                else:
                    result["message"] = f"端口 {port} 不存在或无数据"
            else:
                result["message"] = f"交换机 {dpid} 有 {len(target_ports)} 个活动端口"
        else:
            result["message"] = f"查询失败，状态码: {response.status_code}"

    except Exception as e:
        result["message"] = f"查询端口统计时发生错误: {str(e)}"
        result["details"]["traceback"] = traceback.format_exc()

    return result


# 工具函数列表（与sdn_controls.py兼容）
SDN_TOOLS = [
    {
        "name": "apply_qos_policy",
        "description": "在指定交换机端口上应用QoS带宽限速策略",
        "function": apply_qos_policy,
    },
    {
        "name": "apply_security_block",
        "description": "在网络上阻断特定源IP地址的流量",
        "function": apply_security_block,
    },
    {
        "name": "redirect_to_honeypot",
        "description": "将攻击者流量重定向到蜜罐",
        "function": redirect_to_honeypot,
    },
    {
        "name": "query_switches",
        "description": "查询网络中所有交换机的列表",
        "function": query_switches,
    },
    {
        "name": "query_topology",
        "description": "查询网络拓扑信息（包括主机）",
        "function": query_topology,
    },
    {
        "name": "query_network_stats",
        "description": "查询网络统计信息",
        "function": query_network_stats,
    },
    {
        "name": "set_controller_role",
        "description": "设置控制器角色（MASTER/SLAVE）",
        "function": set_controller_role,
    },
    {
        "name": "query_flow_tables",
        "description": "查询指定交换机的流表信息",
        "function": query_flow_tables,
    },
    {
        "name": "query_port_stats",
        "description": "查询交换机端口统计信息",
        "function": query_port_stats,
    },
]


if __name__ == "__main__":
    print("SDN控制器适配器")
    print("=" * 50)
    print(f"自定义控制器地址: {API_BASE}")
    print()
    print("可用工具:")
    for tool in SDN_TOOLS:
        print(f"  - {tool['name']}: {tool['description']}")
