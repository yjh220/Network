#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动化攻击检测演示脚本 v3.1 - 简化版
直接显示生成的攻击类型，不依赖IDS识别
"""

import sys
import time
import logging
import os
import random
from datetime import datetime
from scapy.all import IP, TCP, Ether, Raw, wrpcap

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


class AutoAttackDemo:
    """自动化攻击检测演示 - 支持7种威胁类型"""

    def __init__(self, target_ip="192.168.100.1"):
        self.target_ip = target_ip
        self.pcap_file = "attack.pcap"
        self.attacks_generated = []

        # 威胁类型配置
        self.threat_types = {
            'DDoS攻击': {'severity': '高', 'description': '分布式拒绝服务', 'color': '🔴'},
            '端口扫描': {'severity': '中', 'description': '探测开放端口', 'color': '🟡'},
            'SQL注入': {'severity': '高', 'description': '数据库攻击', 'color': '🔴'},
            'XSS攻击': {'severity': '中', 'description': '跨站脚本攻击', 'color': '🟡'},
            '暴力破解': {'severity': '中', 'description': 'FTP/SSH暴力破解', 'color': '🟡'},
            '僵尸网络': {'severity': '高', 'description': 'Bot网络活动', 'color': '🔴'},
            'Heartbleed': {'severity': '高', 'description': 'OpenSSL漏洞利用', 'color': '🔴'}
        }

    def print_step(self, step_num, total_steps, message):
        """打印进度信息"""
        print(f"\n[{step_num}/{total_steps}] {message}")
        time.sleep(0.3)

    def generate_ddos_attack(self):
        """生成DDoS攻击流量 - 高危"""
        packets = []
        print(f"    🔴 生成 DDoS攻击 流量（高危）...")

        src_ips = [f"10.0.{i}.{j}" for i in range(50, 55) for j in range(1, 10)]

        for src_ip in src_ips[:30]:
            for _ in range(5):
                packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=80,
                    flags='PA'
                ) / Raw(load=b"X" * 200)
                packets.append(packet)

        self.attacks_generated.append({
            'type': 'DDoS攻击',
            'count': len(packets),
            'src_ip': f"{src_ips[0]} ... {src_ips[-1]}",
            'dst_ip': self.target_ip,
            'severity': '高',
            'description': '分布式拒绝服务'
        })
        print(f"       ✓ 生成 {len(packets)} 个 DDoS 攻击包")
        return packets

    def generate_port_scan(self):
        """生成端口扫描攻击流量 - 中危"""
        packets = []
        print(f"    🟡 生成 端口扫描 流量（中危）...")

        src_ip = "192.168.100.2"
        target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9200, 27017]

        for port in target_ports:
            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=random.randint(50000, 60000),
                dport=port,
                flags='S'
            )
            packets.append(packet)

        self.attacks_generated.append({
            'type': '端口扫描',
            'count': len(packets),
            'src_ip': src_ip,
            'dst_ip': self.target_ip,
            'severity': '中',
            'description': '探测开放端口'
        })
        print(f"       ✓ 扫描了 {len(packets)} 个端口")
        return packets

    def generate_sql_injection(self):
        """生成SQL注入攻击流量 - 高危"""
        packets = []
        print(f"    🔴 生成 SQL注入 流量（高危）...")

        src_ip = "192.168.100.3"
        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "' OR 1=1#",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "admin' #",
            "' UNION SELECT * FROM users--",
            "1' ORDER BY 1--",
            "'; EXEC xp_cmdshell('dir')--"
        ]

        for payload in sql_payloads:
            http_request = f"GET /login?id={payload}&page=1 HTTP/1.1\r\n"
            http_request += f"Host: {self.target_ip}\r\n"
            http_request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            http_request += "Accept: */*\r\n\r\n"

            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=45000,
                dport=80,
                flags='PA'
            ) / Raw(load=http_request.encode())
            packets.append(packet)

        self.attacks_generated.append({
            'type': 'SQL注入',
            'count': len(packets),
            'src_ip': src_ip,
            'dst_ip': self.target_ip,
            'severity': '高',
            'description': '数据库攻击'
        })
        print(f"       ✓ 生成 {len(packets)} 个 SQL 注入攻击")
        return packets

    def generate_xss_attack(self):
        """生成XSS攻击流量 - 中危"""
        packets = []
        print(f"    🟡 生成 XSS攻击 流量（中危）...")

        src_ip = "192.168.100.4"
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>"
        ]

        for payload in xss_payloads:
            http_request = f"GET /search?q={payload} HTTP/1.1\r\n"
            http_request += f"Host: {self.target_ip}\r\n"
            http_request += "User-Agent: Mozilla/5.0\r\n"
            http_request += "Referer: http://evil.com\r\n\r\n"

            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=46000,
                dport=80,
                flags='PA'
            ) / Raw(load=http_request.encode())
            packets.append(packet)

        self.attacks_generated.append({
            'type': 'XSS攻击',
            'count': len(packets),
            'src_ip': src_ip,
            'dst_ip': self.target_ip,
            'severity': '中',
            'description': '跨站脚本攻击'
        })
        print(f"       ✓ 生成 {len(packets)} 个 XSS 攻击")
        return packets

    def generate_brute_force(self):
        """生成暴力破解攻击流量 - 中危"""
        packets = []
        print(f"    🟡 生成 暴力破解 流量（中危）...")

        src_ip = "192.168.100.5"

        # SSH暴力破解
        for i in range(15):
            username_password = f"root:password{i}"
            payload = f"SSH-2.0-{username_password}"

            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=50000 + i,
                dport=22,
                flags='PA'
            ) / Raw(load=payload.encode())
            packets.append(packet)

        # FTP暴力破解
        for i in range(10):
            payload = f"USER admin\r\nPASS pass{i}"

            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=51000 + i,
                dport=21,
                flags='PA'
            ) / Raw(load=payload.encode())
            packets.append(packet)

        self.attacks_generated.append({
            'type': '暴力破解',
            'count': len(packets),
            'src_ip': src_ip,
            'dst_ip': self.target_ip,
            'severity': '中',
            'description': 'FTP/SSH暴力破解'
        })
        print(f"       ✓ 生成 {len(packets)} 个暴力破解尝试")
        return packets

    def generate_botnet(self):
        """生成僵尸网络流量 - 高危"""
        packets = []
        print(f"    🔴 生成 僵尸网络 流量（高危）...")

        bot_ips = [f"172.16.{i}.{j}" for i in range(100, 105) for j in range(1, 5)]
        c2_server = self.target_ip

        # Bot向C2服务器汇报
        for bot_ip in bot_ips:
            heartbeat = IP(src=bot_ip, dst=c2_server) / TCP(
                sport=random.randint(40000, 50000),
                dport=6667,
                flags='PA'
            ) / Raw(load=b"PRIVMSG #botnet :heartbeat\r\n")
            packets.append(heartbeat)

            status = IP(src=bot_ip, dst=c2_server) / TCP(
                sport=random.randint(40000, 50000),
                dport=8080,
                flags='PA'
            ) / Raw(load=b"GET /status?bot=" + bot_ip.encode() + b" HTTP/1.1\r\n")
            packets.append(status)

        # C2命令下发
        for i in range(5):
            command = IP(src=c2_server, dst=bot_ips[0]) / TCP(
                sport=80,
                dport=random.randint(40000, 50000),
                flags='PA'
            ) / Raw(load=b"COMMAND:DDOS_START target.com\r\n")
            packets.append(command)

        self.attacks_generated.append({
            'type': '僵尸网络',
            'count': len(packets),
            'src_ip': f"{bot_ips[0]} ... {bot_ips[-1]}",
            'dst_ip': c2_server,
            'severity': '高',
            'description': 'Bot网络活动'
        })
        print(f"       ✓ 生成 {len(bot_ips)} 个僵尸节点的通信")
        return packets

    def generate_heartbleed(self):
        """生成Heartbleed攻击流量 - 高危"""
        packets = []
        print(f"    🔴 生成 Heartbleed 流量（高危）...")

        src_ip = "192.168.100.7"

        for i in range(8):
            heartbeat_payload = bytes.fromhex('01 40 00')
            heartbeat_payload += bytes(16)

            tls_header = bytes.fromhex('16 03 01 00 20')
            tls_header += bytes.fromhex('01 00 00 1c 03 01')
            tls_header += bytes(28)

            packet = IP(src=src_ip, dst=self.target_ip) / TCP(
                sport=52000 + i,
                dport=443,
                flags='PA'
            ) / Raw(load=tls_header + heartbeat_payload)
            packets.append(packet)

        self.attacks_generated.append({
            'type': 'Heartbleed',
            'count': len(packets),
            'src_ip': src_ip,
            'dst_ip': self.target_ip,
            'severity': '高',
            'description': 'OpenSSL漏洞利用'
        })
        print(f"       ✓ 生成 {len(packets)} 个 Heartbleed 漏洞利用")
        return packets

    def save_pcap(self, packets):
        """保存数据包到PCAP文件"""
        print(f"    - 保存 {len(packets)} 个数据包到 {self.pcap_file}...")

        try:
            wrpcap(self.pcap_file, packets)
            print(f"    ✓ PCAP文件保存成功: {self.pcap_file}")
            print(f"    ✓ 文件路径: {os.path.abspath(self.pcap_file)}")
            print(f"    ✓ 文件大小: {os.path.getsize(self.pcap_file)} 字节")
            return True
        except Exception as e:
            print(f"    ✗ 保存失败: {e}")
            return False

    def display_results(self):
        """显示检测结果"""
        print("\n" + "="*80)
        print("【攻击检测结果】")
        print("="*80)

        # 统计
        total_attacks = sum([a['count'] for a in self.attacks_generated])
        high_severity = [a for a in self.attacks_generated if a['severity'] == '高']
        medium_severity = [a for a in self.attacks_generated if a['severity'] == '中']

        print(f"✓ 成功生成 {total_attacks} 个攻击数据包")
        print(f"✓ 攻击类型数量: {len(self.attacks_generated)} 种")
        print(f"🔴 高危攻击: {len(high_severity)} 种 ({sum([a['count'] for a in high_severity])} 个包)")
        print(f"🟡 中危攻击: {len(medium_severity)} 种 ({sum([a['count'] for a in medium_severity])} 个包)")

        print("\n" + "─"*80)
        print("攻击详情列表:")
        print("─"*80)

        for i, attack in enumerate(self.attacks_generated, 1):
            color = '🔴' if attack['severity'] == '高' else '🟡'

            print(f"\n{color} 攻击 #{i}: {attack['type']}")
            print(f"   严重等级: {attack['severity']}")
            print(f"   说明: {attack['description']}")
            print(f"   源IP: {attack['src_ip']}")
            print(f"   目标IP: {attack['dst_ip']}")
            print(f"   数据包数: {attack['count']}")

        print("\n" + "="*80)
        print(f"【总结】成功生成: {'、'.join([a['type'] for a in self.attacks_generated])} 攻击")
        print("="*80)

        # 威胁类型统计表
        print("\n【威胁类型统计表】")
        print("─"*80)
        print(f"{'威胁类型':<15} {'严重等级':<10} {'说明':<30} {'数据包数':<10}")
        print("─"*80)

        for attack in self.attacks_generated:
            color = self.threat_types[attack['type']]['color']
            print(f"{color} {attack['type']:<13} {attack['severity']:<10} {attack['description']:<30} {attack['count']:<10}")

        print("="*80)

    def run(self):
        """运行完整的自动化演示"""
        total_steps = 4

        print("\n" + "="*80)
        print("【自动化攻击检测演示 v3.1】")
        print("支持7种威胁类型：DDoS、端口扫描、SQL注入、XSS、暴力破解、僵尸网络、Heartbleed")
        print("="*80)
        print(f"目标IP: {self.target_ip}")
        print(f"保存文件: {self.pcap_file}")
        print("="*80)

        # 步骤1: 生成攻击流量
        self.print_step(1, total_steps, "正在生成攻击流量...")
        print("    支持的威胁类型:")
        for threat_type, info in self.threat_types.items():
            print(f"      {info['color']} {threat_type:<12} - {info['severity']} - {info['description']}")

        all_packets = []

        # 按严重程度生成攻击
        print("\n    开始生成各种攻击流量...")
        all_packets.extend(self.generate_ddos_attack())
        all_packets.extend(self.generate_heartbleed())
        all_packets.extend(self.generate_sql_injection())
        all_packets.extend(self.generate_botnet())
        all_packets.extend(self.generate_xss_attack())
        all_packets.extend(self.generate_port_scan())
        all_packets.extend(self.generate_brute_force())

        print(f"\n    ✓ 总共生成 {len(all_packets)} 个攻击数据包")
        print(f"    ✓ 包含 {len(self.attacks_generated)} 种攻击类型")

        # 步骤2: 保存PCAP文件
        self.print_step(2, total_steps, f"攻击流量已生成，保存为 {self.pcap_file}")

        if not self.save_pcap(all_packets):
            print("✗ 无法保存PCAP文件，演示终止")
            return

        # 步骤3: 检测完成
        self.print_step(3, total_steps, "攻击流量已保存，可用于入侵检测分析")

        # 步骤4: 显示结果
        self.print_step(4, total_steps, "显示攻击类型统计...")

        self.display_results()

        print("\n【使用说明】")
        print("─"*80)
        print("1. 使用Wireshark抓包:")
        print("   - 安装 Microsoft Loopback Adapter")
        print(f"   - 设置IP为 {self.target_ip}")
        print("   - Wireshark选择虚拟网卡")
        print("   - 运行此脚本查看流量")
        print()
        print("2. 入侵检测分析:")
        print(f"   - 文件路径: {os.path.abspath(self.pcap_file)}")
        print("   - 访问: http://127.0.0.1:8080/intrusion_detection")
        print(f"   - 输入文件路径进行分析")
        print()
        print("3. 依赖安装:")
        print("   - pip install scapy requests")
        print("="*80)


def main():
    """主函数"""
    import argparse

    random.seed(int(time.time()))

    parser = argparse.ArgumentParser(description='自动化攻击检测演示 - 支持7种威胁类型')
    parser.add_argument('-t', '--target-ip',
                        default='192.168.100.1',
                        help='目标IP地址 (默认: 192.168.100.1)')
    parser.add_argument('-o', '--output',
                        default='attack.pcap',
                        help='输出PCAP文件名 (默认: attack.pcap)')

    args = parser.parse_args()

    demo = AutoAttackDemo(target_ip=args.target_ip)
    demo.pcap_file = args.output

    try:
        demo.run()
    except KeyboardInterrupt:
        print("\n\n用户中断演示")
    except Exception as e:
        print(f"\n\n演示过程中出错: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
