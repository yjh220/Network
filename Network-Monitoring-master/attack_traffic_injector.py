#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击流量注入器 - 生成混合攻击流量用于实时检测演示
"""

import random
import time
import threading
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw
from scapy.utils import wrpcap
import logging

logger = logging.getLogger(__name__)


class AttackTrafficInjector:
    """攻击流量注入器 - 生成各种攻击流量"""

    def __init__(self):
        self.is_running = False
        self.thread = None
        self.attack_packets = []
        self.generated_attacks = []

        # 攻击配置
        self.attacks = {
            'port_scan': {
                'name': '端口扫描',
                'weight': 30,
                'generate': self._generate_port_scan
            },
            'syn_flood': {
                'name': 'SYN洪水攻击',
                'weight': 20,
                'generate': self._generate_syn_flood
            },
            'brute_force': {
                'name': '暴力破解',
                'weight': 20,
                'generate': self._generate_brute_force
            },
            'dos_attack': {
                'name': 'DoS攻击',
                'weight': 15,
                'generate': self._generate_dos
            },
            'sql_injection': {
                'name': 'SQL注入',
                'weight': 15,
                'generate': self._generate_sql_injection
            }
        }

    def _generate_port_scan(self, count=10):
        """生成端口扫描攻击流量"""
        packets = []
        src_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 255)}"

        # 扫描多个端口
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]

        for i in range(min(count, len(ports))):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=ports[i],
                flags='S'  # SYN包
            )
            packets.append(packet)

        logger.info(f"生成端口扫描攻击: {src_ip} -> {dst_ip}, 端口数: {len(packets)}")
        return packets, {'type': 'PortScan', 'src_ip': src_ip, 'dst_ip': dst_ip}

    def _generate_syn_flood(self, count=20):
        """生成SYN洪水攻击流量"""
        packets = []
        src_ip = f"172.16.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_port = 80

        for _ in range(count):
            # 使用随机源IP进行伪造
            spoofed_src = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

            packet = Ether() / IP(src=spoofed_src, dst=dst_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=dst_port,
                flags='S'
            )
            packets.append(packet)

        logger.info(f"生成SYN洪水攻击: {dst_ip}:80, 数据包数: {len(packets)}")
        return packets, {'type': 'SYN Flood', 'src_ip': src_ip, 'dst_ip': dst_ip}

    def _generate_brute_force(self, count=15):
        """生成暴力破解攻击流量"""
        packets = []
        src_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 255)}"
        dst_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_port = random.choice([22, 3389, 21])  # SSH, RDP, FTP

        for _ in range(count):
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=dst_port,
                flags='PA'  # PSH + ACK
            ) / Raw(load=b"Login attempt: admin / " + str(random.randint(1000, 9999)).encode())

            packets.append(packet)

        logger.info(f"生成暴力破解攻击: {src_ip} -> {dst_ip}:{dst_port}, 尝试次数: {len(packets)}")
        return packets, {'type': 'BruteForce', 'src_ip': src_ip, 'dst_ip': dst_ip}

    def _generate_dos(self, count=25):
        """生成DoS攻击流量"""
        packets = []
        src_ips = [f"10.0.{random.randint(1, 5)}.{i}" for i in range(1, 10)]
        dst_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"

        for src_ip in src_ips:
            for _ in range(count // len(src_ips)):
                packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=80,
                    flags='PA'
                ) / Raw(load=b"X" * random.randint(100, 500))

                packets.append(packet)

        logger.info(f"生成DoS攻击: {dst_ip}:80, 数据包数: {len(packets)}")
        return packets, {'type': 'DoS', 'src_ip': src_ips[0], 'dst_ip': dst_ip}

    def _generate_sql_injection(self, count=8):
        """生成SQL注入攻击流量"""
        packets = []
        src_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 255)}"

        sql_payloads = [
            b"' OR '1'='1",
            b"admin'--",
            b"' UNION SELECT * FROM users--",
            b"1' AND 1=1--",
            b"'; DROP TABLE users;--",
            b"admin' #",
            b"' OR 1=1--",
            b"1' EXEC xp_cmdshell('dir')--"
        ]

        for payload in sql_payloads[:count]:
            packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=80,
                flags='PA'
            ) / Raw(load=b"GET /login?id=" + payload + b" HTTP/1.1\r\nHost: " + dst_ip.encode())

            packets.append(packet)

        logger.info(f"生成SQL注入攻击: {src_ip} -> {dst_ip}, 攻击数: {len(packets)}")
        return packets, {'type': 'SQLInjection', 'src_ip': src_ip, 'dst_ip': dst_ip}

    def generate_random_attack(self):
        """随机生成一种攻击"""
        # 根据权重随机选择攻击类型
        attack_choices = []
        for attack_type, config in self.attacks.items():
            attack_choices.extend([attack_type] * config['weight'])

        selected_attack = random.choice(attack_choices)
        packets, info = self.attacks[selected_attack]['generate']()

        self.generated_attacks.append({
            'timestamp': datetime.now().isoformat(),
            'attack_type': info['type'],
            'src_ip': info['src_ip'],
            'dst_ip': info['dst_ip'],
            'packet_count': len(packets)
        })

        return packets, info

    def start_injection(self, interval=5):
        """开始定期注入攻击流量"""
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(target=self._injection_loop, args=(interval,))
            self.thread.daemon = True
            self.thread.start()
            logger.info(f"攻击流量注入器已启动，间隔: {interval}秒")

    def _injection_loop(self, interval):
        """注入循环"""
        while self.is_running:
            try:
                # 生成攻击数据包
                packets, info = self.generate_random_attack()

                # 保存到列表供检测系统使用
                self.attack_packets.extend(packets)

                # 保存到PCAP文件
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f'data/pcap/attack_{timestamp}.pcap'

                import os
                os.makedirs('data/pcap', exist_ok=True)
                wrpcap(filename, packets)

                logger.info(f"已注入 {info['type']} 攻击，保存到: {filename}")

                time.sleep(interval)

            except Exception as e:
                logger.error(f"注入攻击流量失败: {str(e)}")
                time.sleep(interval)

    def stop_injection(self):
        """停止注入"""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2)

    def get_recent_attacks(self, limit=10):
        """获取最近的攻击记录"""
        return self.generated_attacks[-limit:]


# 创建全局实例
attack_injector = AttackTrafficInjector()
