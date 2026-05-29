#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模拟网络流量生成器 - 用于演示和测试网络监控功能
"""

import random
import time
import threading
from datetime import datetime

class MockTrafficGenerator:
    """生成模拟网络流量数据"""

    def __init__(self):
        self.is_running = False
        self.thread = None
        self.packet_stats = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'http': 0,
            'other': 0
        }
        self.traffic_data = []
        self.lock = threading.Lock()

        # 模拟的IP地址池
        self.internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
        self.external_ips = [
            "8.8.8.8", "1.1.1.1", "93.184.216.34", "151.101.1.140",
            "104.16.132.229", "172.67.209.36", "140.82.112.4"
        ]

        # 常见服务端口
        self.common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            23: 'Telnet',
            53: 'DNS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt'
        }

    def generate_packet(self):
        """生成单个模拟数据包"""
        # 随机选择源和目标
        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.internal_ips + self.external_ips)

        # 随机选择协议
        protocol_choice = random.choices(
            ['tcp', 'udp', 'icmp', 'http'],
            weights=[50, 25, 5, 20]
        )[0]

        protocol = protocol_choice.upper()
        if protocol_choice == 'http':
            dst_port = random.choice([80, 443, 8080])
        elif protocol_choice == 'tcp':
            dst_port = random.choice(list(self.common_ports.keys()))
        elif protocol_choice == 'udp':
            dst_port = random.choice([53, 123, 161])
        else:
            dst_port = 0

        src_port = random.randint(1024, 65535)

        # 根据协议调整
        if protocol_choice == 'http':
            self.packet_stats['http'] += 1
            self.packet_stats['tcp'] += 1
            protocol = 'HTTP/HTTPS'
        elif protocol_choice == 'tcp':
            self.packet_stats['tcp'] += 1
            protocol = 'TCP'
        elif protocol_choice == 'udp':
            self.packet_stats['udp'] += 1
            protocol = 'UDP'
        elif protocol_choice == 'icmp':
            self.packet_stats['icmp'] += 1
            protocol = 'ICMP'
        else:
            self.packet_stats['other'] += 1

        # 生成数据包大小
        size = random.randint(40, 1500)

        packet = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_mac': f"00:1A:2B:3C:4D:{random.randint(10, 99):02X}",
            'dst_mac': f"00:1A:2B:3C:4D:{random.randint(10, 99):02X}",
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'size': size,
            'type': protocol_choice,
            'raw': ''
        }

        return packet

    def start_generation(self, packets_per_second=5):
        """开始生成模拟流量"""
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(
                target=self._generate_traffic,
                args=(packets_per_second,)
            )
            self.thread.daemon = True
            self.thread.start()

    def _generate_traffic(self, packets_per_second):
        """生成流量的线程函数"""
        interval = 1.0 / packets_per_second

        while self.is_running:
            try:
                packet = self.generate_packet()

                with self.lock:
                    self.traffic_data.append(packet)

                    # 保持最近1000条记录
                    if len(self.traffic_data) > 1000:
                        self.traffic_data = self.traffic_data[-1000:]

                time.sleep(interval)

            except Exception as e:
                print(f"生成流量错误: {e}")

    def stop_generation(self):
        """停止生成流量"""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2)

    def get_traffic_stats(self):
        """获取流量统计"""
        with self.lock:
            return self.packet_stats.copy()

    def get_recent_traffic(self, limit=100):
        """获取最近的流量数据"""
        with self.lock:
            if limit > 0:
                return self.traffic_data[-limit:]
            return self.traffic_data.copy()


# 创建全局实例
mock_generator = MockTrafficGenerator()
