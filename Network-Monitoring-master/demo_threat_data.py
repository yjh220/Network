#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成演示用的威胁检测数据 - 完整版
模拟真实攻击的流量特征，供ML模型检测
"""

import pandas as pd
import numpy as np
import os

def get_full_columns():
    """返回所有需要的列"""
    return ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
            'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
            'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
            'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
            'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

def generate_ddos_attack(count=20):
    """生成DDoS攻击流量特征"""
    attacks = []
    for i in range(count):
        src_ip = f"10.0.{i%5}.{i+1}"
        dst_ip = '192.168.1.100'
        dst_port = 80
        fwd_pkts = np.random.randint(50, 200)
        bwd_pkts = 0
        fwd_len = np.random.randint(50000, 200000)
        bwd_len = 0
        duration = np.random.uniform(1000, 5000)

        attacks.append({
            'Flow ID': f"ddos-{i}",
            'Source IP': src_ip,
            'Source Port': np.random.randint(1000, 65000),
            'Destination IP': dst_ip,
            'Destination Port': dst_port,
            'Protocol': 6,
            'Timestamp': '2024-01-01 10:00:00',
            'Flow Duration': duration,
            'Total Fwd Packets': fwd_pkts,
            'Total Backward Packets': bwd_pkts,
            'Total Length of Fwd Packets': fwd_len,
            'Total Length of Bwd Packets': bwd_len,
            'Fwd Packet Length Max': np.random.uniform(1000, 1500),
            'Fwd Packet Length Min': np.random.uniform(40, 60),
            'Fwd Packet Length Mean': fwd_len / fwd_pkts,
            'Fwd Packet Length Std': np.random.uniform(50, 200),
            'Bwd Packet Length Max': 0,
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': 0,
            'Bwd Packet Length Std': 0,
            'Flow Bytes/s': (fwd_len + bwd_len) / (duration / 1000000),
            'Flow Packets/s': (fwd_pkts + bwd_pkts) / (duration / 1000000),
            'Flow IAT Mean': duration / fwd_pkts,
            'Flow IAT Std': np.random.uniform(10, 100),
            'Flow IAT Max': np.random.uniform(500, 2000),
            'Flow IAT Min': np.random.uniform(1, 10),
            'Fwd IAT Total': duration,
            'Fwd IAT Mean': duration / fwd_pkts,
            'Fwd IAT Std': np.random.uniform(10, 100),
            'Fwd IAT Max': np.random.uniform(500, 2000),
            'Fwd IAT Min': np.random.uniform(1, 10),
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,
            'Bwd IAT Std': 0,
            'Bwd IAT Max': 0,
            'Bwd IAT Min': 0,
            'Fwd PSH Flags': fwd_pkts,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': fwd_pkts * 40,
            'Bwd Header Length': 0,
            'Fwd Packets/s': fwd_pkts / (duration / 1000000),
            'Bwd Packets/s': 0,
            'Min Packet Length': np.random.uniform(40, 60),
            'Max Packet Length': np.random.uniform(1000, 1500),
            'Packet Length Mean': fwd_len / fwd_pkts,
            'Packet Length Std': np.random.uniform(50, 200),
            'Packet Length Variance': np.random.uniform(2500, 40000),
            'FIN Flag Count': 0,
            'SYN Flag Count': np.random.randint(1, 5),
            'RST Flag Count': 0,
            'PSH Flag Count': fwd_pkts,
            'ACK Flag Count': fwd_pkts,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': 0,
            'Average Packet Size': fwd_len / fwd_pkts,
            'Avg Fwd Segment Size': fwd_len / fwd_pkts,
            'Avg Bwd Segment Size': 0,
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': fwd_pkts,
            'Subflow Fwd Bytes': fwd_len,
            'Subflow Bwd Packets': 0,
            'Subflow Bwd Bytes': 0,
            'Init_Win_bytes_forward': np.random.randint(20000, 60000),
            'Init_Win_bytes_backward': 0,
            'act_data_pkt_fwd': fwd_pkts,
            'min_seg_size_forward': np.random.randint(40, 60),
            'Active Mean': np.random.uniform(100, 500),
            'Active Std': np.random.uniform(50, 200),
            'Active Max': np.random.uniform(1000, 3000),
            'Active Min': np.random.uniform(10, 100),
            'Idle Mean': 0,
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0,
            'Label': 'DDoS'
        })
    return attacks

def generate_portscan(count=15):
    """生成端口扫描流量特征"""
    attacks = []
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]
    for i in range(count):
        dst_port = ports[i % len(ports)]
        attacks.append({
            'Flow ID': f"portscan-{i}",
            'Source IP': '192.168.1.200',
            'Source Port': np.random.randint(1000, 65000),
            'Destination IP': '192.168.1.100',
            'Destination Port': dst_port,
            'Protocol': 6,
            'Timestamp': '2024-01-01 10:05:00',
            'Flow Duration': np.random.uniform(100, 500),
            'Total Fwd Packets': 1,
            'Total Backward Packets': 0,
            'Total Length of Fwd Packets': np.random.randint(40, 60),
            'Total Length of Bwd Packets': 0,
            'Fwd Packet Length Max': np.random.randint(40, 60),
            'Fwd Packet Length Min': np.random.randint(40, 60),
            'Fwd Packet Length Mean': np.random.randint(40, 60),
            'Fwd Packet Length Std': 0,
            'Bwd Packet Length Max': 0,
            'Bwd Packet Length Min': 0,
            'Bwd Packet Length Mean': 0,
            'Bwd Packet Length Std': 0,
            'Flow Bytes/s': np.random.uniform(100, 500),
            'Flow Packets/s': np.random.uniform(2, 10),
            'Flow IAT Mean': np.random.uniform(100, 500),
            'Flow IAT Std': 0,
            'Flow IAT Max': np.random.uniform(100, 500),
            'Flow IAT Min': np.random.uniform(100, 500),
            'Fwd IAT Total': np.random.uniform(100, 500),
            'Fwd IAT Mean': np.random.uniform(100, 500),
            'Fwd IAT Std': 0,
            'Fwd IAT Max': np.random.uniform(100, 500),
            'Fwd IAT Min': np.random.uniform(100, 500),
            'Bwd IAT Total': 0,
            'Bwd IAT Mean': 0,
            'Bwd IAT Std': 0,
            'Bwd IAT Max': 0,
            'Bwd IAT Min': 0,
            'Fwd PSH Flags': 0,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': 40,
            'Bwd Header Length': 0,
            'Fwd Packets/s': np.random.uniform(2, 10),
            'Bwd Packets/s': 0,
            'Min Packet Length': np.random.randint(40, 60),
            'Max Packet Length': np.random.randint(40, 60),
            'Packet Length Mean': np.random.randint(40, 60),
            'Packet Length Std': 0,
            'Packet Length Variance': 0,
            'FIN Flag Count': 0,
            'SYN Flag Count': 1,
            'RST Flag Count': 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': 0,
            'Average Packet Size': np.random.randint(40, 60),
            'Avg Fwd Segment Size': np.random.randint(40, 60),
            'Avg Bwd Segment Size': 0,
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': 1,
            'Subflow Fwd Bytes': np.random.randint(40, 60),
            'Subflow Bwd Packets': 0,
            'Subflow Bwd Bytes': 0,
            'Init_Win_bytes_forward': np.random.randint(2000, 8000),
            'Init_Win_bytes_backward': 0,
            'act_data_pkt_fwd': 0,
            'min_seg_size_forward': np.random.randint(40, 60),
            'Active Mean': np.random.uniform(100, 500),
            'Active Std': np.random.uniform(50, 200),
            'Active Max': np.random.uniform(100, 500),
            'Active Min': np.random.uniform(100, 500),
            'Idle Mean': 0,
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0,
            'Label': 'PortScan'
        })
    return attacks

def generate_ssh_bruteforce(count=10):
    """生成SSH暴力破解流量特征"""
    attacks = []
    for i in range(count):
        fwd_pkts = np.random.randint(10, 30)
        bwd_pkts = np.random.randint(10, 30)
        fwd_len = np.random.randint(500, 2000)
        bwd_len = np.random.randint(300, 1500)
        duration = np.random.uniform(2000, 10000)

        attacks.append({
            'Flow ID': f"ssh-{i}",
            'Source IP': '172.16.1.50',
            'Source Port': np.random.randint(1000, 65000),
            'Destination IP': '192.168.1.100',
            'Destination Port': 22,
            'Protocol': 6,
            'Timestamp': '2024-01-01 10:10:00',
            'Flow Duration': duration,
            'Total Fwd Packets': fwd_pkts,
            'Total Backward Packets': bwd_pkts,
            'Total Length of Fwd Packets': fwd_len,
            'Total Length of Bwd Packets': bwd_len,
            'Fwd Packet Length Max': np.random.uniform(100, 200),
            'Fwd Packet Length Min': np.random.uniform(40, 60),
            'Fwd Packet Length Mean': fwd_len / fwd_pkts,
            'Fwd Packet Length Std': np.random.uniform(20, 80),
            'Bwd Packet Length Max': np.random.uniform(80, 150),
            'Bwd Packet Length Min': np.random.uniform(30, 50),
            'Bwd Packet Length Mean': bwd_len / bwd_pkts,
            'Bwd Packet Length Std': np.random.uniform(15, 60),
            'Flow Bytes/s': (fwd_len + bwd_len) / (duration / 1000000),
            'Flow Packets/s': (fwd_pkts + bwd_pkts) / (duration / 1000000),
            'Flow IAT Mean': duration / (fwd_pkts + bwd_pkts),
            'Flow IAT Std': np.random.uniform(200, 800),
            'Flow IAT Max': np.random.uniform(1000, 3000),
            'Flow IAT Min': np.random.uniform(50, 200),
            'Fwd IAT Total': duration * 0.5,
            'Fwd IAT Mean': (duration * 0.5) / fwd_pkts,
            'Fwd IAT Std': np.random.uniform(200, 800),
            'Fwd IAT Max': np.random.uniform(1000, 3000),
            'Fwd IAT Min': np.random.uniform(50, 200),
            'Bwd IAT Total': duration * 0.5,
            'Bwd IAT Mean': (duration * 0.5) / bwd_pkts,
            'Bwd IAT Std': np.random.uniform(200, 800),
            'Bwd IAT Max': np.random.uniform(1000, 3000),
            'Bwd IAT Min': np.random.uniform(50, 200),
            'Fwd PSH Flags': fwd_pkts,
            'Bwd PSH Flags': bwd_pkts,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': fwd_pkts * 40,
            'Bwd Header Length': bwd_pkts * 40,
            'Fwd Packets/s': fwd_pkts / (duration / 1000000),
            'Bwd Packets/s': bwd_pkts / (duration / 1000000),
            'Min Packet Length': np.random.uniform(30, 60),
            'Max Packet Length': np.random.uniform(100, 200),
            'Packet Length Mean': (fwd_len + bwd_len) / (fwd_pkts + bwd_pkts),
            'Packet Length Std': np.random.uniform(20, 80),
            'Packet Length Variance': np.random.uniform(400, 6400),
            'FIN Flag Count': 0,
            'SYN Flag Count': 1,
            'RST Flag Count': np.random.randint(0, 2),
            'PSH Flag Count': fwd_pkts + bwd_pkts,
            'ACK Flag Count': fwd_pkts + bwd_pkts - np.random.randint(0, 3),
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': bwd_len / fwd_len if fwd_len > 0 else 0,
            'Average Packet Size': (fwd_len + bwd_len) / (fwd_pkts + bwd_pkts),
            'Avg Fwd Segment Size': fwd_len / fwd_pkts,
            'Avg Bwd Segment Size': bwd_len / bwd_pkts,
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': fwd_pkts,
            'Subflow Fwd Bytes': fwd_len,
            'Subflow Bwd Packets': bwd_pkts,
            'Subflow Bwd Bytes': bwd_len,
            'Init_Win_bytes_forward': np.random.randint(2000, 8000),
            'Init_Win_bytes_backward': np.random.randint(2000, 8000),
            'act_data_pkt_fwd': np.random.randint(5, 20),
            'min_seg_size_forward': np.random.randint(40, 60),
            'Active Mean': np.random.uniform(500, 2000),
            'Active Std': np.random.uniform(200, 800),
            'Active Max': np.random.uniform(2000, 5000),
            'Active Min': np.random.uniform(100, 500),
            'Idle Mean': np.random.uniform(100, 500),
            'Idle Std': np.random.uniform(50, 200),
            'Idle Max': np.random.uniform(500, 1500),
            'Idle Min': np.random.uniform(50, 200),
            'Label': 'SSH-Patator'
        })
    return attacks

def generate_benign(count=30):
    """生成正常流量特征"""
    attacks = []
    for i in range(count):
        src_ip = f"192.168.1.{i%20+1}"
        fwd_pkts = np.random.randint(100, 500)
        bwd_pkts = np.random.randint(100, 500)
        fwd_len = np.random.randint(50000, 500000)
        bwd_len = np.random.randint(30000, 400000)
        duration = np.random.uniform(50000, 500000)

        attacks.append({
            'Flow ID': f"benign-{i}",
            'Source IP': src_ip,
            'Source Port': np.random.randint(1000, 65000),
            'Destination IP': '10.0.0.1',
            'Destination Port': 443,
            'Protocol': 6,
            'Timestamp': '2024-01-01 10:15:00',
            'Flow Duration': duration,
            'Total Fwd Packets': fwd_pkts,
            'Total Backward Packets': bwd_pkts,
            'Total Length of Fwd Packets': fwd_len,
            'Total Length of Bwd Packets': bwd_len,
            'Fwd Packet Length Max': np.random.uniform(1000, 1500),
            'Fwd Packet Length Min': np.random.uniform(40, 60),
            'Fwd Packet Length Mean': fwd_len / fwd_pkts,
            'Fwd Packet Length Std': np.random.uniform(100, 500),
            'Bwd Packet Length Max': np.random.uniform(800, 1200),
            'Bwd Packet Length Min': np.random.uniform(30, 50),
            'Bwd Packet Length Mean': bwd_len / bwd_pkts,
            'Bwd Packet Length Std': np.random.uniform(80, 400),
            'Flow Bytes/s': (fwd_len + bwd_len) / (duration / 1000000),
            'Flow Packets/s': (fwd_pkts + bwd_pkts) / (duration / 1000000),
            'Flow IAT Mean': duration / (fwd_pkts + bwd_pkts),
            'Flow IAT Std': np.random.uniform(1000, 5000),
            'Flow IAT Max': np.random.uniform(10000, 50000),
            'Flow IAT Min': np.random.uniform(100, 1000),
            'Fwd IAT Total': duration * 0.5,
            'Fwd IAT Mean': (duration * 0.5) / fwd_pkts,
            'Fwd IAT Std': np.random.uniform(1000, 5000),
            'Fwd IAT Max': np.random.uniform(10000, 50000),
            'Fwd IAT Min': np.random.uniform(100, 1000),
            'Bwd IAT Total': duration * 0.5,
            'Bwd IAT Mean': (duration * 0.5) / bwd_pkts,
            'Bwd IAT Std': np.random.uniform(1000, 5000),
            'Bwd IAT Max': np.random.uniform(10000, 50000),
            'Bwd IAT Min': np.random.uniform(100, 1000),
            'Fwd PSH Flags': int(fwd_pkts * 0.8),
            'Bwd PSH Flags': int(bwd_pkts * 0.8),
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': fwd_pkts * 40,
            'Bwd Header Length': bwd_pkts * 40,
            'Fwd Packets/s': fwd_pkts / (duration / 1000000),
            'Bwd Packets/s': bwd_pkts / (duration / 1000000),
            'Min Packet Length': np.random.uniform(30, 50),
            'Max Packet Length': np.random.uniform(1000, 1500),
            'Packet Length Mean': (fwd_len + bwd_len) / (fwd_pkts + bwd_pkts),
            'Packet Length Std': np.random.uniform(100, 500),
            'Packet Length Variance': np.random.uniform(10000, 250000),
            'FIN Flag Count': np.random.randint(0, 2),
            'SYN Flag Count': 1,
            'RST Flag Count': 0,
            'PSH Flag Count': int((fwd_pkts + bwd_pkts) * 0.8),
            'ACK Flag Count': fwd_pkts + bwd_pkts - 2,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': bwd_len / fwd_len if fwd_len > 0 else 0,
            'Average Packet Size': (fwd_len + bwd_len) / (fwd_pkts + bwd_pkts),
            'Avg Fwd Segment Size': fwd_len / fwd_pkts,
            'Avg Bwd Segment Size': bwd_len / bwd_pkts,
            'Fwd Avg Bytes/Bulk': np.random.uniform(1000, 5000),
            'Fwd Avg Packets/Bulk': np.random.uniform(5, 20),
            'Fwd Avg Bulk Rate': np.random.uniform(1000, 5000),
            'Bwd Avg Bytes/Bulk': np.random.uniform(800, 4000),
            'Bwd Avg Packets/Bulk': np.random.uniform(5, 15),
            'Bwd Avg Bulk Rate': np.random.uniform(800, 4000),
            'Subflow Fwd Packets': fwd_pkts,
            'Subflow Fwd Bytes': fwd_len,
            'Subflow Bwd Packets': bwd_pkts,
            'Subflow Bwd Bytes': bwd_len,
            'Init_Win_bytes_forward': np.random.randint(20000, 60000),
            'Init_Win_bytes_backward': np.random.randint(20000, 60000),
            'act_data_pkt_fwd': np.random.randint(50, 200),
            'min_seg_size_forward': np.random.randint(40, 60),
            'Active Mean': np.random.uniform(5000, 20000),
            'Active Std': np.random.uniform(2000, 8000),
            'Active Max': np.random.uniform(20000, 60000),
            'Active Min': np.random.uniform(1000, 5000),
            'Idle Mean': np.random.uniform(1000, 5000),
            'Idle Std': np.random.uniform(500, 2000),
            'Idle Max': np.random.uniform(5000, 15000),
            'Idle Min': np.random.uniform(100, 1000),
            'Label': 'BENIGN'
        })
    return attacks

def generate_demo_threats():
    """生成包含多种攻击类型的演示数据"""

    attacks = []
    attacks.extend(generate_ddos_attack(20))
    attacks.extend(generate_portscan(15))
    attacks.extend(generate_ssh_bruteforce(10))
    attacks.extend(generate_benign(30))

    # 转换为DataFrame
    df = pd.DataFrame(attacks)

    # 保存为CSV
    os.makedirs('data/flow_features', exist_ok=True)
    csv_file = 'data/flow_features/demo_with_threats.csv'
    df.to_csv(csv_file, index=False)

    print(f"✓ 已生成演示威胁数据: {csv_file}")
    print(f"  - 总计: {len(attacks)} 条流量记录")
    print(f"  - DDoS攻击: 20 条")
    print(f"  - 端口扫描: 15 条")
    print(f"  - SSH暴力破解: 10 条")
    print(f"  - 正常流量: 30 条")
    print(f"\n完整文件路径: {os.path.abspath(csv_file)}")

    return csv_file

if __name__ == '__main__':
    print("="*60)
    print("【演示威胁数据生成器 - 完整版】")
    print("包含78个完整流量特征列")
    print("="*60)
    generate_demo_threats()
    print("="*60)
