#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成更多攻击流量数据用于测试入侵检测系统
"""

import pandas as pd
import random
import numpy as np
from datetime import datetime, timedelta

# 攻击类型配置
attack_types = {
    'PortScan': {
        'description': '端口扫描攻击',
        'patterns': [
            {'duration': (50, 200), 'fwd_pkts': (1, 5), 'fwd_bytes': (40, 200)},
        ]
    },
    'DDoS': {
        'description': '分布式拒绝服务攻击',
        'patterns': [
            {'duration': (100, 1000), 'fwd_pkts': (500, 2000), 'fwd_bytes': (50000, 200000)},
        ]
    },
    'BruteForce': {
        'description': '暴力破解攻击',
        'patterns': [
            {'duration': (1000, 10000), 'fwd_pkts': (5, 20), 'fwd_bytes': (200, 1000)},
        ]
    },
    'SQLInjection': {
        'description': 'SQL注入攻击',
        'patterns': [
            {'duration': (5000, 20000), 'fwd_pkts': (10, 50), 'fwd_bytes': (1000, 5000)},
        ]
    },
    'XSS': {
        'description': '跨站脚本攻击',
        'patterns': [
            {'duration': (3000, 15000), 'fwd_pkts': (15, 40), 'fwd_bytes': (800, 3000)},
        ]
    }
}

def generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol):
    """生成流量ID"""
    return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"

def generate_attack_flow(attack_type, index):
    """生成单条攻击流量"""
    config = attack_types[attack_type]['patterns'][0]

    # 随机生成IP地址
    src_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
    dst_ip = f"10.0.{random.randint(1, 10)}.{random.randint(1, 255)}"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 3306, 3389, 8080])
    protocol = 6  # TCP

    # 流量特征
    duration = random.randint(*config['duration'])
    fwd_pkts = random.randint(*config['fwd_pkts'])
    bwd_pkts = random.randint(0, fwd_pkts // 10)
    fwd_bytes = random.randint(*config['fwd_bytes'])
    bwd_bytes = random.randint(0, fwd_bytes // 5)

    # 计算衍生特征
    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes

    flow = {
        'Flow ID': generate_flow_id(src_ip, dst_ip, src_port, dst_port, protocol),
        'Source IP': src_ip,
        'Source Port': src_port,
        'Destination IP': dst_ip,
        'Destination Port': dst_port,
        'Protocol': protocol,
        'Timestamp': (datetime.now() + timedelta(seconds=index)).strftime('%Y-%m-%d %H:%M:%S'),
        'Flow Duration': duration,
        'Total Fwd Packets': fwd_pkts,
        'Total Backward Packets': bwd_pkts,
        'Total Length of Fwd Packets': fwd_bytes,
        'Total Length of Bwd Packets': bwd_bytes,
        'Fwd Packet Length Max': fwd_bytes // fwd_pkts if fwd_pkts > 0 else 0,
        'Fwd Packet Length Min': 40,
        'Fwd Packet Length Mean': fwd_bytes // fwd_pkts if fwd_pkts > 0 else 0,
        'Fwd Packet Length Std': random.randint(5, 20),
        'Bwd Packet Length Max': bwd_bytes // bwd_pkts if bwd_pkts > 0 else 0,
        'Bwd Packet Length Min': 0,
        'Bwd Packet Length Mean': bwd_bytes // bwd_pkts if bwd_pkts > 0 else 0,
        'Bwd Packet Length Std': random.randint(0, 10),
        'Flow Bytes/s': (total_bytes / duration * 1000000) if duration > 0 else 0,
        'Flow Packets/s': (total_pkts / duration * 1000000) if duration > 0 else 0,
        'Flow IAT Mean': duration / total_pkts if total_pkts > 0 else 0,
        'Flow IAT Std': random.randint(10, 100),
        'Flow IAT Max': duration,
        'Flow IAT Min': random.randint(1, 10),
        'Fwd IAT Total': duration,
        'Fwd IAT Mean': duration / fwd_pkts if fwd_pkts > 0 else 0,
        'Fwd IAT Std': random.randint(5, 50),
        'Fwd IAT Max': duration,
        'Fwd IAT Min': random.randint(1, 5),
        'Bwd IAT Total': 0,
        'Bwd IAT Mean': 0,
        'Bwd IAT Std': 0,
        'Bwd IAT Max': 0,
        'Bwd IAT Min': 0,
        'Fwd PSH Flags': fwd_pkts,
        'Bwd PSH Flags': bwd_pkts,
        'Fwd URG Flags': 0,
        'Bwd URG Flags': 0,
        'Fwd Header Length': fwd_pkts * 40,
        'Bwd Header Length': bwd_pkts * 40,
        'Fwd Packets/s': (fwd_pkts / duration * 1000000) if duration > 0 else 0,
        'Bwd Packets/s': (bwd_pkts / duration * 1000000) if duration > 0 else 0,
        'Min Packet Length': 40,
        'Max Packet Length': max(fwd_bytes // fwd_pkts if fwd_pkts > 0 else 0, 100),
        'Packet Length Mean': total_bytes / total_pkts if total_pkts > 0 else 0,
        'Packet Length Std': random.randint(10, 50),
        'Packet Length Variance': random.randint(100, 500),
        'FIN Flag Count': 1 if random.random() > 0.7 else 0,
        'SYN Flag Count': 1,
        'RST Flag Count': random.randint(0, 1),
        'PSH Flag Count': fwd_pkts,
        'ACK Flag Count': fwd_pkts + bwd_pkts,
        'URG Flag Count': 0,
        'CWE Flag Count': 0,
        'ECE Flag Count': 0,
        'Down/Up Ratio': bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0,
        'Average Packet Size': total_bytes / total_pkts if total_pkts > 0 else 0,
        'Avg Fwd Segment Size': fwd_bytes / fwd_pkts if fwd_pkts > 0 else 0,
        'Avg Bwd Segment Size': bwd_bytes / bwd_pkts if bwd_pkts > 0 else 0,
        'Fwd Header Length.1': fwd_pkts * 40,
        'Fwd Avg Bytes/Bulk': 0,
        'Fwd Avg Packets/Bulk': 0,
        'Fwd Avg Bulk Rate': 0,
        'Bwd Avg Bytes/Bulk': 0,
        'Bwd Avg Packets/Bulk': 0,
        'Bwd Avg Bulk Rate': 0,
        'Subflow Fwd Packets': fwd_pkts,
        'Subflow Fwd Bytes': fwd_bytes,
        'Subflow Bwd Packets': bwd_pkts,
        'Subflow Bwd Bytes': bwd_bytes,
        'Init_Win_bytes_forward': random.choice([8192, 16384, 32768, 65536]),
        'Init_Win_bytes_backward': random.choice([8192, 16384, 32768, 65536]),
        'act_data_pkt_fwd': fwd_pkts,
        'min_seg_size_forward': 40,
        'Active Mean': duration / 2,
        'Active Std': random.randint(10, 100),
        'Active Max': duration,
        'Active Min': random.randint(10, 50),
        'Idle Mean': 0,
        'Idle Std': 0,
        'Idle Max': 0,
        'Idle Min': 0,
        'Label': attack_type
    }

    return flow

def generate_attack_dataset(num_flows_per_type=50):
    """生成攻击数据集"""
    all_flows = []

    for attack_type in attack_types.keys():
        print(f"生成 {attack_type} 攻击流量...")
        for i in range(num_flows_per_type):
            flow = generate_attack_flow(attack_type, i)
            all_flows.append(flow)

    # 转换为DataFrame
    df = pd.DataFrame(all_flows)

    # 保存到CSV
    output_file = 'attack_traffic_generated.csv'
    df.to_csv(output_file, index=False)
    print(f"\n已生成 {len(df)} 条攻击流量记录")
    print(f"文件保存至: {output_file}")
    print("\n攻击类型分布:")
    print(df['Label'].value_counts())

    return df

if __name__ == '__main__':
    # 生成每个攻击类型50条记录
    generate_attack_dataset(num_flows_per_type=50)
