from scapy.all import IP, UDP, wrpcap

# 完全和你日志一样
SRC_IP = "192.168.1.153"
DST_IP = "10.0.0.243"
DST_PORT = 44643

# 构造数据包
pkt = IP(src=SRC_IP, dst=DST_IP) / UDP(dport=DST_PORT)

# 保存成 PCAP 文件
wrpcap("attack_packet.pcap", [pkt])

print("✅ 已生成攻击包文件：attack_packet.pcap")
print("源IP：192.168.1.153")
print("目标IP：10.0.0.243")
print("协议：UDP 端口：44643")
print("双击这个文件即可用 Wireshark 打开！")