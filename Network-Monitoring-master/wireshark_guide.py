# Wireshark 攻击流量检测指南

## 一、安装和配置虚拟网卡

### Windows 系统

#### 方法1：使用 Microsoft Loopback Adapter（推荐）

1. **打开设备管理器**
   - 按 `Win + X`，选择"设备管理器"

2. **添加过时硬件**
   - 点击顶部菜单"操作" → "添加过时硬件"
   - 点击"下一步"
   - 选择"从磁盘安装"
   - 点击"浏览"
   - 选择"Microsoft Loopback Adapter"
   - 完成安装

3. **配置IP地址**
   - 在设备管理器中找到"Microsoft KM-TEST Loopback Adapter"
   - 右键 → 属性 → "Internet 协议版本 4 (TCP/IPv4)"
   - 设置IP地址：`192.168.100.1`
   - 子网掩码：`255.255.255.0`

---

## 二、下载和安装 Wireshark

1. **下载 Wireshark**
   - 访问：https://www.wireshark.org/download.html
   - 下载 Windows 64位版本

2. **安装 Wireshark**
   - 运行安装程序
   - 安装时会提示安装 Npcap 或 WinPcap
   - **重要**：选择完整安装

3. **启动 Wireshark**
   - 打开 Wireshark

---

## 三、在 Wireshark 中捕获攻击流量

### 步骤1：选择捕获接口

1. 启动 Wireshark
2. 在主界面找到"Microsoft KM-TEST Loopback Adapter"
3. 点击该接口旁边的"捕获选项"（齿轮图标）
4. 设置捕获过滤器（可选）：`host 192.168.100.1`
5. 点击"开始捕获"

### 步骤2：运行攻击脚本

打开命令行，运行：

```bash
cd "C:\Users\29236\Desktop\Network-Monitoring-master\Network-Monitoring-master\Network-Monitoring-master"
python auto_attack_demo.py
```

### 步骤3：在Wireshark中查看流量

运行脚本后，你会在Wireshark中看到捕获到的数据包。

---

## 四、识别各种攻击流量

### 1. DDoS攻击识别

**特征：**
- 大量来自不同源IP的数据包
- 目标都是同一个IP和端口
- 通常指向端口80（HTTP）或443（HTTPS）

**Wireshark过滤器：**
```wireshark
ip.dst == 192.168.100.1 && tcp.dstport == 80
```

**识别方法：**
- 查看"Statistics" → "Conversations" → "TCP"
- 如果看到大量不同IP连接到同一目标，可能是DDoS

---

### 2. 端口扫描识别

**特征：**
- 同一个源IP向目标发送大量SYN包
- 连接许多不同的目标端口

**Wireshark过滤器：**
```wireshark
ip.src == 192.168.100.2 && ip.dst == 192.168.100.1 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**识别方法：**
- 查看数据包列表，寻找大量SYN包
- 目标端口各不相同

---

### 3. SQL注入识别

**特征：**
- HTTP GET/POST请求
- URL中包含特殊字符：`'`, `"`, `--`, `OR`, `UNION`, `DROP`

**Wireshark过滤器：**
```wireshark
http.request.method == "GET" && http.request.uri contains "login"
```

**手动检查：**
1. 找到HTTP数据包
2. 右键 → "Follow" → "HTTP Stream"
3. 查看完整的HTTP请求
4. 寻找类似以下payload：
   - `' OR '1'='1`
   - `admin'--`
   - `'; DROP TABLE users--`

---

### 4. XSS攻击识别

**特征：**
- HTTP请求参数包含脚本代码
- 包含 `<script>`, `javascript:`, `onerror=` 等

**Wireshark过滤器：**
```wireshark
http.request.uri contains "search"
```

**手动检查：**
1. 找到HTTP请求
2. 查看URL参数
3. 寻找类似：
   - `<script>alert('XSS')</script>`
   - `<img src=x onerror=alert(1)>`

---

### 5. 暴力破解识别

**特征：**
- SSH：大量到端口22的连接尝试
- FTP：频繁的USER/PASS命令

**SSH过滤器：**
```wireshark
tcp.dstport == 22 || tcp.srcport == 22
```

**FTP过滤器：**
```wireshark
ftp || tcp.dstport == 21
```

**识别方法：**
- 查看同一IP多次尝试连接
- 时间间隔很短（自动化特征）

---

### 6. 僵尸网络识别

**特征：**
- IRC通信（端口6667）
- 大量bot向同一C2服务器发送心跳
- 特殊的命令模式

**Wireshark过滤器：**
```wireshark
tcp.dstport == 6667 || tcp.dstport == 8080
```

**识别方法：**
- 查看IRC协议内容
- 寻找 `PRIVMSG #botnet`
- 查看是否有命令下发

---

### 7. Heartbleed识别

**特征：**
- TLS/SSL心跳请求
- 数据包类型：`Content Type: Heartbeat`
- 异常大的心跳请求

**Wireshark过滤器：**
```wireshark
ssl || tls || tcp.dstport == 443
```

**识别方法：**
1. 找到TLS数据包
2. 展开"Transport Layer Security"
3. 查看"ContentType"
4. 寻找心跳扩展（类型24）

---

## 五、Wireshark 分析技巧

### 1. 使用显示过滤器

常用过滤器：
```wireshark
# 查看所有到特定IP的流量
ip.dst == 192.168.100.1

# 查看特定端口
tcp.port == 80

# 查看SYN包
tcp.flags.syn == 1

# 查看HTTP请求
http.request

# 查看特定内容
http contains "password"
```

### 2. 统计功能

- **Conversations**: 查看通信对
  - 菜单：Statistics → Conversations

- **Endpoints**: 查看端点统计
  - 菜单：Statistics → Endpoints

- **IO Graph**: 流量图表
  - 菜单：Statistics → IO Graph

### 3. 数据包追踪

**Follow TCP Stream：**
- 右键数据包 → Follow → TCP Stream
- 查看完整的TCP会话

**Follow HTTP Stream：**
- 右键数据包 → Follow → HTTP Stream
- 查看完整的HTTP请求/响应

---

## 六、快速检测流程

### 检查清单

1. **开始捕获**
   - 选择 Loopback Adapter
   - 点击开始捕获

2. **运行攻击脚本**
   ```bash
   python auto_attack_demo.py
   ```

3. **停止捕获**
   - 点击红色停止按钮

4. **分析流量**
   - 使用过滤器筛选特定攻击
   - 使用 Follow Stream 查看详细内容
   - 使用 Statistics 查看统计信息

5. **导出结果**
   - File → Export Specified Packets
   - 保存感兴趣的数据包

---

## 七、常见问题

### Q1: Wireshark看不到流量？

**A: 检查以下项目：**
- 确认选择了正确的网络接口
- 确认虚拟网卡IP配置正确（192.168.100.1）
- 确认防火墙没有阻止流量

### Q2: 如何保存捕获的数据？

**A:**
- 点击 File → Save
- 选择保存为 .pcap 或 .pcapng 格式

### Q3: 如何查看加密流量？

**A:**
- HTTPS/TLS流量是加密的
- 只能看到连接信息，不能看到内容
- 需要配置SSL/TLS解密（需要私钥）

---

## 八、实用过滤器集合

保存为Wireshark的收藏过滤器：

```wireshark
# 攻击检测过滤器集合

# 1. DDoS 检测
ip.dst == 192.168.100.1 && tcp.dstport == 80

# 2. 端口扫描
tcp.flags.syn == 1 && tcp.flags.ack == 0

# 3. SQL 注入
http.request.uri contains "'" || http.request.uri contains "--"

# 4. XSS 攻击
http.request.uri contains "<script>" || http.request.uri contains "javascript:"

# 5. 暴力破解
tcp.flags.syn == 1 && (tcp.dstport == 21 || tcp.dstport == 22)

# 6. IRC/Botnet
tcp.dstport == 6667 || irc

# 7. 心跳异常
ssl && tls.content_type == 24
```

---

## 九、进阶技巧

### 1. 设置着色规则

让不同类型的攻击显示不同颜色：

- 菜单：View → Coloring Rules
- 添加规则：
  - 名称：DDoS
  - 过滤器：`tcp.dstport == 80 && frame.len < 100`
  - 颜色：红色

### 2. 导出对象

提取HTTP对象：
- 菜单：File → Export Objects → HTTP
- 可以提取所有传输的文件

### 3. 时间分析

查看攻击时间线：
- Statistics → IO Graph
- 可以看到流量高峰时间点

---

## 十、实践练习

### 练习1：检测端口扫描

1. 运行攻击脚本
2. 在Wireshark中应用过滤器：`tcp.flags.syn == 1`
3. 查看有多少个不同的目标端口

### 练习2：分析SQL注入

1. 运行攻击脚本
2. 找到HTTP数据包
3. Follow HTTP Stream
4. 识别SQL注入payload

### 练习3：统计DDoS流量

1. 运行攻击脚本
2. 使用 Statistics → Conversations
3. 查看有多少个不同的源IP

---

**提示**：将这些步骤保存为书签，方便下次快速查找！
