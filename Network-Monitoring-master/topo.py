#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
项目拓扑文件 - 配合my_rest_controller.py使用

拓扑结构：
    h1 -- s1 -- s2 -- s3
          |      |      |
         h2     h3     h4

启动命令：sudo python3 topo_final.py
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class ProjectTopo(Topo):
    """项目拓扑"""
    def build(self):
        # 添加3个OpenFlow 1.3交换机
        s1, s2, s3 = [self.addSwitch(n, protocols='OpenFlow13') for n in ['s1', 's2', 's3']]

        # 添加4个主机
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')

        # 添加链路
        # 交换机之间的链路
        self.addLink(s1, s2)
        self.addLink(s2, s3)

        # 主机连接
        self.addLink(h1, s2)          # h1 -> s2
        self.addLink(h2, s2, bw=1)     # h2 -> s2 (1Mbps限速)
        self.addLink(h3, s3)
        self.addLink(h4, s3)

if __name__ == '__main__':
    setLogLevel('info')

    # 创建拓扑
    topo = ProjectTopo()

    # 创建网络，使用远程控制器
    net = Mininet(
        topo=topo,
        controller=None,  # 手动添加控制器
        link=TCLink
    )

    # 添加远程控制器
    info('*** 添加控制器 ***\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # 启动网络
    net.start()

    info('*** SDN项目网络已启动 ***\n')
    info('控制器: ryu-manager my_rest_controller.py --wsapi-port 8080 --ofp-tcp-listen-port 6633\n')
    info('可用API:\n')
    info('  GET  http://localhost:8080/api/v1/switches\n')
    info('  GET  http://localhost:8080/api/v1/topology\n')
    info('  GET  http://localhost:8080/api/v1/network/stats\n')
    info('  POST http://localhost:8080/api/v1/meter\n')
    info('  POST http://localhost:8080/api/v1/role\n')
    info('  POST http://localhost:8080/api/v1/honeypot/redirect\n')
    info('  POST http://localhost:8080/api/v1/agent/task\n')
    info('\n')

    # 等待控制器连接
    info('等待控制器连接...\n')
    time.sleep(2)

    # 显示网络信息
    info('*** 网络信息 ***\n')
    info('交换机:\n')
    for switch in net.switches:
        info(f'  {switch.name}: {switch.IP()}\n')

    info('主机:\n')
    for host in net.hosts:
        info(f'  {host.name}: {host.IP()}\n')

    info('\n')

    # 进入CLI
    CLI(net)

    # 清理
    net.stop()
