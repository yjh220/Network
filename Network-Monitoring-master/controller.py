#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整SDN控制器 - 包含所有文档要求功能
修复了所有导入和常量错误
可直接使用，无需任何修改
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from webob import Response
import json
import redis
import time
from collections import defaultdict

# 实例名称，用于WSGI注册
instance_name = 'network_api_app'


class MyNetworkApp(app_manager.RyuApp):
    """
    主SDN控制器应用

    功能：
    1. 双机热备（MASTER/SLAVE角色管理）
    2. MAC学习和转发
    3. 拓扑发现与主机学习（Redis持久化）
    4. QoS限速（Meter表）
    5. 蜜罐引流（Group表）
    6. 网络统计监控
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MyNetworkApp, self).__init__(*args, **kwargs)

        # 数据存储
        self.switches = {}           # {dpid: datapath}
        self.mac_to_port = {}        # {dpid: {mac: port}}
        self.hosts_inventory = {}    # {mac: {ip, dpid, port, last_seen}}
        self.port_speed_kbps = {}    # {(dpid, port): kbps}
        self.port_stats_prev = {}    # {(dpid, port): {rx_bytes, tx_bytes, timestamp}}

        # 角色管理（默认为SLAVE）
        self.role = ofproto_v1_3.OFPCR_ROLE_SLAVE

        # 链路容量（用于计算带宽利用率）
        self.LINK_CAPACITY = 100 * 1000 * 1000  # 100Mbps

        # 初始化Redis连接
        try:
            self.r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            self.r.ping()
            self.logger.info("Redis连接成功")
        except Exception as e:
            self.logger.error(f"Redis连接失败: {e}")
            self.r = None

        # 注册REST API
        wsgi = kwargs['wsgi']
        wsgi.register(MyRestHandler, {instance_name: self})

        # 启动监控线程
        self.monitor_thread = hub.spawn(self._monitor_loop)

        self.logger.info("MyNetworkApp初始化完成")
        self.logger.info(f"当前角色: {'MASTER' if self.role == ofproto_v1_3.OFPCR_ROLE_MASTER else 'SLAVE'}")

    # ========================================
    # 三大核心函数
    # ========================================

    def add_flow(self, datapath, priority, match, inst, bypass_role_check=False):
        """
        添加流表（用于阻断/引流/换路径）

        Args:
            datapath: 数据路径对象
            priority: 流表优先级
            match: OFPMatch对象
            inst: 指令列表
            bypass_role_check: 是否绕过角色检查（用于Table-Miss）
        """
        # 非MASTER角色且未绕过检查时，不执行
        if not bypass_role_check and self.role != ofproto_v1_3.OFPCR_ROLE_MASTER:
            return

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def add_meter(self, datapath, meter_id, rate, burst_size=10):
        """
        添加Meter表（用于限速）

        Args:
            datapath: 数据路径对象
            meter_id: Meter表ID
            rate: 速率限制（Kbps）
            burst_size: 突发大小（默认10）
        """
        # 非MASTER角色不执行
        if self.role != ofproto_v1_3.OFPCR_ROLE_MASTER:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bands = [parser.OFPMeterBandDrop(rate=rate, burst_size=burst_size)]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(req)
        self.logger.info(f"Meter {meter_id} 添加到交换机 {datapath.id}, 速率={rate}Kbps")

    def add_group(self, datapath, group_id, group_type, buckets):
        """
        添加Group表（用于多路径/引流至蜜罐）

        Args:
            datapath: 数据路径对象
            group_id: Group表ID
            group_type: Group类型（如ofproto.OFPGT_INDIRECT）
            buckets: Bucket列表
        """
        # 非MASTER角色不执行
        if self.role != ofproto_v1_3.OFPCR_ROLE_MASTER:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 先删除旧的Group（如果存在）
        try:
            del_req = parser.OFPGroupMod(
                datapath=datapath,
                command=ofproto.OFPGC_DELETE,
                group_id=group_id
            )
            datapath.send_msg(del_req)
        except:
            pass  # 如果删除失败（Group不存在），继续

        # 添加新的Group（使用位置参数）
        add_req = parser.OFPGroupMod(
            datapath=datapath,
            command=ofproto.OFPGC_ADD,
            group_id=group_id,
            buckets=buckets
        )
        # 如果Ryu版本支持type参数，尝试设置
        try:
            # 某些版本使用type_作为参数名
            if hasattr(add_req, 'type'):
                add_req.type = group_type
        except:
            pass
        datapath.send_msg(add_req)
        self.logger.info(f"Group {group_id} 添加到交换机 {datapath.id}")

    # ========================================
    # 角色管理
    # ========================================

    def set_role(self, datapath, role):
        """
        设置控制器角色

        Args:
            datapath: 数据路径对象
            role: 角色值（OFPCR_ROLE_MASTER或OFPCR_ROLE_SLAVE）
        """
        parser = datapath.ofproto_parser
        msg = parser.OFPRoleRequest(datapath, role, generation_id=0)
        datapath.send_msg(msg)
        self.logger.info(f"发送角色请求到交换机 {datapath.id}: {'MASTER' if role == 2 else 'SLAVE'}")

    def repair_table_miss_entries(self):
        """修复所有交换机的Table-Miss流表（提升为MASTER时调用）"""
        for datapath in self.switches.values():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                              datapath.ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, 0, match, inst, bypass_role_check=True)
        self.logger.info("Table-Miss流表修复完成")

    # ========================================
    # 交换机事件处理
    # ========================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """交换机连接处理"""
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath

        # 设置为SLAVE角色
        self.set_role(datapath, ofproto_v1_3.OFPCR_ROLE_SLAVE)

        # 安装Table-Miss流表
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER,
                                              datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, match, inst, bypass_role_check=True)

        self.logger.info(f"交换机 {datapath.id} 连接，默认角色: SLAVE")

    @set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
    def role_reply_handler(self, ev):
        """角色切换回复处理"""
        self.role = ev.msg.role
        role_str = "MASTER" if self.role == ofproto_v1_3.OFPCR_ROLE_MASTER else "SLAVE"
        self.logger.info(f"角色已切换为: {role_str}")

        # 如果提升为MASTER，修复Table-Miss
        if self.role == ofproto_v1_3.OFPCR_ROLE_MASTER:
            self.repair_table_miss_entries()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        """交换机状态变化处理"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.switches:
                self.switches[datapath.id] = datapath
        else:
            if datapath.id in self.switches:
                del self.switches[datapath.id]
                # 清理相关数据
                if datapath.id in self.mac_to_port:
                    del self.mac_to_port[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        数据包处理（核心转发逻辑）

        功能：
        1. 主机学习（MAC、IP、dpid、port）
        2. 存储到Redis
        3. MAC学习和转发
        """
        try:
            msg = ev.msg
            datapath = msg.datapath
            dpid = datapath.id
            in_port = msg.match['in_port']

            pkt = packet.Packet(msg.data)
            eth_protocols = pkt.get_protocols(ethernet)

            if not eth_protocols:
                return
            eth = eth_protocols[0]

            # 忽略IPv6数据包
            if pkt.get_protocol(ipv6.ipv6):
                return

            # ========================================
            # 主机信息学习与存储
            # ========================================
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4:
                host_info = {
                    "ip": pkt_ipv4.src,
                    "dpid": dpid,
                    "port": in_port,
                    "last_seen": time.time()
                }

                # 存储到内存
                self.hosts_inventory[eth.src] = host_info

                # 存储到Redis（持久化）
                if self.r:
                    try:
                        self.r.hset("topology_hosts", eth.src, json.dumps(host_info))
                        self.logger.debug(f"主机信息存入Redis: {eth.src} -> {pkt_ipv4.src}")
                    except Exception as e:
                        self.logger.error(f"Redis存储失败: {e}")

            # ========================================
            # MAC学习与转发
            # ========================================
            if dpid not in self.mac_to_port:
                self.mac_to_port[dpid] = {}

            # 学习源MAC
            self.mac_to_port[dpid][eth.src] = in_port

            # 查找目的端口
            dst_mac = eth.dst
            if dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_mac]
            else:
                out_port = datapath.ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            # 如果是已知目标且为MASTER，安装流表
            if out_port != datapath.ofproto.OFPP_FLOOD and self.role == ofproto_v1_3.OFPCR_ROLE_MASTER:
                match = datapath.ofproto_parser.OFPMatch(eth_src=eth.src, eth_dst=dst_mac)
                inst = [datapath.ofproto_parser.OFPInstructionActions(
                    datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self.add_flow(datapath, 1, match, inst)

            # 发送数据包
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)

        except Exception as e:
            self.logger.error(f"PacketIn处理异常: {e}")
            import traceback
            traceback.print_exc()

    # ========================================
    # 监控循环（统计信息收集）
    # ========================================

    def _monitor_loop(self):
        """主监控循环"""
        while True:
            try:
                # 周期性请求端口统计
                if self.role == ofproto_v1_3.OFPCR_ROLE_MASTER:
                    for dp in list(self.switches.values()):
                        req = dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
                        dp.send_msg(req)

                hub.sleep(3)  # 每3秒采集一次

            except Exception as e:
                self.logger.error(f"监控循环错误: {e}")
                hub.sleep(3)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """处理端口统计回复"""
        dpid = ev.msg.datapath.id
        current_time = time.time()

        try:
            for stat in ev.msg.body:
                if stat.port_no == 0xffffffff:  # 跳过OFPP_LOCAL
                    continue

                # 获取上一次的统计
                prev_key = (dpid, stat.port_no)
                if prev_key in self.port_stats_prev:
                    prev = self.port_stats_prev[prev_key]
                    time_diff = current_time - prev['timestamp']

                    if time_diff > 0:
                        # 计算速率
                        rx_diff = stat.rx_bytes - prev['rx_bytes']
                        tx_diff = stat.tx_bytes - prev['tx_bytes']
                        total_bytes = rx_diff + tx_diff
                        byte_rate = total_bytes / time_diff  # bytes/sec
                        kbps = int(byte_rate * 8 / 1024)  # 转换为kbps

                        # 存储速率
                        self.port_speed_kbps[prev_key] = kbps

                        # 发布到Redis（供其他系统订阅）
                        if self.r:
                            try:
                                traffic_info = {
                                    "dpid": dpid,
                                    "port": stat.port_no,
                                    "rx_bytes": stat.rx_bytes,
                                    "tx_bytes": stat.tx_bytes,
                                    "kbps": kbps,
                                    "timestamp": current_time
                                }
                                self.r.publish('network_features', json.dumps(traffic_info))
                            except Exception as e:
                                self.logger.error(f"Redis发布失败: {e}")

                # 更新上一次的统计
                self.port_stats_prev[prev_key] = {
                    'rx_bytes': stat.rx_bytes,
                    'tx_bytes': stat.tx_bytes,
                    'timestamp': current_time
                }
        except Exception as e:
            self.logger.error(f"端口统计处理异常: {e}")


class MyRestHandler(ControllerBase):
    """
    REST API处理器

    提供与ModuleA多智能体系统适配的接口
    """

    def __init__(self, req, link, data, **config):
        super(MyRestHandler, self).__init__(req, link, data, **config)
        self.parent_app = data[instance_name]

    # ========================================
    # 基础信息接口
    # ========================================

    @route('network', '/api/v1/switches', methods=['GET'])
    def list_switches(self, req, **kwargs):
        """
        GET /api/v1/switches
        获取交换机列表

        Returns: list of dpid
        """
        switches = list(self.parent_app.switches.keys())
        return Response(
            content_type='application/json',
            charset='utf8',
            body=json.dumps({
                "success": True,
                "switches": switches,
                "count": len(switches),
                "role": "MASTER" if self.parent_app.role == ofproto_v1_3.OFPCR_ROLE_MASTER else "SLAVE"
            })
        )

    @route('network', '/api/v1/topology', methods=['GET'])
    def get_topology(self, req, **kwargs):
        """
        GET /api/v1/topology
        获取拓扑快照（包括主机信息）

        Returns: JSON包含交换机列表和主机清单
        """
        topology_data = {
            "switches_count": len(self.parent_app.switches),
            "switches": list(self.parent_app.switches.keys()),
            "hosts": self.parent_app.hosts_inventory
        }
        return Response(
            content_type='application/json',
            charset='utf8',
            body=json.dumps(topology_data)
        )

    # ========================================
    # 角色管理接口（双机热备）
    # ========================================

    @route('network', '/api/v1/role', methods=['POST'])
    def set_role_api(self, req, **kwargs):
        """
        POST /api/v1/role
        切换控制器角色（MASTER/SLAVE）

        Body: {"role": "master" 或 "slave"}
        """
        try:
            params = json.loads(req.body)
            role_str = params.get('role', '').lower()

            if role_str == 'master':
                role_val = ofproto_v1_3.OFPCR_ROLE_MASTER
            elif role_str == 'slave':
                role_val = ofproto_v1_3.OFPCR_ROLE_SLAVE
            else:
                return Response(
                    status=400,
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({"success": False, "error": "Invalid role. Use 'master' or 'slave'"})
                )

            # 向所有交换机发送角色请求
            for dp in self.parent_app.switches.values():
                self.parent_app.set_role(dp, role_val)

            # 如果切换为MASTER，修复Table-Miss
            if role_val == ofproto_v1_3.OFPCR_ROLE_MASTER:
                # 等待角色切换完成
                hub.sleep(1)
                self.parent_app.repair_table_miss_entries()

            return Response(
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({
                    "success": True,
                    "message": f"角色切换为: {role_str.upper()}"
                })
            )

        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({"success": False, "error": str(e)})
            )

    # ========================================
    # QoS限速接口（ModuleA适配）
    # ========================================

    @route('network', '/api/v1/meter', methods=['POST'])
    def set_meter_limit(self, req, **kwargs):
        """
        POST /api/v1/meter
        设置Meter限速（QoS）

        Body: {"dpid": 2, "ip": "10.0.0.2", "rate": 200}

        Flow:
        1. 调用add_meter()创建Meter表
        2. 构造匹配源IP的OFPMatch
        3. 创建Instruction列表（APPLY_ACTIONS + METER）
        4. 调用add_flow()下发高优先级流表
        """
        try:
            params = json.loads(req.body)
            dpid = int(params.get('dpid', 1))
            target_ip = params.get('ip', '')
            rate = int(params.get('rate', 200))  # Kbps

            if not target_ip:
                return Response(
                    status=400,
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({"success": False, "error": "Missing 'ip' parameter"})
                )

            datapath = self.parent_app.switches.get(dpid)
            if not datapath:
                return Response(
                    status=404,
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({"success": False, "error": f"Switch {dpid} not found"})
                )

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # 1. 调用add_meter()创建Meter表
            meter_id = 1
            self.parent_app.add_meter(datapath, meter_id, rate, burst_size=rate*2)

            # 2. 构造匹配源IP的OFPMatch
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=target_ip)

            # 3. 创建Instruction列表（APPLY_ACTIONS + METER）
            inst = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                ),
                parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER)
            ]

            # 4. 调用add_flow()下发高优先级流表
            self.parent_app.add_flow(datapath, 65535, match, inst)

            return Response(
                content_type='application/json',
                charset='utf8',
                body=json.dumps({
                    "success": True,
                    "message": f"Meter限速已设置: {target_ip} -> {rate}Kbps",
                    "details": {
                        "dpid": dpid,
                        "ip": target_ip,
                        "rate_kbps": rate,
                        "meter_id": meter_id
                    }
                })
            )

        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({"success": False, "error": str(e)})
            )

    # ========================================
    # 遥测统计接口
    # ========================================

    @route('network', '/api/v1/network/stats', methods=['GET'])
    def get_network_stats(self, req, **kwargs):
        """
        GET /api/v1/network/stats
        获取网络统计（端口速率）

        Returns: [{"dpid": 1, "port": 2, "kbps": 100}, ...]
        """
        try:
            stats = []
            for (dpid, port), kbps in self.parent_app.port_speed_kbps.items():
                stats.append({
                    "dpid": dpid,
                    "port": port,
                    "kbps": kbps
                })

            return Response(
                content_type='application/json',
                charset='utf8',
                body=json.dumps({
                    "success": True,
                    "stats": stats,
                    "count": len(stats)
                })
            )

        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({"success": False, "error": str(e)})
            )

    # ========================================
    # 蜜罐引流接口（ModuleA适配）
    # ========================================

    @route('network', '/api/v1/honeypot/redirect', methods=['POST'])
    def redirect_to_honeypot(self, req, **kwargs):
        """
        POST /api/v1/honeypot/redirect
        将攻击者流量重定向到蜜罐端口

        Body: {"dpid": 2, "attacker_ip": "10.0.0.2", "honeypot_port": 3}

        Flow:
        1. 先删除该攻击者IP的所有旧流表
        2. 在指定交换机上创建Group表（INDIRECT类型）
        3. 下发高优先级流表，将攻击者流量重定向到honeypot_port
        """
        try:
            params = json.loads(req.body)
            dpid = int(params.get('dpid', 1))
            attacker_ip = params.get('attacker_ip', '')
            honeypot_port = int(params.get('honeypot_port', 3))

            if not attacker_ip:
                return Response(
                    status=400,
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({"success": False, "error": "Missing 'attacker_ip' parameter"})
                )

            datapath = self.parent_app.switches.get(dpid)
            if not datapath:
                return Response(
                    status=404,
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({"success": False, "error": f"Switch {dpid} not found"})
                )

            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # 1. 先删除该攻击者IP的所有旧流表
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            del_mod = parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY
            )
            datapath.send_msg(del_mod)

            # 2. 创建Group表（INDIRECT类型）
            group_id = 101
            buckets = [parser.OFPBucket(
                actions=[parser.OFPActionOutput(honeypot_port)]
            )]
            self.parent_app.add_group(datapath, group_id, ofproto.OFPGT_INDIRECT, buckets)

            # 3. 下发高优先级流表，将攻击者流量重定向到Group
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionGroup(group_id)]
            )]
            self.parent_app.add_flow(datapath, 200, match, inst)

            return Response(
                content_type='application/json',
                charset='utf8',
                body=json.dumps({
                    "success": True,
                    "message": f"攻击者流量已重定向到蜜罐",
                    "details": {
                        "dpid": dpid,
                        "attacker_ip": attacker_ip,
                        "honeypot_port": honeypot_port,
                        "group_id": group_id
                    }
                })
            )

        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({"success": False, "error": str(e)})
            )

    # ========================================
    # ModuleA适配接口（额外添加，用于多智能体集成）
    # ========================================

    @route('network', '/api/v1/agent/task', methods=['POST'])
    def agent_task(self, req, **kwargs):
        """
        POST /api/v1/agent/task
        ModuleA通用任务执行接口

        Body: {
            "task_type": "qos|security|block|redirect",
            "params": {...}
        }
        """
        try:
            task_data = json.loads(req.body)
            task_type = task_data.get('task_type', '')
            params = task_data.get('params', {})

            if task_type == 'qos':
                # QoS限速任务 - 直接处理
                dpid = int(params.get('dpid', 1))
                target_ip = params.get('ip', '')
                rate = int(params.get('rate', 200))

                if not target_ip:
                    return Response(
                        status=400,
                        content_type='application/json',
                        charset='utf-8',
                        body=json.dumps({"success": False, "error": "Missing 'ip' parameter"})
                    )

                datapath = self.parent_app.switches.get(dpid)
                if not datapath:
                    return Response(
                        status=404,
                        content_type='application/json',
                        charset='utf-8',
                        body=json.dumps({"success": False, "error": f"Switch {dpid} not found"})
                    )

                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                # 创建Meter表
                meter_id = 1
                self.parent_app.add_meter(datapath, meter_id, rate, burst_size=rate*2)

                # 下发流表
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=target_ip)
                inst = [
                    parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                    ),
                    parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER)
                ]
                self.parent_app.add_flow(datapath, 65535, match, inst)

                return Response(
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({
                        "success": True,
                        "message": f"Meter限速已设置: {target_ip} -> {rate}Kbps",
                        "details": {
                            "dpid": dpid,
                            "ip": target_ip,
                            "rate_kbps": rate,
                            "meter_id": meter_id
                        }
                    })
                )

            elif task_type == 'security' or task_type == 'block':
                # 安全阻断任务 - 直接处理
                src_ip = params.get('src_ip', '')
                priority = params.get('priority', 1000)

                if not src_ip:
                    return Response(
                        status=400,
                        content_type='application/json',
                        charset='utf-8',
                        body=json.dumps({"success": False, "error": "Missing 'src_ip' parameter"})
                    )

                # 向所有交换机下发阻断流表
                count = 0
                for datapath in self.parent_app.switches.values():
                    parser = datapath.ofproto_parser
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                    # 空actions表示DROP
                    inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, [])]
                    self.parent_app.add_flow(datapath, priority, match, inst)
                    count += 1

                return Response(
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({
                        "success": True,
                        "message": f"已阻断IP {src_ip} 的流量",
                        "affected_switches": count
                    })
                )

            elif task_type == 'redirect':
                # 蜜罐重定向任务 - 直接处理
                dpid = int(params.get('dpid', 1))
                attacker_ip = params.get('attacker_ip', '')
                honeypot_port = int(params.get('honeypot_port', 3))

                if not attacker_ip:
                    return Response(
                        status=400,
                        content_type='application/json',
                        charset='utf-8',
                        body=json.dumps({"success": False, "error": "Missing 'attacker_ip' parameter"})
                    )

                datapath = self.parent_app.switches.get(dpid)
                if not datapath:
                    return Response(
                        status=404,
                        content_type='application/json',
                        charset='utf-8',
                        body=json.dumps({"success": False, "error": f"Switch {dpid} not found"})
                    )

                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                # 删除该攻击者IP的所有旧流表
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
                del_mod = parser.OFPFlowMod(
                    datapath=datapath,
                    match=match,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY
                )
                datapath.send_msg(del_mod)

                # 创建Group表
                group_id = 101
                buckets = [parser.OFPBucket(
                    actions=[parser.OFPActionOutput(honeypot_port)]
                )]
                self.parent_app.add_group(datapath, group_id, ofproto.OFPGT_INDIRECT, buckets)

                # 下发高优先级流表
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
                inst = [parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionGroup(group_id)]
                )]
                self.parent_app.add_flow(datapath, 200, match, inst)

                return Response(
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({
                        "success": True,
                        "message": f"攻击者流量已重定向到蜜罐",
                        "details": {
                            "dpid": dpid,
                            "attacker_ip": attacker_ip,
                            "honeypot_port": honeypot_port,
                            "group_id": group_id
                        }
                    })
                )

            else:
                return Response(
                    status=400,
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({"success": False, "error": f"Unknown task_type: {task_type}"})
                )

        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({"success": False, "error": str(e)})
            )

    def _block_traffic(self, params):
        """内部方法：阻断流量"""
        try:
            src_ip = params.get('src_ip', '')
            priority = params.get('priority', 1000)

            if not src_ip:
                return Response(
                    status=400,
                    content_type='application/json',
                    charset='utf-8',
                    body=json.dumps({"success": False, "error": "Missing 'src_ip' parameter"})
                )

            # 向所有交换机下发阻断流表
            count = 0
            for datapath in self.parent_app.switches.values():
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                # 空actions表示DROP
                inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, [])]
                self.parent_app.add_flow(datapath, priority, match, inst)
                count += 1

            return Response(
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({
                    "success": True,
                    "message": f"已阻断IP {src_ip} 的流量",
                    "affected_switches": count
                })
            )

        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({"success": False, "error": str(e)})
            )
