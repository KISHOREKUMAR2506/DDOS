from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv6
import time

class DDoSDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.packet_count = {}
        self.blocked_hosts = {}
        self.THRESHOLD = 50      # packets per second threshold
        self.BLOCK_TIME = 10     # seconds

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        if eth is None:
            return

        src = eth.src
        dst = eth.dst

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # DDoS detection
        if ipv6_pkt:
            src_ip = ipv6_pkt.src
            now = int(time.time())
            if src_ip not in self.packet_count:
                self.packet_count[src_ip] = [now, 1]
            else:
                last_time, count = self.packet_count[src_ip]
                if now == last_time:
                    self.packet_count[src_ip][1] += 1
                else:
                    # Reset for new second
                    self.packet_count[src_ip] = [now, 1]

                # If threshold exceeded
                if self.packet_count[src_ip][1] > self.THRESHOLD:
                    if src_ip not in self.blocked_hosts:
                        self.logger.info("🚨 DDoS Detected from %s. Blocking traffic.", src_ip)
                        match = parser.OFPMatch(eth_type=0x86DD, ipv6_src=src_ip)
                        actions = []  # drop packet
                        self.add_flow(datapath, 10, match, actions, hard_timeout=self.BLOCK_TIME)
                        self.blocked_hosts[src_ip] = now

        # Forwarding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
