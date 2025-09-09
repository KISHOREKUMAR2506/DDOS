from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv6
import time
import joblib
import pandas as pd
import csv
import os
import zmq
import json

# Setup ZeroMQ Publisher (send logs to dashboard)
context = zmq.Context()
socket = context.socket(zmq.PUB)
socket.bind("tcp://*:5555")  # Dashboard subscribes here

def publish_event(src_ip, port, packet_count, byte_count, prediction, status):
    msg = {
        "src_ip": str(src_ip),
        "port": int(port),
        "packet_count": int(packet_count),
        "byte_count": int(byte_count),
        "prediction": str(prediction),
        "status": str(status)  # e.g., "normal", "ddos", "blocked", "mitigated"
    }
    try:
        socket.send_string(json.dumps(msg))
    except Exception as e:
        print("⚠️ ZeroMQ publish failed:", e)

# Load trained model
model = joblib.load("ddos_model.pkl")

LOG_FILE = "traffic_log.csv"

# Create CSV log file if not exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "port", "packet_count", "byte_count", "prediction"])


class DDoSDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.packet_count = {}   # key: (src_ip, in_port) -> [timestamp, count, byte_count]
        self.blocked_ports = {}  # key: in_port -> unblock_time
        self.THRESHOLD = 5       # packets per second threshold per port
        self.BLOCK_TIME = 10     # seconds

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
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

        # Check if port is blocked
        now = int(time.time())
        if in_port in self.blocked_ports:
            if now < self.blocked_ports[in_port]:
                # Drop all packets from this port (still blocked)
                publish_event("unknown", in_port, 0, 0, 1, "blocked")
                return
            else:
                # Unblock the port after BLOCK_TIME
                del self.blocked_ports[in_port]
                self.logger.info("✅ Port %s is unblocked now", in_port)
                publish_event("unknown", in_port, 0, 0, 0, "unblocked")

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)

        if eth is None:
            return

        src = eth.src
        dst = eth.dst
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # DDoS detection (IP + port)
        if ipv6_pkt:
            src_ip = ipv6_pkt.src

            key = (src_ip, in_port)
            if key not in self.packet_count:
                self.packet_count[key] = [now, 1, len(msg.data)]
            else:
                last_time, count, byte_count = self.packet_count[key]
                if now == last_time:
                    self.packet_count[key][1] += 1
                    self.packet_count[key][2] += len(msg.data)
                else:
                    self.packet_count[key] = [now, 1, len(msg.data)]

            # Features for ML
            features = pd.DataFrame([[self.packet_count[key][1], self.packet_count[key][2]]],
                                    columns=['packet_count', 'byte_count'])
            prediction = model.predict(features)[0]

            # Debug log - see live traffic features
            self.logger.info("📊 Features: packets=%s, bytes=%s -> Prediction=%s",
                             features['packet_count'][0],
                             features['byte_count'][0],
                             prediction)

            # Save to CSV
            with open(LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([now, src_ip, in_port,
                                 features['packet_count'][0],
                                 features['byte_count'][0],
                                 prediction])

            # Publish to dashboard (real-time)
            publish_event(src_ip, in_port,
                          features['packet_count'][0],
                          features['byte_count'][0],
                          prediction, "allowed")

            # If DDoS detected, block IP & port
            if prediction == 1:
                self.logger.info("🚨 DDoS Detected from %s on port %s. Blocking traffic.", src_ip, in_port)

                # Block IP
                match_ip = parser.OFPMatch(eth_type=0x86DD, ipv6_src=src_ip)
                self.add_flow(datapath, 10, match_ip, [], hard_timeout=self.BLOCK_TIME)

                # Block port
                match_port = parser.OFPMatch(in_port=in_port)
                self.add_flow(datapath, 15, match_port, [], hard_timeout=self.BLOCK_TIME)
                self.blocked_ports[in_port] = now + self.BLOCK_TIME

                # Publish block event
                publish_event(src_ip, in_port,
                              features['packet_count'][0],
                              features['byte_count'][0],
                              prediction, "blocked")

        # Normal forwarding
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
