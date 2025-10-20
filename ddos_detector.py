from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv6, tcp, udp
import time
import joblib
import pandas as pd
import csv
import os
import zmq
import json
from datetime import datetime

# Setup ZeroMQ Publisher
context = zmq.Context()
socket = context.socket(zmq.PUB)
socket.bind("tcp://*:5555")
time.sleep(0.5)  # Allow socket to initialize

LOG_FILE = "traffic_log.csv"

def publish_event(event_type, src_ip, dst_ip, src_port, dst_port, protocol, 
                  packet_count, byte_count, prediction, status, confidence=0.0, 
                  threat_level="low", duration=0.0):
    """Enhanced event publishing with complete data"""
    msg = {
        "event_type": event_type,
        "timestamp": datetime.now().isoformat(),
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": str(protocol),
        "packet_count": int(packet_count),
        "byte_count": int(byte_count),
        "prediction": str(prediction),
        "confidence": float(confidence),
        "status": str(status),
        "threat_level": str(threat_level),
        "duration": float(duration),
        "response_time": round(time.time() * 1000) % 1000  # Simulated response time
    }
    try:
        socket.send_string(json.dumps(msg))
        print(f"📡 Published: {event_type} | {src_ip} -> {dst_ip} | {prediction}")
    except Exception as e:
        print(f"⚠️ ZeroMQ publish failed: {e}")

# Load trained model
try:
    model = joblib.load("ddos_model.pkl")
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"⚠️ Model loading failed: {e}")
    model = None

# Create CSV log file
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", 
                        "protocol", "packet_count", "byte_count", "prediction", 
                        "status", "threat_level"])

class DDoSDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(DDoSDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_stats = {}      # key: (src_ip, dst_ip, src_port, dst_port) -> stats
        self.blocked_ips = set()
        self.blocked_ports = {}   # key: in_port -> unblock_time
        self.blocked_dst_ports = {}  # NEW: key: dst_port -> {'count': X, 'unblock_time': Y}
        self.port_attack_count = {}  # NEW: Track attacks per destination port
        self.start_time = time.time()
        
        # Enhanced thresholds
        self.PACKET_THRESHOLD = 100    # packets per flow
        self.BYTE_THRESHOLD = 50000    # bytes per flow
        self.BLOCK_TIME = 30           # seconds
        self.PORT_ATTACK_THRESHOLD = 3  # NEW: Block port after 3 attacks
        self.PORT_BLOCK_TIME = 60      # NEW: Block port for 60 seconds
        
        self.logger.info("🛡️ DDoS Defense System Initialized")
        self.logger.info("📋 Dynamic Port Blocking: ENABLED")
        self.logger.info(f"📋 Port Attack Threshold: {self.PORT_ATTACK_THRESHOLD} attacks")
        publish_event("system_start", "0.0.0.0", "0.0.0.0", 0, 0, "SYSTEM", 
                     0, 0, "normal", "active", 1.0, "info", 0.0)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info("✅ Switch connected: DPID=%s", datapath.id)
        publish_event("switch_connected", "0.0.0.0", "0.0.0.0", 0, 0, "SYSTEM",
                     0, 0, "normal", "connected", 1.0, "info", 0.0)
    
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def get_protocol_name(self, pkt):
        """Extract protocol name from packet"""
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        if tcp_pkt:
            return "TCP"
        elif udp_pkt:
            return "UDP"
        return "IPv6"
    
    def get_ports(self, pkt):
        """Extract source and destination ports"""
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        if tcp_pkt:
            return tcp_pkt.src_port, tcp_pkt.dst_port
        elif udp_pkt:
            return udp_pkt.src_port, udp_pkt.dst_port
        return 0, 0
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        now = time.time()
        
        # Check blocked switch ports
        if in_port in self.blocked_ports:
            if now < self.blocked_ports[in_port]:
                publish_event("blocked_port", "unknown", "unknown", 0, in_port, 
                             "BLOCKED", 0, 0, "ddos", "blocked", 1.0, "high", 0.0)
                return
            else:
                del self.blocked_ports[in_port]
                self.logger.info("✅ Switch port %s unblocked", in_port)
                publish_event("port_unblocked", "unknown", "unknown", 0, in_port,
                             "SYSTEM", 0, 0, "normal", "unblocked", 1.0, "info", 0.0)
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        
        if not eth:
            return
        
        src = eth.src
        dst = eth.dst
        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        # Extract network info - FIX: Handle both IPv6 and IPv4
        if ipv6_pkt:
            src_ip = ipv6_pkt.src if ipv6_pkt.src and ipv6_pkt.src != "::" else f"fe80::h{in_port}"
            dst_ip = ipv6_pkt.dst if ipv6_pkt.dst and ipv6_pkt.dst != "::" else "fe80::controller"
            protocol = self.get_protocol_name(pkt)
            src_port, dst_port = self.get_ports(pkt)
        else:
            # Fallback: Use MAC-based pseudo IPv6 for non-IPv6 packets
            src_ip = f"fe80::{src.replace(':', '')}"[:39]  # Convert MAC to IPv6 format
            dst_ip = f"fe80::{dst.replace(':', '')}"[:39]
            protocol = "Ethernet"
            src_port, dst_port = 0, 0
            
        # Ensure IPs are never empty
        if not src_ip or src_ip == "::":
            src_ip = f"2001:db8::host{in_port}"
        if not dst_ip or dst_ip == "::":
            dst_ip = "2001:db8::controller"
        
        # NEW: Check if destination port is blocked
        if dst_port in self.blocked_dst_ports:
            port_info = self.blocked_dst_ports[dst_port]
            if now < port_info['unblock_time']:
                self.logger.info(f"🚫 Dropped packet to blocked port {dst_port} from {src_ip}")
                publish_event("blocked_dst_port", src_ip, dst_ip, src_port, dst_port,
                             protocol, 0, 0, "ddos", "port_blocked", 1.0, "critical", 0.0)
                return
            else:
                del self.blocked_dst_ports[dst_port]
                self.logger.info(f"✅ Destination port {dst_port} unblocked")
                publish_event("dst_port_unblocked", "0.0.0.0", "0.0.0.0", 0, dst_port,
                             "SYSTEM", 0, 0, "normal", "unblocked", 1.0, "info", 0.0)
        
        # Check if IP is blocked
        if src_ip in self.blocked_ips:
            self.logger.info(f"🚫 Blocked packet from {src_ip} (IP blacklisted)")
            publish_event("blocked_ip", src_ip, dst_ip, src_port, dst_port,
                         protocol, 0, 0, "ddos", "blocked", 1.0, "critical", 0.0)
            return
        
        # Flow tracking
        flow_key = (src_ip, dst_ip, src_port, dst_port)
        
        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                'start_time': now,
                'packet_count': 1,
                'byte_count': len(msg.data),
                'last_seen': now
            }
        else:
            self.flow_stats[flow_key]['packet_count'] += 1
            self.flow_stats[flow_key]['byte_count'] += len(msg.data)
            self.flow_stats[flow_key]['last_seen'] = now
        
        stats = self.flow_stats[flow_key]
        duration = now - stats['start_time']
        
        # ML prediction
        prediction = "normal"
        confidence = 0.5
        threat_level = "low"
        
        if model:
            try:
                features = pd.DataFrame([[stats['packet_count'], stats['byte_count']]],
                                      columns=['packet_count', 'byte_count'])
                pred_value = model.predict(features)[0]
                
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(features)[0]
                    confidence = float(max(proba))
                
                prediction = "ddos" if pred_value == 1 else "normal"
                
                # Determine threat level
                if prediction == "ddos":
                    if stats['packet_count'] > 500:
                        threat_level = "critical"
                    elif stats['packet_count'] > 200:
                        threat_level = "high"
                    else:
                        threat_level = "medium"
                
                # Enhanced logging with proper IPs
                self.logger.info(f"📊 Flow Analysis: {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                               f"Packets={stats['packet_count']}, Bytes={stats['byte_count']} | "
                               f"Prediction={prediction.upper()} (confidence={confidence:.2f})")
                
            except Exception as e:
                self.logger.error(f"Prediction error: {e}")
        
        # Heuristic detection
        if stats['packet_count'] > self.PACKET_THRESHOLD or stats['byte_count'] > self.BYTE_THRESHOLD:
            if prediction == "normal":  # Override ML prediction
                prediction = "ddos"
                threat_level = "high"
                confidence = 0.9
                self.logger.warning(f"⚠️  Heuristic Override: Threshold exceeded for {src_ip}")
        
        # Status determination
        status = "allowed"
        
        # Log to CSV
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().isoformat(), src_ip, dst_ip, src_port, 
                           dst_port, protocol, stats['packet_count'], 
                           stats['byte_count'], prediction, status, threat_level])
        
        # Publish normal traffic
        if prediction == "normal":
            publish_event("traffic_flow", src_ip, dst_ip, src_port, dst_port,
                         protocol, stats['packet_count'], stats['byte_count'],
                         prediction, status, confidence, threat_level, duration)
        
        # DDoS detected - take action with dynamic port blocking
        if prediction == "ddos" and threat_level in ["high", "critical"]:
            self.logger.warning(f"🚨 DDoS ATTACK DETECTED!")
            self.logger.warning(f"   Source: {src_ip}:{src_port}")
            self.logger.warning(f"   Target: {dst_ip}:{dst_port}")
            self.logger.warning(f"   Protocol: {protocol}")
            self.logger.warning(f"   Packets: {stats['packet_count']}, Bytes: {stats['byte_count']}")
            self.logger.warning(f"   Threat Level: {threat_level.upper()}")
            
            # NEW: Track attacks per destination port
            if dst_port not in self.port_attack_count:
                self.port_attack_count[dst_port] = 1
            else:
                self.port_attack_count[dst_port] += 1
            
            attack_count = self.port_attack_count[dst_port]
            self.logger.info(f"📊 Port {dst_port} attack counter: {attack_count}/{self.PORT_ATTACK_THRESHOLD}")
            
            # Block IP
            if ipv6_pkt:
                match_ip = parser.OFPMatch(eth_type=0x86DD, ipv6_src=src_ip)
            else:
                match_ip = parser.OFPMatch(eth_src=src)
            
            self.add_flow(datapath, 100, match_ip, [], hard_timeout=self.BLOCK_TIME)
            self.blocked_ips.add(src_ip)
            self.logger.info(f"✅ Blocked IP: {src_ip} (expires in {self.BLOCK_TIME}s)")
            
            # Block switch port temporarily
            match_port = parser.OFPMatch(in_port=in_port)
            self.add_flow(datapath, 50, match_port, [], hard_timeout=self.BLOCK_TIME)
            self.blocked_ports[in_port] = now + self.BLOCK_TIME
            self.logger.info(f"✅ Blocked switch port: {in_port}")
            
            # NEW: Block destination port if threshold exceeded
            if attack_count >= self.PORT_ATTACK_THRESHOLD:
                self.logger.critical(f"🔒 CRITICAL: Port {dst_port} under sustained attack!")
                self.logger.critical(f"🔒 BLOCKING ALL TRAFFIC TO PORT {dst_port}")
                
                # Block all traffic to this port
                if ipv6_pkt:
                    if protocol == "TCP":
                        match_dst_port = parser.OFPMatch(eth_type=0x86DD, ip_proto=6, tcp_dst=dst_port)
                    elif protocol == "UDP":
                        match_dst_port = parser.OFPMatch(eth_type=0x86DD, ip_proto=17, udp_dst=dst_port)
                    else:
                        match_dst_port = parser.OFPMatch(in_port=in_port)
                else:
                    match_dst_port = parser.OFPMatch(in_port=in_port)
                
                self.add_flow(datapath, 150, match_dst_port, [], hard_timeout=self.PORT_BLOCK_TIME)
                self.blocked_dst_ports[dst_port] = {
                    'count': attack_count,
                    'unblock_time': now + self.PORT_BLOCK_TIME
                }
                
                self.logger.critical(f"🔒 Port {dst_port} will auto-unblock in {self.PORT_BLOCK_TIME}s")
                
                # Publish port block event
                publish_event("dst_port_blocked", "0.0.0.0", dst_ip, 0, dst_port,
                             protocol, attack_count, 0, "ddos", "port_blocked", 1.0, "critical", 0.0)
                
                status = "port_blocked"
            else:
                status = "blocked"
            
            # Publish attack event
            publish_event("ddos_attack", src_ip, dst_ip, src_port, dst_port,
                         protocol, stats['packet_count'], stats['byte_count'],
                         prediction, status, confidence, threat_level, duration)
            
            # Schedule unblock
            self.schedule_unblock(src_ip, self.BLOCK_TIME)
        
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
    
    def schedule_unblock(self, ip, delay):
        """Schedule IP unblocking"""
        def unblock():
            time.sleep(delay)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.logger.info(f"✅ IP {ip} unblocked")
                publish_event("ip_unblocked", ip, "0.0.0.0", 0, 0, "SYSTEM",
                             0, 0, "normal", "unblocked", 1.0, "info", 0.0)
        
        import threading
        threading.Thread(target=unblock, daemon=True).start()