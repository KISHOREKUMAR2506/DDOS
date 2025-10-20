#!/usr/bin/env python3
"""
Custom Mininet Topology for DDoS Testing
Creates a network with multiple switches and hosts to simulate realistic attacks
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class DDoSTestTopology(Topo):
    """
    Custom topology for DDoS testing:
    
    Network Structure:
                    [Controller]
                         |
                    [Core Switch s1]
                    /    |    \    \
                   /     |     \    \
              [s2]     [s3]   [s4]  [victim]
              /  \      |  \    |
            h1  h2     h3  h4  h5
    
    - s1: Core switch (connects to controller)
    - s2, s3, s4: Edge switches
    - h1-h5: Attack hosts
    - victim: Target server
    """
    
    def build(self):
        # Add core switch
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Add edge switches
        s2 = self.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')
        s4 = self.addSwitch('s4', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Add attacker hosts with IPv6
        h1 = self.addHost('h1', ip='10.0.0.1/24', 
                         mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24',
                         mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24',
                         mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24',
                         mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24',
                         mac='00:00:00:00:00:05')
        
        # Add victim server
        victim = self.addHost('victim', ip='10.0.0.100/24',
                            mac='00:00:00:00:01:00')
        
        # Connect switches to core
        self.addLink(s1, s2, bw=100, delay='5ms')
        self.addLink(s1, s3, bw=100, delay='5ms')
        self.addLink(s1, s4, bw=100, delay='5ms')
        
        # Connect hosts to edge switches
        self.addLink(h1, s2, bw=10, delay='2ms')
        self.addLink(h2, s2, bw=10, delay='2ms')
        self.addLink(h3, s3, bw=10, delay='2ms')
        self.addLink(h4, s3, bw=10, delay='2ms')
        self.addLink(h5, s4, bw=10, delay='2ms')
        
        # Connect victim to core switch
        self.addLink(victim, s1, bw=1000, delay='1ms')


class SimpleTopology(Topo):
    """
    Simple topology for quick testing:
    
          [Controller]
               |
          [Switch s1]
          /    |    \
        h1    h2   victim
    """
    
    def build(self):
        # Add switch
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Add hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        victim = self.addHost('victim', ip='10.0.0.100/24')
        
        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(victim, s1)


class LargeScaleTopology(Topo):
    """
    Large-scale topology for stress testing:
    
    - 5 switches
    - 20 hosts (potential attackers)
    - 1 victim server
    """
    
    def build(self):
        # Core switch
        core = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Edge switches
        switches = []
        for i in range(2, 6):
            sw = self.addSwitch(f's{i}', cls=OVSSwitch, protocols='OpenFlow13')
            switches.append(sw)
            self.addLink(core, sw, bw=1000, delay='5ms')
        
        # Add hosts to each edge switch
        host_id = 1
        for sw in switches:
            for _ in range(5):
                host = self.addHost(f'h{host_id}', 
                                  ip=f'10.0.0.{host_id}/24',
                                  mac=f'00:00:00:00:00:{host_id:02x}')
                self.addLink(host, sw, bw=10, delay='2ms')
                host_id += 1
        
        # Victim server
        victim = self.addHost('victim', ip='10.0.0.100/24',
                            mac='00:00:00:00:01:00')
        self.addLink(victim, core, bw=1000, delay='1ms')


def run_topology(topo_name='ddos'):
    """
    Run the specified topology with remote controller
    
    Args:
        topo_name: 'simple', 'ddos', or 'large'
    """
    setLogLevel('info')
    
    # Select topology
    if topo_name == 'simple':
        topo = SimpleTopology()
        info("*** Creating Simple Topology\n")
    elif topo_name == 'large':
        topo = LargeScaleTopology()
        info("*** Creating Large-Scale Topology\n")
    else:
        topo = DDoSTestTopology()
        info("*** Creating DDoS Test Topology\n")
    
    # Create network with remote controller
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    info("*** Starting network\n")
    net.start()
    
    # Configure IPv6 on hosts (for DDoS detector)
    info("*** Configuring IPv6 addresses\n")
    for host in net.hosts:
        host_name = host.name
        if host_name == 'victim':
            host.cmd('ip -6 addr add 2001:db8::100/64 dev victim-eth0')
        else:
            # Extract host number
            host_num = ''.join(filter(str.isdigit, host_name))
            if host_num:
                host.cmd(f'ip -6 addr add 2001:db8::{host_num}/64 dev {host_name}-eth0')
    
    info("*** Network ready\n")
    info("*** Ryu controller should be running on 127.0.0.1:6653\n")
    info("\n")
    info("=" * 60 + "\n")
    info("TESTING COMMANDS:\n")
    info("=" * 60 + "\n")
    info("\n")
    info("1. Normal traffic:\n")
    info("   mininet> h1 ping -c 10 victim\n")
    info("\n")
    info("2. Single-source DDoS:\n")
    info("   mininet> h1 ping -f -c 1000 victim\n")
    info("\n")
    info("3. Multi-source DDoS:\n")
    info("   mininet> h1 ping -f victim &\n")
    info("   mininet> h2 ping -f victim &\n")
    info("   mininet> h3 ping -f victim &\n")
    info("\n")
    info("4. TCP flood (requires hping3):\n")
    info("   mininet> h1 hping3 -S --flood victim\n")
    info("\n")
    info("5. Check connectivity:\n")
    info("   mininet> pingall\n")
    info("\n")
    info("6. Monitor traffic:\n")
    info("   mininet> victim tcpdump -i victim-eth0\n")
    info("\n")
    info("=" * 60 + "\n")
    
    # Start CLI
    CLI(net)
    
    # Cleanup
    info("*** Stopping network\n")
    net.stop()


# Topology definitions for Mininet command-line
topos = {
    'simple': SimpleTopology,
    'ddos': DDoSTestTopology,
    'large': LargeScaleTopology
}


if __name__ == '__main__':
    import sys
    
    # Parse command-line arguments
    if len(sys.argv) > 1:
        topo_type = sys.argv[1]
    else:
        topo_type = 'ddos'
    
    # Run topology
    run_topology(topo_type)