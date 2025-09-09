from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

class MultiSwitchTopo(Topo):
    def build(self):

        # All hosts in the same subnet 2001:db8::/64
        attacker = self.addHost('attacker', ip='2001:db8::1/64')
        h1 = self.addHost('h1', ip='2001:db8::2/64')
        h2 = self.addHost('h2', ip='2001:db8::3/64')
        server = self.addHost('server', ip='2001:db8::100/64')

        # Add switches
        s1 = self.addSwitch('s1')  # attacker side
        s2 = self.addSwitch('s2')  # users side
        s3 = self.addSwitch('s3')  # server side

        # Add links
        self.addLink(attacker, s1)
        self.addLink(h1, s2)
        self.addLink(h2, s2)
        self.addLink(server, s3)

        # Connect switches
        self.addLink(s1, s2)
        self.addLink(s2, s3)

def run():
    net = Mininet(topo=MultiSwitchTopo(),
                  controller=RemoteController,
                  switch=OVSSwitch,
                  autoSetMacs=True)

    net.start()

    # Just to be safe, re-assign IPv6 manually
    attacker, h1, h2, server = net.get('attacker', 'h1', 'h2', 'server')

    attacker.cmd("ip -6 addr flush dev attacker-eth0")
    h1.cmd("ip -6 addr flush dev h1-eth0")
    h2.cmd("ip -6 addr flush dev h2-eth0")
    server.cmd("ip -6 addr flush dev server-eth0")

    attacker.cmd("ip -6 addr add 2001:db8::1/64 dev attacker-eth0")
    h1.cmd("ip -6 addr add 2001:db8::2/64 dev h1-eth0")
    h2.cmd("ip -6 addr add 2001:db8::3/64 dev h2-eth0")
    server.cmd("ip -6 addr add 2001:db8::100/64 dev server-eth0")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
