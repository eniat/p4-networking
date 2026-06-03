#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.nodelib import LinuxBridge
from mininet.node import Node
from stratum import StratumBmv2Switch, NoIpv6OffloadHost

class LinuxRouter(NoIpv6OffloadHost):
    def config(self, **params):
        r = super(LinuxRouter, self).config(**params)
        if 'routes' in params:
            for (ip, gateway) in params['routes']:
                self.cmd('ip route add {} {}'.format(ip, gateway))
        self.cmd('sysctl net.ipv4.ip_forward=1')
        return r

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class Server(NoIpv6OffloadHost):
    def config(self, **params):
        r = super(Server, self).config(**params)
        self.cmd('python3 /mininet/flask_ip.py &')
        # self.cmd(f'iperf -s -i 1 > /tmp/{self.name}-iperf.log &')
        self.cmd(f'iperf3 -s -i 1 > /tmp/{self.name}-iperf3.log &')
        return r

    def terminate(self):
        self.cmd('pkill -f flask_ip.py')
        self.cmd('pkill -f iperf3')
        super(Server, self).terminate()

class LabTopology(Topo):
    """Network topology with multiple hosts connected to a single switch."""

    def build(self):
        # Create a single switch
        pat = self.addSwitch("s1", cls=StratumBmv2Switch, loglevel="info")
        nat = self.addSwitch("s2", cls=StratumBmv2Switch, loglevel="info")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")

        # Home network hosts
        homePC = self.addHost("homePC", ip="192.168.0.10/24",
                              defaultRoute="via 192.168.0.1")
        tablet = self.addHost("tablet", ip="192.168.0.12/24",
                              defaultRoute="via 192.168.0.1")
        phone = self.addHost("phone", ip="192.168.0.5/24",
                             defaultRoute="via 192.168.0.1")
        
        # Hosts in the cloud1 network
        cloud1 = self.addHost("cloud1", ip="10.10.0.32/16",
                             defaultRoute="via 10.10.0.1")
        
        # Hosts in the web network
        web1 = self.addHost("web1", ip="10.0.0.2/16",
                           defaultRoute="via 10.0.0.1")
        web2 = self.addHost("web2", ip="10.0.0.3/16",
                           defaultRoute="via 10.0.0.1")

        # Create all the network routers
        home = self.addHost("home", cls=LinuxRouter, ip=None, 
                                      routes=[
                                          ("10.10.0.0/16", "via 192.168.10.1"), 
                                          ("10.0.0.0/16", "via 192.168.10.1"),
                                          ("10.20.0.0/16", "via 192.168.10.1"),  
                                          ("192.168.30.0/24", "via 192.168.10.1"), 
                                          ("192.168.20.0/24", "via 192.168.10.1")])
        internet = self.addHost("internet", cls=LinuxRouter, ip=None, 
                                      routes=[
                                          ("10.10.0.0/16", "via 192.168.30.2"), 
                                          ("10.0.0.0/16", "via 192.168.20.2"),
                                          
                                          ("10.20.0.0/16", "via 192.168.20.2"),  
                                          ("192.168.0.0/24", "via 192.168.10.2")])
        cloud = self.addHost("cloud", cls=LinuxRouter, ip=None, defaultRoute="via 192.168.30.1")
        web = self.addHost("web", cls=LinuxRouter, ip=None, defaultRoute="via 192.168.20.1")

        # Home network
        self.addLink(s3, homePC)
        self.addLink(s3, tablet)
        self.addLink(s3, phone)
        self.addLink(home, s3, params1={"ip": "192.168.0.1/24"})

        # wan1 network
        self.addLink(home, pat, port2=1, params1={"ip": "192.168.10.2/24"})
        self.addLink(internet, pat, port2=2, params1={"ip": "192.168.10.1/24"})

        # wan2 network
        self.addLink(internet, nat, port2=1, params1={"ip": "192.168.20.1/24"})
        self.addLink(web, nat, port2=2, params1={"ip": "192.168.20.2/24"})

        # wan3 network
        self.addLink(internet, cloud, params1={"ip": "192.168.30.1/24"}, params2={"ip": "192.168.30.2/24"})

        # cloud1 network
        self.addLink(cloud, s4, params1={"ip": "10.10.0.1/16"})   
        self.addLink(cloud1, s4, params1={"ip": "10.10.0.32/16"})
        # web network
        self.addLink(web, s5, params1={"ip": "10.0.0.1/16"})
        self.addLink(web1, s5)
        self.addLink(web2, s5)


# Expose topology for `mn --custom topology.py --topo simple`
topos = {
    "simple": (lambda: LabTopology()),
}


def run():
    """Spin up the network, run a quick test, then drop into CLI."""
    net = Mininet(topo=LabTopology(), link=TCLink, 
                  autoSetMacs=True,
                  autoStaticArp=True,
                  host=Server,
                  switch=LinuxBridge, controller=None)
    net.start()

    # Interactive CLI for exploration
    CLI(net)

    # Clean up
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
