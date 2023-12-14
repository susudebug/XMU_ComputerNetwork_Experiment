from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxRouter(Node):
    def config(self, mac1 = None, mac2 = None, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')
        self.setMAC(mac = mac1, intf = self.name + '-eth1')
        self.setMAC(mac = mac2, intf = self.name + '-eth2')
        
    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class NetworkTopo(Topo):
    def build(self, **_opts):
        # Add 2 routers in two different subnets
        router1 = self.addHost('router1', cls=LinuxRouter, ip='100.0.0.1/24', mac1='c6:dc:64:56:a9:a5',mac2='aa:c7:bb:9b:c7:85')
        router2 = self.addHost('router2', cls=LinuxRouter, ip='192.0.1.1/24', mac1='ce:dc:a7:21:46:1b',mac2='7e:f8:e6:a7:b8:e4')


        # Adding hosts specifying the default route
        host1 = self.addHost(name='host1',
                          ip='100.0.0.250/24',
                          mac='8e:0f:a3:4a:f6:e5',
                          defaultRoute='via 100.0.0.1')
        host2 = self.addHost(name='host2',
                          ip='192.0.1.251/24',
                          mac='02:84:eb:2f:80:3c',
                          defaultRoute='via 192.0.1.1')

        # Add host-switch links in the same subnet
        self.addLink(host1,
                     router1,
                     intfName2='router1-eth1',
                     params2={'ip': '100.0.0.1/24'})

        self.addLink(host2,
                     router2,
                     intfName2='router2-eth1',
                     params2={'ip': '192.0.1.1/24'})

        # Add router-router link in a new subnet for the router-router connection
        self.addLink(router1,
                     router2,
                     intfName1='router1-eth2',
                     intfName2='router2-eth2',
                     params1={'ip': '10.100.0.1/24'},
                     params2={'ip': '10.100.0.2/24'})




def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo)

    # Add routing for reaching networks that aren't directly connected
    info(net['router1'].cmd("ip route add 192.0.1.0/24 via 10.100.0.2 dev router1-eth2"))
    info(net['router2'].cmd("ip route add 100.0.0.0/24 via 10.100.0.1 dev router2-eth2"))

    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
