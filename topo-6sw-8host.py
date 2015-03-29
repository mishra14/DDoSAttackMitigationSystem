# #!/usr/bin/python

# from mininet.topo import Topo
# from mininet.net import Mininet
# from mininet.node import CPULimitedHost
# from mininet.link import TCLink
# from mininet.util import dumpNodeConnections
# from mininet.log import setLogLevel

# class SingleSwitchTopo(Topo):
#     "Single switch connected to n hosts."
#     def build(self, n=2):
#         switch = self.addSwitch('s1')
#         for h in range(n):
#             # Each host gets 50%/n of system CPU
#             host = self.addHost('h%s' % (h + 1),cpu=.5/n)
#             # 10 Mbps, 5ms delay, 10% loss, 1000 packet queue
#             self.addLink(host, switch,bw=10, delay='5ms', loss=10, max_queue_size=1000, use_htb=True)

# if __name__ == '__main__':
#     setLogLevel('info')
#     a = SingleSwitchTopo(n=5)

"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."
    def __init__( self ):
        "Create custom topo."
        # Initialize topology
        Topo.__init__( self )
        # Add hosts and switches
        AAh1 = self.addHost( 'AAh1' )
        AAh2 = self.addHost( 'AAh2' )
        ABh1 = self.addHost( 'ABh1' )
        ABh2 = self.addHost( 'ABh2' )
        BAh1 = self.addHost( 'BAh1' )
        BAh2 = self.addHost( 'BAh2' )
        BBh1 = self.addHost( 'BBh1' )
        BBh2 = self.addHost( 'BBh2' )
        sA = self.addSwitch( 's1' )
        sAA = self.addSwitch( 's11' )
        sAB = self.addSwitch( 's12' )
        sB = self.addSwitch( 's2' )
        sBA = self.addSwitch( 's21' )
        sBB = self.addSwitch( 's22' )
        # Add links
        self.addLink(AAh1,sAA,bw=2, delay='2ms',max_queue_size=5)
        self.addLink(AAh2,sAA,bw=2, delay='2ms',max_queue_size=5)
        
        self.addLink(ABh1,sAB,bw=2, delay='2ms',max_queue_size=5)
        self.addLink(ABh2,sAB,bw=2, delay='2ms',max_queue_size=5)
        
        self.addLink(BAh1,sBA,bw=2, delay='2ms',max_queue_size=5)
        self.addLink(BAh2,sBA,bw=2, delay='2ms',max_queue_size=5)
        
        self.addLink(BBh1,sBB,bw=2, delay='2ms',max_queue_size=5)
        self.addLink(BBh2,sBB,bw=2, delay='2ms',max_queue_size=5)

        self.addLink(sAA,sA, bw=5, delay='1ms',max_queue_size=10)
        self.addLink(sAB,sA, bw=5, delay='1ms',max_queue_size=10)
        
        self.addLink(sBA,sB, bw=5, delay='1ms',max_queue_size=10)
        self.addLink(sBB,sB, bw=5, delay='1ms',max_queue_size=10)
        
        self.addLink(sA,sB,bw=10, delay='0ms',max_queue_size=20)


topos = { 'mytopo': ( lambda: MyTopo() ) }
