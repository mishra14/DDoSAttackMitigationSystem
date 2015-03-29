#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

## To run Ryu controllers,
## python .ryu/bin/ryu-manager --ofp-tcp-listen-port XXXX ryu/ryu/app/simple_switch_13.py

## I BLATANTLY PLAGIARISED THIS FUNCTION. SUE ME. -G
def int2dpid(dpid):
   try:
      dpid = hex(dpid)[2:]
      dpid = '0' * (16 - len(dpid)) + dpid
      return dpid
   except IndexError:
      raise Exception( 'Unable to derive default datapath ID - '
                       'please either specify a dpid or use a '
               'canonical switch name such as s23.' )

def createNetworkTopology():

    "Create a network and add nodes to it."

    net = Mininet(controller=RemoteController, link=TCLink)

    info( '*** Adding controller\n' )
    cA = net.addController('cA', controller=RemoteController, ip="127.0.0.1", port=6633)
    cB = net.addController('cB', controller=RemoteController, ip="127.0.0.1", port=6634)

    info( '*** Adding hosts\n' )
    AAh1 = net.addHost('AAh1', ip='10.1.1.1', mac='0A:0A:00:00:00:01')
    AAh2 = net.addHost('AAh2', ip='10.1.1.2', mac='0A:0A:00:00:00:02')
    ABh1 = net.addHost('ABh1', ip='10.1.2.1', mac='0A:0B:00:00:00:01')
    ABh2 = net.addHost('ABh2', ip='10.1.2.2', mac='0A:0B:00:00:00:02')
    BAh1 = net.addHost('BAh1', ip='10.10.10.1', mac='0B:0A:00:00:00:01')
    BAh2 = net.addHost('BAh2', ip='10.10.10.2', mac='0B:0A:00:00:00:02')
    BBh1 = net.addHost('BBh1', ip='10.10.20.1', mac='0B:0B:00:00:00:01')
    BBh2 = net.addHost('BBh2', ip='10.10.20.2', mac='0B:0B:00:00:00:02')

    info( '*** Adding switches\n' )
    sA = net.addSwitch( 's1', dpid=int2dpid(1) )
    sAA = net.addSwitch( 's11', dpid=int2dpid(11) )
    sAB = net.addSwitch( 's12', dpid=int2dpid(12) )
    sB = net.addSwitch( 's2', dpid=int2dpid(2) )
    sBA = net.addSwitch( 's21', dpid=int2dpid(21) )
    sBB = net.addSwitch( 's22', dpid=int2dpid(22) )
    
    info( '*** Adding links\n' )
    net.addLink(AAh1,sAA,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(AAh2,sAA,bw=2, delay='2ms',max_queue_size=5)
    
    net.addLink(ABh1,sAB,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(ABh2,sAB,bw=2, delay='2ms',max_queue_size=5)
    
    net.addLink(BAh1,sBA,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(BAh2,sBA,bw=2, delay='2ms',max_queue_size=5)
    
    net.addLink(BBh1,sBB,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(BBh2,sBB,bw=2, delay='2ms',max_queue_size=5)

    net.addLink(sAA,sA, bw=5, delay='1ms',max_queue_size=10)
    net.addLink(sAB,sA, bw=5, delay='1ms',max_queue_size=10)
    
    net.addLink(sBA,sB, bw=5, delay='1ms',max_queue_size=10)
    net.addLink(sBB,sB, bw=5, delay='1ms',max_queue_size=10)
    
    net.addLink(sA,sB,bw=10, delay='0ms',max_queue_size=20)


    info('*** Starting network\n')
    net.build()
    sA.start([cA])
    sAA.start([cA])
    sAB.start([cA])
    sB.start([cB])
    sBA.start([cB])
    sBB.start([cB])

    info('\n*** Running pingall\n')
    net.pingAll()

    info('*** Running iperf\n')
    net.iperf(hosts=[AAh1, ABh1])
    net.iperf(hosts=[AAh1, BAh1])
    net.iperf(hosts=[AAh1, BBh1])
    net.iperf(hosts=[ABh1, BAh1])
    net.iperf(hosts=[ABh1, BBh1])
    net.iperf(hosts=[BAh1, BBh1])

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    createNetworkTopology()
